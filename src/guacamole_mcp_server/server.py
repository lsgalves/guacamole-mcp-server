"""MCP server exposing Apache Guacamole connections as command-execution tools, plus the
administration of connections, connection groups, users, user groups and permissions."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .admin import GuacamoleAdmin
from .api import Connection, ConnectionGroup, GuacamoleAPI, GuacamoleError
from .tunnel import GuacamoleSSHSession
from .winrm import GuacamoleWinRMSession

log = logging.getLogger("guacamole_mcp_server")

INSTRUCTIONS = """\
Tools to inspect and troubleshoot servers reachable through Apache Guacamole connections:
Linux/Unix servers via SSH connections, and Windows servers via RDP connections that have
WinRM enabled (guacamole-winrm extension).

When the user asks to analyse/check/debug a server by name:
1. Call `list_connections` (optionally with a search term) to find the matching connection.
   If several connections match, ask the user which one, or pick the exact name match.
   The `shell` field tells which language `run_command` expects: "posix" or "powershell".
2. Call `run_command` with that connection name, a non-interactive command in that language and
   `shell` set to that same value (the command is refused if it does not match the connection).
3. Investigate step by step, then report findings to the user.

Linux (shell "posix", SSH): the shell session is kept open between calls, so `cd` and exported
variables persist. Useful: uptime, df -h, free -m, systemctl status <svc>,
journalctl -u <svc> -n 200 --no-pager, tail -n 200 /var/log/..., ss -tlnp, ps aux --sort=-%cpu | head.
Avoid full-screen programs (top, vim, less); use `top -b -n 1` instead.

Windows (shell "powershell", WinRM):
- IMPORTANT: every run_command is a NEW PowerShell process. Only the current directory persists
  between calls (`cd`/`Set-Location` works); variables, functions, imported modules and
  `$env:` changes from previous calls are LOST. Put dependent steps in the same command, e.g.
  `$p = Get-Process | Sort-Object CPU -Descending; $p | Select-Object -First 10`.
- Output is only returned when the command finishes, and a command that exceeds timeout_seconds
  is NOT cancelled (it keeps running on the server). Keep commands bounded
  (Get-WinEvent -MaxEvents 100, Get-Content -Tail 200, Select-Object -First N).
- Useful: Get-ComputerInfo, Get-Service, Get-Process, Get-CimInstance Win32_LogicalDisk,
  Get-WinEvent -LogName System -MaxEvents 50, Get-Counter, Get-NetTCPConnection, Test-NetConnection.

Rules: commands must not need interactive input (stdin is closed; use --no-pager, -y, -Confirm:$false
only when the user approved the change). Prefer read-only commands and ask the user before changing
anything on the server (restarts, edits, deletes, package installs).

Administration of Guacamole itself (connections, connection groups, users, user groups and
permissions): the tools act as the configured Guacamole user, and Guacamole refuses (HTTP 403)
what its permissions do not allow; `get_current_user` shows them. Read with get_connection,
list_connection_groups, list_active_connections, list_users, get_user, list_user_groups and
get_user_group. Change only what the user asked for: updates keep every field not given (null
clears a parameter or attribute), and changes name their object exactly (name, "group/name" or
identifier). Passwords and keys are shown as *** and that mask is never a valid value.
"""


class Settings:
    def __init__(self) -> None:
        self.url = _require("GUACAMOLE_URL")
        self.username = _require("GUACAMOLE_USERNAME")
        self.password = _require("GUACAMOLE_PASSWORD")
        self.verify_ssl = os.environ.get("GUACAMOLE_VERIFY_SSL", "true").lower() not in ("0", "false", "no")
        ds = os.environ.get("GUACAMOLE_DATA_SOURCES", "").strip()
        self.data_sources = [d.strip() for d in ds.split(",") if d.strip()] or None
        self.default_timeout = float(os.environ.get("GUACAMOLE_COMMAND_TIMEOUT", "60"))
        self.idle_timeout = float(os.environ.get("GUACAMOLE_SESSION_IDLE_TIMEOUT", "900"))


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Environment variable {name} is required")
    return value


class SessionManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.api = GuacamoleAPI(
            settings.url,
            settings.username,
            settings.password,
            verify_ssl=settings.verify_ssl,
            data_sources=settings.data_sources,
        )
        self.sessions: dict[str, GuacamoleSSHSession | GuacamoleWinRMSession] = {}
        self._lock = asyncio.Lock()
        self._connections: list[Connection] = []
        self._groups: list[ConnectionGroup] = []
        self._connections_at = 0.0
        self._reaper: asyncio.Task | None = None
        self.admin = GuacamoleAdmin(self)

    async def start(self) -> None:
        self._reaper = asyncio.create_task(self._reap_idle())

    async def shutdown(self) -> None:
        if self._reaper:
            self._reaper.cancel()
        for session in list(self.sessions.values()):
            await session.close()
        self.sessions.clear()
        await self.api.close()

    async def connections(self, refresh: bool = False) -> list[Connection]:
        await self._load_tree(refresh)
        return self._connections

    async def groups(self, refresh: bool = False) -> list[ConnectionGroup]:
        await self._load_tree(refresh)
        return self._groups

    def invalidate(self) -> None:
        """Reload connections and groups on next use (after a change)."""
        self._connections_at = 0.0

    async def _load_tree(self, refresh: bool) -> None:
        if refresh or not self._connections_at or time.time() - self._connections_at > 60:
            self._connections, self._groups = await self.api.load_tree()
            self._connections_at = time.time()

    async def resolve(self, query: str, usable_only: bool = True, exact: bool = False) -> Connection:
        """Find a connection by identifier, name or group/name (and unique partial name unless exact).

        usable_only limits the search to connections that run commands (SSH, RDP with WinRM).
        """
        q = query.strip().lower()
        for refresh in (False, True):
            usable = [c for c in await self.connections(refresh) if c.kind or not usable_only]
            for matcher in (
                lambda c: c.identifier == query.strip(),
                lambda c: c.name.lower() == q,
                lambda c: c.full_name.lower() == q,
            ):
                matches = [c for c in usable if matcher(c)]
                if len(matches) == 1:
                    return matches[0]
                if len(matches) > 1:
                    raise GuacamoleError(_ambiguous(query, matches))
            if exact:
                continue
            partial = [c for c in usable if q in c.full_name.lower()]
            if len(partial) == 1:
                return partial[0]
            if len(partial) > 1:
                raise GuacamoleError(_ambiguous(query, partial))
        what = "SSH or WinRM-enabled RDP connection" if usable_only else "connection"
        hint = " (use the exact name, group/name or identifier)" if exact else ""
        raise GuacamoleError(f"No {what} matches '{query}'{hint}. Use list_connections to see available connections.")

    def _new_session(self, connection: Connection) -> GuacamoleSSHSession | GuacamoleWinRMSession:
        if connection.kind == "winrm":
            return GuacamoleWinRMSession(self.api, connection)
        return GuacamoleSSHSession(self.api, connection)

    async def session_for(self, connection: Connection) -> GuacamoleSSHSession | GuacamoleWinRMSession:
        key = f"{connection.data_source}:{connection.identifier}"
        async with self._lock:
            session = self.sessions.get(key)
            if session is not None and session.is_open:
                return session
            session = self._new_session(connection)
            try:
                await session.open()
            except GuacamoleError as exc:
                # The token may have expired between REST calls and the tunnel; retry once with a fresh one.
                log.info("Opening session failed (%s), retrying with new token", exc)
                await self.api.authenticate()
                session = self._new_session(connection)
                await session.open()
            self.sessions[key] = session
            return session

    async def close(self, connection: Connection) -> bool:
        key = f"{connection.data_source}:{connection.identifier}"
        session = self.sessions.pop(key, None)
        if session is None:
            return False
        await session.close()
        return True

    async def _reap_idle(self) -> None:
        while True:
            await asyncio.sleep(30)
            now = time.time()
            for key, session in list(self.sessions.items()):
                if not session.is_open or now - session.last_used > self.settings.idle_timeout:
                    self.sessions.pop(key, None)
                    await session.close()


def _ambiguous(query: str, matches: list[Connection]) -> str:
    names = "\n".join(f"- {c.full_name} (id {c.identifier}, {c.data_source})" for c in matches[:30])
    return f"'{query}' matches several connections; use the exact name or identifier:\n{names}"


manager: SessionManager | None = None
_manager_users = 0


@asynccontextmanager
async def lifespan(_server: FastMCP):
    # Over HTTP the lifespan runs once per MCP session, so all clients share one manager
    # that is shut down when the last session ends.
    global manager, _manager_users
    if manager is None:
        manager = SessionManager(Settings())
        await manager.start()
    _manager_users += 1
    try:
        yield
    finally:
        _manager_users -= 1
        if _manager_users == 0:
            await manager.shutdown()
            manager = None


mcp = FastMCP("guacamole", instructions=INSTRUCTIONS, lifespan=lifespan)


def _mgr() -> SessionManager:
    assert manager is not None, "Server not initialised"
    return manager


def _admin() -> GuacamoleAdmin:
    return _mgr().admin


@mcp.tool()
async def list_connections(search: str | None = None, include_all: bool = False) -> list[dict]:
    """List Guacamole connections the configured user can run commands on.

    Returns SSH connections (shell "posix") and RDP connections with WinRM enabled
    (shell "powershell").

    Args:
        search: Optional case-insensitive substring to filter by connection name or group.
        include_all: Also return connections that cannot run commands (VNC, telnet, RDP without WinRM).
    """
    conns = await _mgr().connections(refresh=True)
    if not include_all:
        conns = [c for c in conns if c.kind]
    if search:
        s = search.lower()
        conns = [c for c in conns if s in c.full_name.lower()]
    return [c.to_dict() for c in sorted(conns, key=lambda c: c.full_name.lower())]


@mcp.tool()
async def run_command(
    connection: str,
    command: str,
    timeout_seconds: float | None = None,
    shell: Literal["posix", "powershell"] | None = None,
) -> str:
    """Run a command on a server through Guacamole and return the output.

    SSH connections (Linux): POSIX shell syntax. The session is reused between calls
    (working directory and env vars persist); stdout and stderr are merged.
    RDP connections with WinRM (Windows): PowerShell syntax. Each call is a new PowerShell
    process: only the working directory persists, variables do NOT (combine dependent steps
    in one command). Output arrives only at the end; on timeout the command is NOT cancelled.
    Commands must be non-interactive.

    Args:
        connection: Connection name (exact or unique partial match), "group/name", or identifier.
        command: Command to execute (POSIX shell or PowerShell, see list_connections "shell").
        timeout_seconds: Max time to wait (default from GUACAMOLE_COMMAND_TIMEOUT, 60s).
            SSH: on timeout the command receives Ctrl+C and partial output is returned.
            WinRM: on timeout no output is returned and the command keeps running on the server.
        shell: Language the command is written in ("posix" or "powershell", from list_connections).
            When given, the command is refused if the connection uses the other one, so a
            pre-execution policy can trust it to classify the command.
    """
    mgr = _mgr()
    conn = await mgr.resolve(connection)
    if shell is not None and shell != conn.shell:
        raise GuacamoleError(f"Connection '{conn.full_name}' runs {conn.shell} commands, not {shell}; command not executed.")
    session = await mgr.session_for(conn)
    result = await session.run(command, timeout_seconds or mgr.settings.default_timeout)

    header = [f"[{conn.full_name}] exit_code={result.exit_code if result.exit_code is not None else 'unknown'}"
              f" duration={result.duration:.1f}s"]
    if isinstance(session, GuacamoleWinRMSession):
        header[0] += f" cwd={session.cwd}"
    if result.timed_out and isinstance(session, GuacamoleWinRMSession):
        header.append("TIMED OUT: the command was not cancelled and may still be running on the server.")
    elif result.timed_out:
        header.append("TIMED OUT: command was interrupted with Ctrl+C; output may be partial.")
    if result.truncated:
        header.append(f"Output truncated to {session.max_output_bytes} bytes; narrow the command (grep/tail/head).")
    return "\n".join(header) + "\n" + (result.output or "(no output)")


@mcp.tool()
async def list_sessions() -> list[dict]:
    """List SSH sessions currently kept open by this MCP server."""
    now = time.time()
    return [
        {
            "connection": s.connection.full_name,
            "identifier": s.connection.identifier,
            "type": s.connection.kind,
            "open": s.is_open,
            "age_seconds": int(now - s.created_at),
            "idle_seconds": int(now - s.last_used),
        }
        for s in _mgr().sessions.values()
    ]


@mcp.tool()
async def close_session(connection: str) -> str:
    """Close the open session for a connection (a new one is opened on the next run_command)."""
    mgr = _mgr()
    conn = await mgr.resolve(connection)
    return f"Session for '{conn.full_name}' closed." if await mgr.close(conn) else f"No open session for '{conn.full_name}'."


# Administration. The tools act as the configured Guacamole user: Guacamole refuses (HTTP 403)
# what its permissions do not allow, so the same server serves read-only and admin users.

ConnectionProtocol = Literal["ssh", "rdp", "vnc", "telnet", "kubernetes"]
Values = dict[str, str | int | bool | None]
Permission = Literal[
    "READ", "UPDATE", "DELETE", "ADMINISTER", "AUDIT", "CREATE_USER", "CREATE_USER_GROUP",
    "CREATE_CONNECTION", "CREATE_CONNECTION_GROUP", "CREATE_SHARING_PROFILE",
]


@mcp.tool()
async def get_current_user() -> dict:
    """Show the Guacamole user this server acts as and what it may administer.

    Returns its system permissions (ADMINISTER, CREATE_USER, CREATE_CONNECTION, ...), user groups
    and on how many connections, groups and users it holds each permission. Check it before
    administering: Guacamole refuses (HTTP 403) what these permissions do not allow.
    """
    return await _admin().current_user()


@mcp.tool()
async def get_connection(connection: str, history_limit: int = 10) -> dict:
    """Show a connection's settings and recent use.

    Returns protocol, group, parameters (hostname, port, username...; passwords and keys masked
    as ***), attributes and the latest sessions. Parameters need UPDATE permission on the connection.

    Args:
        connection: Connection name (exact or unique partial match), "group/name", or identifier;
            any protocol (see list_connections with include_all=True).
        history_limit: Most recent sessions to return (0 for none).
    """
    return await _admin().connection(connection, history_limit)


@mcp.tool()
async def list_connection_groups(search: str | None = None) -> list[dict]:
    """List connection groups (folders) with path, identifier, type and number of children.

    Args:
        search: Optional case-insensitive substring of the group path.
    """
    return await _admin().connection_groups(search)


@mcp.tool()
async def list_active_connections(search: str | None = None) -> list[dict]:
    """List the sessions open right now in Guacamole: connection, user, remote address, start time.

    Without ADMINISTER, Guacamole only shows the configured user's own sessions.

    Args:
        search: Optional case-insensitive substring of the connection name or username.
    """
    return await _admin().active_connections(search)


@mcp.tool()
async def list_users(search: str | None = None) -> list[dict]:
    """List Guacamole users: username, full name, e-mail, organization, disabled, last activity.

    Args:
        search: Optional case-insensitive substring of username, full name, e-mail, organization or role.
    """
    return await _admin().users(search)


@mcp.tool()
async def get_user(username: str, history_limit: int = 10, include_effective: bool = False) -> dict:
    """Show a user: attributes, user groups, permissions granted to it and recent logins.

    Args:
        username: Exact username.
        history_limit: Most recent logins to return (0 for none).
        include_effective: Also return the effective permissions (its own plus those inherited
            from its groups), e.g. to answer which connections the user can open.
    """
    return await _admin().user(username, history_limit, include_effective)


@mcp.tool()
async def list_user_groups(search: str | None = None) -> list[dict]:
    """List user groups (name and whether disabled).

    Args:
        search: Optional case-insensitive substring of the group name.
    """
    return await _admin().user_groups(search)


@mcp.tool()
async def get_user_group(group: str) -> dict:
    """Show a user group: member users, member groups, parent groups and permissions.

    Args:
        group: Exact user group name.
    """
    return await _admin().user_group(group)


@mcp.tool()
async def create_connection(
    name: str,
    protocol: ConnectionProtocol,
    parameters: Values,
    group: str = "ROOT",
    attributes: Values | None = None,
) -> dict:
    """Create a connection. CHANGES GUACAMOLE: only when the user asked for this change.

    Args:
        name: Connection name (e.g. L-24410-WEB-03).
        protocol: Guacamole protocol.
        parameters: Connection parameters, e.g. {"hostname": "10.0.0.3", "port": 22,
            "username": "remops", "password": "..."}; RDP usually adds "security", "ignore-cert"
            and "domain". Nothing is added by default (e.g. session recording parameters).
        group: Parent connection group: exact path ("Clientes/Linux/24410 - ACME"), name,
            identifier or ROOT.
        attributes: Connection attributes, e.g. {"max-connections": 2} or, for the
            guacamole-winrm extension, {"winrm-enabled": true, "winrm-port": 5985}.
    """
    return await _admin().create_connection(name, protocol, parameters, group, attributes)


@mcp.tool()
async def update_connection(
    connection: str,
    name: str | None = None,
    group: str | None = None,
    parameters: Values | None = None,
    attributes: Values | None = None,
) -> dict:
    """Rename, move or reconfigure a connection. CHANGES GUACAMOLE: only when the user asked for it.

    Only the given fields change; a parameter or attribute set to null is cleared. An open
    session on the connection is closed, so the next run_command uses the new settings.

    Args:
        connection: Exact connection name, "group/name" or identifier.
        name: New name.
        group: New parent group (exact path, name, identifier or ROOT).
        parameters: Parameters to set, e.g. {"hostname": "10.0.0.4"} or {"password": null}.
        attributes: Attributes to set, e.g. {"winrm-enabled": true}.
    """
    return await _admin().update_connection(connection, name, group, parameters, attributes)


@mcp.tool()
async def delete_connection(connection: str) -> dict:
    """Delete a connection. CHANGES GUACAMOLE and cannot be undone: only when the user asked for it.

    Args:
        connection: Exact connection name, "group/name" or identifier.
    """
    return await _admin().delete_connection(connection)


@mcp.tool()
async def create_connection_group(
    name: str,
    parent: str = "ROOT",
    type: Literal["ORGANIZATIONAL", "BALANCING"] = "ORGANIZATIONAL",
    attributes: Values | None = None,
) -> dict:
    """Create a connection group. CHANGES GUACAMOLE: only when the user asked for this change.

    Args:
        name: Group name (e.g. "24410 - ACME LTDA").
        parent: Parent group: exact path ("Clientes/Linux"), name, identifier or ROOT.
        type: ORGANIZATIONAL (a folder) or BALANCING (load balancing among its connections).
        attributes: Group attributes, e.g. {"max-connections": 10}.
    """
    return await _admin().create_connection_group(name, parent, type, attributes)


@mcp.tool()
async def update_connection_group(
    group: str,
    name: str | None = None,
    parent: str | None = None,
    attributes: Values | None = None,
) -> dict:
    """Rename or move a connection group. CHANGES GUACAMOLE: only when the user asked for it.

    Args:
        group: Exact group path, name or identifier.
        name: New name.
        parent: New parent group (exact path, name, identifier or ROOT).
        attributes: Attributes to set; null clears one.
    """
    return await _admin().update_connection_group(group, name, parent, attributes)


@mcp.tool()
async def delete_connection_group(group: str) -> dict:
    """Delete an empty connection group. CHANGES GUACAMOLE: only when the user asked for it.

    Refused while the group has connections or subgroups (Guacamole would delete them all).
    Children the configured user cannot see are not counted.

    Args:
        group: Exact group path, name or identifier.
    """
    return await _admin().delete_connection_group(group)


@mcp.tool()
async def create_user(username: str, password: str | None = None, attributes: Values | None = None) -> dict:
    """Create a user. CHANGES GUACAMOLE: only when the user asked for this change.

    Access is given afterwards with update_group_members or update_permissions.

    Args:
        username: Username.
        password: Initial password; leave out for users that log in only through LDAP/SSO.
        attributes: e.g. {"guac-full-name": "...", "guac-email-address": "...",
            "guac-organization": "...", "guac-organizational-role": "...",
            "expired": true (must change the password at the next login),
            "valid-until": "2026-12-31", "timezone": "America/Sao_Paulo"}.
    """
    return await _admin().create_user(username, password, attributes)


@mcp.tool()
async def update_user(
    username: str,
    password: str | None = None,
    disabled: bool | None = None,
    attributes: Values | None = None,
) -> dict:
    """Change a user's password, enable/disable it or set attributes. CHANGES GUACAMOLE: only when
    the user asked for it. Only the given fields change; an attribute set to null is cleared.

    Args:
        username: Exact username.
        password: New password.
        disabled: true disables the login, false enables it again.
        attributes: Attributes to set (see create_user).
    """
    return await _admin().update_user(username, password, disabled, attributes)


@mcp.tool()
async def delete_user(username: str) -> dict:
    """Delete a user. CHANGES GUACAMOLE and cannot be undone (prefer update_user disabled=true):
    only when the user asked for it.

    Args:
        username: Exact username.
    """
    return await _admin().delete_user(username)


@mcp.tool()
async def create_user_group(name: str, attributes: Values | None = None) -> dict:
    """Create a user group. CHANGES GUACAMOLE: only when the user asked for this change.

    Members are added with update_group_members and access with update_permissions.

    Args:
        name: Group name.
        attributes: Group attributes.
    """
    return await _admin().create_user_group(name, attributes)


@mcp.tool()
async def update_user_group(group: str, disabled: bool | None = None, attributes: Values | None = None) -> dict:
    """Enable/disable a user group or set its attributes. CHANGES GUACAMOLE: only when the user asked for it.

    Args:
        group: Exact user group name.
        disabled: true disables the group (its members lose what it grants), false enables it.
        attributes: Attributes to set; null clears one.
    """
    return await _admin().update_user_group(group, disabled, attributes)


@mcp.tool()
async def delete_user_group(group: str) -> dict:
    """Delete a user group (members lose what it grants). CHANGES GUACAMOLE and cannot be undone:
    only when the user asked for it.

    Args:
        group: Exact user group name.
    """
    return await _admin().delete_user_group(group)


@mcp.tool()
async def update_group_members(
    group: str,
    add_users: list[str] | None = None,
    remove_users: list[str] | None = None,
    add_groups: list[str] | None = None,
    remove_groups: list[str] | None = None,
) -> dict:
    """Add or remove members of a user group. CHANGES GUACAMOLE: only when the user asked for it.

    Returns the resulting members; `not_applied` lists names Guacamole skipped (e.g. not found).

    Args:
        group: Exact user group name.
        add_users / remove_users: Usernames.
        add_groups / remove_groups: User groups nested in this one.
    """
    return await _admin().update_group_members(group, add_users, remove_users, add_groups, remove_groups)


@mcp.tool()
async def update_permissions(
    target_type: Literal["connection", "connection_group", "user", "user_group", "system"],
    target: str | None = None,
    grant: list[Permission] | None = None,
    revoke: list[Permission] | None = None,
    user: str | None = None,
    user_group: str | None = None,
) -> dict:
    """Grant or revoke permissions of a user or user group on one target. CHANGES GUACAMOLE:
    only when the user asked for this change.

    Example: access to a server = update_permissions(user="joao", target_type="connection",
    target="L-24410-WEB-03", grant=["READ"]); a whole folder = target_type="connection_group".

    Args:
        target_type: What the permissions apply to; "system" for system-wide permissions.
        target: Exact connection (name, "group/name" or identifier), connection group (path or
            identifier), username or user group name; leave out for "system".
        grant / revoke: For objects READ (use/see), UPDATE, DELETE, ADMINISTER (manage its
            permissions); for "system" ADMINISTER, AUDIT, CREATE_USER, CREATE_USER_GROUP,
            CREATE_CONNECTION, CREATE_CONNECTION_GROUP, CREATE_SHARING_PROFILE.
        user / user_group: Whose permissions change (exactly one).
    """
    return await _admin().update_permissions(target_type, target, grant, revoke, user, user_group)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("GUACAMOLE_LOG_LEVEL", "WARNING").upper(),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport == "stdio":
        mcp.run()
        return
    if transport not in ("http", "streamable-http"):
        raise SystemExit(f"Invalid MCP_TRANSPORT '{transport}': use 'stdio' or 'http'")

    Settings()  # fail at startup, not on the first client, if GUACAMOLE_* is missing
    mcp.settings.host = os.environ.get("MCP_HOST", "127.0.0.1")
    mcp.settings.port = int(os.environ.get("MCP_PORT", "8000"))
    allowed_hosts = [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
    if allowed_hosts:
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[f"{scheme}://{h}" for h in allowed_hosts for scheme in ("http", "https")],
        )
    elif mcp.settings.host not in ("127.0.0.1", "localhost", "::1"):
        mcp.settings.transport_security = None
    log.warning(
        "Serving MCP over HTTP on %s:%s%s without authentication; every client acts as Guacamole user '%s'",
        mcp.settings.host, mcp.settings.port, mcp.settings.streamable_http_path, os.environ["GUACAMOLE_USERNAME"],
    )
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
