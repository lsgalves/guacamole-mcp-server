"""MCP server exposing Apache Guacamole SSH connections as command-execution tools."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .api import Connection, GuacamoleAPI, GuacamoleError
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
2. Call `run_command` with that connection name and a non-interactive command in that language.
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
        self._connections_at = 0.0
        self._reaper: asyncio.Task | None = None

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
        if refresh or not self._connections or time.time() - self._connections_at > 60:
            self._connections = await self.api.list_connections()
            self._connections_at = time.time()
        return self._connections

    async def resolve(self, query: str) -> Connection:
        q = query.strip().lower()
        for refresh in (False, True):
            usable = [c for c in await self.connections(refresh) if c.kind]
            for matcher in (
                lambda c: c.identifier == query.strip(),
                lambda c: c.name.lower() == q,
                lambda c: c.full_name.lower() == q,
            ):
                exact = [c for c in usable if matcher(c)]
                if len(exact) == 1:
                    return exact[0]
                if len(exact) > 1:
                    raise GuacamoleError(_ambiguous(query, exact))
            partial = [c for c in usable if q in c.full_name.lower()]
            if len(partial) == 1:
                return partial[0]
            if len(partial) > 1:
                raise GuacamoleError(_ambiguous(query, partial))
        raise GuacamoleError(
            f"No SSH or WinRM-enabled RDP connection matches '{query}'. Use list_connections to see available connections."
        )

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
async def run_command(connection: str, command: str, timeout_seconds: float | None = None) -> str:
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
    """
    mgr = _mgr()
    conn = await mgr.resolve(connection)
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
