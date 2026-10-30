"""Minimal client for the Apache Guacamole REST API."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx


class GuacamoleError(Exception):
    pass


class GuacamolePermissionError(GuacamoleError):
    """Guacamole refused the call (HTTP 403) although the token is valid."""


@dataclass
class Connection:
    identifier: str
    name: str
    protocol: str
    data_source: str
    group_path: str = ""
    attributes: dict = field(default_factory=dict)

    @property
    def winrm_enabled(self) -> bool:
        # Attribute added by the guacamole-winrm extension to RDP connections.
        return self.protocol == "rdp" and self.attributes.get("winrm-enabled") == "true"

    @property
    def kind(self) -> str | None:
        """How commands are executed on this connection, or None if they cannot be."""
        if self.protocol == "ssh":
            return "ssh"
        if self.winrm_enabled:
            return "winrm"
        return None

    @property
    def shell(self) -> str | None:
        """Language run_command expects on this connection: "posix", "powershell" or None."""
        return {"ssh": "posix", "winrm": "powershell"}.get(self.kind or "", None)

    @property
    def full_name(self) -> str:
        return f"{self.group_path}/{self.name}" if self.group_path else self.name

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "identifier": self.identifier,
            "protocol": self.protocol,
            "shell": self.shell,
            "data_source": self.data_source,
            "group": self.group_path or "ROOT",
        }


@dataclass
class ConnectionGroup:
    identifier: str
    name: str
    type: str
    data_source: str
    path: str = ""  # "" for ROOT
    parent_identifier: str | None = None
    connections: int = 0
    groups: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "identifier": self.identifier,
            "path": self.path or "ROOT",
            "type": self.type,
            "data_source": self.data_source,
            "connections": self.connections,
            "groups": self.groups,
        }


class GuacamoleAPI:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        data_sources: list[str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._forced_data_sources = data_sources
        self.token: str | None = None
        self.data_sources: list[str] = []
        # Where users, groups and new connections are administered: the first of
        # GUACAMOLE_DATA_SOURCES, or the data source that authenticated the user.
        self.primary_data_source = ""
        self._http = httpx.AsyncClient(verify=verify_ssl, timeout=30.0, transport=transport)
        self._auth_lock = asyncio.Lock()

    async def close(self) -> None:
        await self._http.aclose()

    async def authenticate(self) -> str:
        async with self._auth_lock:
            resp = await self._http.post(
                f"{self.base_url}/api/tokens",
                data={"username": self.username, "password": self.password},
            )
            if resp.status_code != 200:
                raise GuacamoleError(
                    f"Guacamole authentication failed (HTTP {resp.status_code}): {resp.text[:300]}"
                )
            body = resp.json()
            self.token = body["authToken"]
            self.data_sources = self._forced_data_sources or body.get(
                "availableDataSources", [body.get("dataSource")]
            )
            if self._forced_data_sources:
                self.primary_data_source = self._forced_data_sources[0]
            else:
                self.primary_data_source = body.get("dataSource") or self.data_sources[0]
            return self.token

    async def ensure_token(self) -> str:
        if self.token is None:
            await self.authenticate()
        return self.token  # type: ignore[return-value]

    async def _token_is_valid(self) -> bool:
        try:
            resp = await self._http.get(
                f"{self.base_url}/api/session/data/{quote(self.primary_data_source, safe='')}/self",
                headers={"Guacamole-Token": self.token or ""},
            )
        except httpx.HTTPError:
            return False
        return resp.status_code == 200

    async def _request(self, method: str, path: str, json: dict | list | None = None, timeout: float | None = None):
        await self.ensure_token()
        for attempt in range(2):
            try:
                resp = await self._http.request(
                    method,
                    f"{self.base_url}/api{path}",
                    headers={"Guacamole-Token": self.token or ""},
                    json=json,
                    timeout=timeout or self._http.timeout,
                )
            except httpx.TimeoutException:
                raise
            except httpx.HTTPError as exc:
                raise GuacamoleError(f"{method} {path} failed: {type(exc).__name__}: {exc}") from exc
            # Guacamole answers 403 both for an expired token and for a missing permission:
            # only log in again when the token itself is no longer valid.
            if attempt == 0 and (resp.status_code == 401 or (resp.status_code == 403 and not await self._token_is_valid())):
                await self.authenticate()
                continue
            if resp.status_code == 403:
                raise GuacamolePermissionError(
                    f"{method} {path} refused (HTTP 403): {_error_message(resp)} "
                    f"The Guacamole user '{self.username}' does not have the permission for this."
                )
            if not 200 <= resp.status_code < 300:
                raise GuacamoleError(f"{method} {path} failed (HTTP {resp.status_code}): {_error_message(resp)}")
            if resp.status_code == 204 or not resp.content:
                return None
            return resp.json()

    async def _get(self, path: str):
        return await self._request("GET", path)

    async def default_data_source(self) -> str:
        await self.ensure_token()
        return self.primary_data_source

    async def data(self, method: str, path: str, json: dict | list | None = None, data_source: str | None = None):
        """Call api/session/data/{dataSource}{path} (default: the primary data source)."""
        ds = data_source or await self.default_data_source()
        return await self._request(method, f"/session/data/{quote(ds, safe='')}{path}", json=json)

    # Endpoints of the guacamole-winrm extension (api/session/ext/{dataSource}/...).

    async def winrm_info(self, conn: Connection) -> dict:
        return await self._request("GET", f"/session/ext/{conn.data_source}/connections/{conn.identifier}")

    async def winrm_execute(self, conn: Connection, command: str, cwd: str | None, timeout: float) -> dict:
        return await self._request(
            "POST",
            f"/session/ext/{conn.data_source}/connections/{conn.identifier}/execute",
            json={"command": command, "cwd": cwd},
            timeout=timeout,
        )

    async def load_tree(self) -> tuple[list[Connection], list[ConnectionGroup]]:
        """Connections and connection groups (ROOT included) of every data source."""
        await self.ensure_token()
        connections: list[Connection] = []
        groups: list[ConnectionGroup] = []
        for ds in self.data_sources:
            try:
                tree = await self._get(f"/session/data/{ds}/connectionGroups/ROOT/tree")
            except GuacamoleError:
                # Some data sources (e.g. LDAP without connections) may not expose a tree.
                continue
            self._walk(tree, ds, "", connections, groups, None)
        return connections, groups

    def _walk(
        self, group: dict, ds: str, path: str, out: list[Connection], groups: list[ConnectionGroup], parent: str | None
    ) -> None:
        identifier = str(group.get("identifier") or "ROOT")
        children = group.get("childConnectionGroups", []) or []
        groups.append(
            ConnectionGroup(
                identifier=identifier,
                name=group.get("name", ""),
                type=group.get("type", "ORGANIZATIONAL"),
                data_source=ds,
                path=path,
                parent_identifier=parent,
                connections=len(group.get("childConnections", []) or []),
                groups=len(children),
            )
        )
        for conn in group.get("childConnections", []) or []:
            out.append(
                Connection(
                    identifier=str(conn["identifier"]),
                    name=conn.get("name", ""),
                    protocol=conn.get("protocol", ""),
                    data_source=ds,
                    group_path=path,
                    attributes=conn.get("attributes", {}) or {},
                )
            )
        for child in children:
            child_path = f"{path}/{child.get('name', '')}" if path else child.get("name", "")
            self._walk(child, ds, child_path, out, groups, identifier)

    def websocket_url(self) -> str:
        if self.base_url.startswith("https://"):
            return "wss://" + self.base_url[len("https://"):] + "/websocket-tunnel"
        if self.base_url.startswith("http://"):
            return "ws://" + self.base_url[len("http://"):] + "/websocket-tunnel"
        raise GuacamoleError(f"Unsupported Guacamole URL: {self.base_url}")


def _error_message(resp: httpx.Response) -> str:
    try:
        return resp.json().get("message") or resp.text[:300]
    except ValueError:
        return resp.text[:300]
