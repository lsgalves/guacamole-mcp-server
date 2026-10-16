"""Run PowerShell on Windows hosts through the guacamole-winrm extension.

The extension adds WinRM to RDP connections and exposes ``POST api/session/ext/{dataSource}/connections/{id}/execute``,
which runs a command and returns stdout, stderr, exit code and the resulting
working directory. Credentials and host stay inside Guacamole.

Each call is a separate WinRM execution: only the working directory is carried
over (we send back the ``cwd`` returned by the previous call).
"""

from __future__ import annotations

import time

import httpx

from .api import Connection, GuacamoleAPI, GuacamoleError
from .tunnel import CommandResult



class GuacamoleWinRMSession:
    def __init__(self, api: GuacamoleAPI, connection: Connection, max_output_bytes: int = 200_000) -> None:
        self.api = api
        self.connection = connection
        self.max_output_bytes = max_output_bytes
        self.created_at = time.time()
        self.last_used = self.created_at
        self.cwd: str | None = None
        self._open = False

    @property
    def is_open(self) -> bool:
        return self._open

    async def open(self) -> None:
        info = await self.api.winrm_info(self.connection)
        if not info.get("hostnameAvailable"):
            raise GuacamoleError(
                f"The host of '{self.connection.name}' is not readable by the Guacamole user configured in the MCP "
                "server. The guacamole-winrm extension requires EDIT (update) permission on the connection."
            )
        if info.get("credentialsRequired"):
            raise GuacamoleError(
                f"Connection '{self.connection.name}' has no stored username/password; WinRM cannot be used."
            )
        self._open = True

    async def close(self) -> None:
        self._open = False

    async def run(self, command: str, timeout: float = 60.0) -> CommandResult:
        if not self._open:
            raise GuacamoleError("Session is closed")
        self.last_used = time.time()
        start = time.monotonic()
        try:
            resp = await self.api.winrm_execute(self.connection, command, self.cwd, timeout=timeout)
        except httpx.TimeoutException:
            # The extension offers no way to cancel a running command.
            return CommandResult(
                output="(no output: WinRM returns output only when the command finishes. "
                "The command may STILL BE RUNNING on the server.)",
                exit_code=None,
                timed_out=True,
                duration=time.monotonic() - start,
            )
        self.cwd = resp.get("cwd") or self.cwd

        stdout = (resp.get("stdout") or "").replace("\r\n", "\n").rstrip()
        stdout = stdout + "\n" if stdout else ""
        stderr = (resp.get("stderr") or "").replace("\r\n", "\n").strip()
        output = stdout + (f"\n[stderr]\n{stderr}\n" if stderr else "")
        raw = output.encode()
        truncated = len(raw) > self.max_output_bytes
        if truncated:
            output = raw[: self.max_output_bytes].decode(errors="ignore")
        return CommandResult(
            output=output,
            exit_code=resp.get("exitCode"),
            timed_out=False,
            duration=time.monotonic() - start,
            truncated=truncated,
        )
