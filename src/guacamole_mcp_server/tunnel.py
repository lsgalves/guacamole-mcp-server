"""Run shell commands on a Guacamole SSH connection over the WebSocket tunnel.

Guacamole renders SSH terminals as images, so the terminal output cannot be
read as text directly. Instead this module relies on two guacd features:

* Input: an inbound pipe stream named "STDIN" is written straight to the
  terminal's standard input (the same mechanism used by `guacctl`).
* Output: the terminal emulator understands the private OSC sequences
  ``ESC ] 482202 ; <flags> ; <name> BEL`` (redirect terminal output to an
  outbound pipe stream called <name>) and ``ESC ] 482203 BEL`` (close it).

Each command is therefore typed into the remote shell wrapped with printf
calls that open and close an output pipe, and the captured bytes are the
command's output.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import ssl
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlencode

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed

from .api import Connection, GuacamoleAPI, GuacamoleError

log = logging.getLogger(__name__)

PIPE_OPEN_OSC = 482202
PIPE_CLOSE_OSC = 482203
PIPE_FLAG_AUTOFLUSH = 2
STDIN_CHUNK = 3000  # raw bytes per blob; keeps instructions well below guacd's 8 KiB limit
CTRL_C = b"\x03"


def encode_instruction(opcode: str, *args: str) -> str:
    return ",".join(f"{len(e)}.{e}" for e in (opcode, *args)) + ";"


class InstructionParser:
    """Incremental parser for the Guacamole protocol (LENGTH.VALUE,...;)."""

    def __init__(self) -> None:
        self._buf = ""

    def feed(self, data: str) -> list[list[str]]:
        self._buf += data
        out: list[list[str]] = []
        while True:
            elements: list[str] = []
            pos = 0
            complete = False
            while True:
                dot = self._buf.find(".", pos)
                if dot == -1:
                    break
                length = int(self._buf[pos:dot])
                end = dot + 1 + length
                if end >= len(self._buf):
                    break
                elements.append(self._buf[dot + 1 : end])
                term = self._buf[end]
                pos = end + 1
                if term == ";":
                    complete = True
                    break
            if not complete:
                return out
            out.append(elements)
            self._buf = self._buf[pos:]


@dataclass
class CommandResult:
    output: str
    exit_code: int | None
    timed_out: bool
    duration: float
    truncated: bool = False


@dataclass
class _PendingCommand:
    pipe_name: str
    rc_marker: str
    data: bytearray = field(default_factory=bytearray)
    tail: bytes = b""  # last bytes received, so the exit-code marker survives truncation
    total: int = 0
    opened: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)


class GuacamoleSSHSession:
    def __init__(
        self,
        api: GuacamoleAPI,
        connection: Connection,
        width: int = 1024,
        height: int = 768,
        max_output_bytes: int = 200_000,
    ) -> None:
        self.api = api
        self.connection = connection
        self.width = width
        self.height = height
        self.max_output_bytes = max_output_bytes
        self.created_at = time.time()
        self.last_used = self.created_at

        self._ws: ClientConnection | None = None
        self._reader: asyncio.Task | None = None
        self._keepalive: asyncio.Task | None = None
        self._parser = InstructionParser()
        self._send_lock = asyncio.Lock()
        self._command_lock = asyncio.Lock()
        self._next_stream = 0
        self._ready = asyncio.Event()
        self._closed = asyncio.Event()
        self._error: str | None = None
        self._pending: dict[str, _PendingCommand] = {}  # pipe name -> command
        self._pipes: dict[str, _PendingCommand] = {}  # inbound stream index -> command
        self._acks: dict[str, asyncio.Future] = {}  # outbound stream index -> ack future

    @property
    def is_open(self) -> bool:
        return self._ws is not None and not self._closed.is_set()

    # ------------------------------------------------------------------ lifecycle

    async def open(self, timeout: float = 30.0) -> None:
        if self.connection.protocol != "ssh":
            raise GuacamoleError(
                f"Connection '{self.connection.name}' uses protocol '{self.connection.protocol}', only 'ssh' is supported"
            )
        token = await self.api.ensure_token()
        params = {
            "token": token,
            "GUAC_DATA_SOURCE": self.connection.data_source,
            "GUAC_ID": self.connection.identifier,
            "GUAC_TYPE": "c",
            "GUAC_WIDTH": str(self.width),
            "GUAC_HEIGHT": str(self.height),
            "GUAC_DPI": "96",
            "GUAC_TIMEZONE": "UTC",
            "GUAC_IMAGE": "image/png",
        }
        url = f"{self.api.websocket_url()}?{urlencode(params)}"
        ssl_ctx = None
        if url.startswith("wss://"):
            ssl_ctx = ssl.create_default_context()
            if not self.api.verify_ssl:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

        self._ws = await connect(
            url,
            subprotocols=["guacamole"],  # type: ignore[list-item]
            ssl=ssl_ctx,
            max_size=None,
            open_timeout=timeout,
            ping_interval=None,
        )
        self._reader = asyncio.create_task(self._read_loop())
        self._keepalive = asyncio.create_task(self._keepalive_loop())

        ready = asyncio.create_task(self._ready.wait())
        closed = asyncio.create_task(self._closed.wait())
        done, pending = await asyncio.wait({ready, closed}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        if not self._ready.is_set():
            await self.close()
            raise GuacamoleError(self._error or f"Timed out waiting for connection '{self.connection.name}' to start")

        await self._wait_for_shell()

    async def _wait_for_shell(self) -> None:
        """Send a probe until the remote shell answers (login/MOTD may take a while)."""
        for attempt, probe_timeout in enumerate((15.0, 10.0, 10.0)):
            result = await self._run_unlocked("echo __guac_mcp_ready__", probe_timeout, interrupt=False)
            if "__guac_mcp_ready__" in result.output:
                return
            if self._closed.is_set():
                break
        await self.close()
        raise GuacamoleError(
            self._error
            or f"Shell on '{self.connection.name}' did not respond. The connection may require interactive "
            "login (credentials not stored in Guacamole), be read-only, or not run a POSIX shell."
        )

    async def close(self) -> None:
        if self._ws is not None and not self._closed.is_set():
            try:
                await self._send("disconnect")
            except Exception:
                pass
            try:
                await self._ws.close()
            except Exception:
                pass
        self._closed.set()
        for task in (self._reader, self._keepalive):
            if task is not None and task is not asyncio.current_task():
                task.cancel()
        for cmd in self._pending.values():
            cmd.done.set()

    # ------------------------------------------------------------------ protocol I/O

    async def _send(self, opcode: str, *args: str) -> None:
        if self._ws is None:
            raise GuacamoleError("Tunnel is not open")
        async with self._send_lock:
            await self._ws.send(encode_instruction(opcode, *args))

    async def _keepalive_loop(self) -> None:
        try:
            while not self._closed.is_set():
                await asyncio.sleep(5)
                await self._send("nop")
        except (asyncio.CancelledError, ConnectionClosed, GuacamoleError):
            pass

    async def _read_loop(self) -> None:
        assert self._ws is not None
        try:
            async for message in self._ws:
                if isinstance(message, bytes):
                    message = message.decode("utf-8", errors="replace")
                for instr in self._parser.feed(message):
                    await self._handle(instr[0], instr[1:])
        except (asyncio.CancelledError, ConnectionClosed):
            pass
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("Guacamole tunnel reader failed")
            self._error = self._error or f"Tunnel reader failed: {exc}"
        finally:
            self._closed.set()
            for cmd in self._pending.values():
                cmd.done.set()
            for fut in self._acks.values():
                if not fut.done():
                    fut.set_exception(GuacamoleError(self._error or "Tunnel closed"))

    async def _handle(self, opcode: str, args: list[str]) -> None:
        if opcode == "sync":
            await self._send("sync", args[0])
            self._ready.set()
        elif opcode == "" and args and args[0] == "ping":
            await self._send("", *args)
        elif opcode == "pipe":
            index, _mimetype, name = args[0], args[1], args[2]
            cmd = next((c for n, c in self._pending.items() if n in name), None)
            if cmd is not None:
                self._pipes[index] = cmd
                cmd.opened.set()
                await self._send("ack", index, "OK", "0")
        elif opcode == "blob":
            cmd = self._pipes.get(args[0])
            if cmd is not None:
                chunk = base64.b64decode(args[1])
                cmd.total += len(chunk)
                cmd.tail = (cmd.tail + chunk)[-512:]
                if len(cmd.data) < self.max_output_bytes:
                    cmd.data.extend(chunk[: self.max_output_bytes - len(cmd.data)])
                await self._send("ack", args[0], "OK", "0")
        elif opcode == "end":
            cmd = self._pipes.pop(args[0], None)
            if cmd is not None:
                cmd.done.set()
        elif opcode == "ack":
            fut = self._acks.get(args[0])
            if fut is not None and not fut.done():
                fut.set_result((args[1], int(args[2])))
        elif opcode == "error":
            self._error = f"Guacamole error {args[1] if len(args) > 1 else ''}: {args[0]}"
            log.warning(self._error)
            asyncio.create_task(self.close())
        elif opcode == "disconnect":
            self._error = self._error or "Remote side disconnected"
            asyncio.create_task(self.close())

    async def _write_stdin(self, data: bytes) -> None:
        index = str(self._next_stream)
        self._next_stream += 1
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._acks[index] = fut
        try:
            await self._send("pipe", index, "text/plain", "STDIN")
            for i in range(0, len(data), STDIN_CHUNK):
                await self._send("blob", index, base64.b64encode(data[i : i + STDIN_CHUNK]).decode())
            await self._send("end", index)
            # guacd acks the pipe (and every blob); a non-zero status means it was refused.
            message, status = await asyncio.wait_for(fut, timeout=10)
            if status != 0:
                raise GuacamoleError(f"guacd refused terminal input (status {status}): {message}")
        except asyncio.TimeoutError:
            pass  # older guacd versions may not ack; input is still delivered
        finally:
            self._acks.pop(index, None)

    # ------------------------------------------------------------------ commands

    async def run(self, command: str, timeout: float = 60.0) -> CommandResult:
        async with self._command_lock:
            if not self.is_open:
                raise GuacamoleError(self._error or "Session is closed")
            self.last_used = time.time()
            return await self._run_unlocked(command, timeout, interrupt=True)

    async def _run_unlocked(self, command: str, timeout: float, interrupt: bool) -> CommandResult:
        tag = uuid.uuid4().hex[:12]
        cmd = _PendingCommand(pipe_name=f"guac-mcp-{tag}", rc_marker=f"__guac_mcp_rc_{tag}__")
        self._pending[cmd.pipe_name] = cmd

        payload = base64.b64encode(command.encode()).decode()
        # Leading space keeps the line out of shell history (HISTCONTROL=ignorespace).
        line = (
            f" printf '\\033]{PIPE_OPEN_OSC};{PIPE_FLAG_AUTOFLUSH};{cmd.pipe_name}\\007';"
            f' eval "$(printf %s {payload} | base64 -d)" </dev/null 2>&1;'
            f" printf '\\n{cmd.rc_marker}%s\\n' \"$?\";"
            f" printf '\\033]{PIPE_CLOSE_OSC};\\007'\n"
        )

        start = time.monotonic()
        timed_out = False
        try:
            await self._write_stdin(line.encode())
            try:
                await asyncio.wait_for(cmd.done.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                timed_out = True
                if interrupt and self.is_open:
                    await self._interrupt(cmd)
        finally:
            self._pending.pop(cmd.pipe_name, None)

        return self._build_result(cmd, timed_out, time.monotonic() - start)

    async def _interrupt(self, cmd: _PendingCommand) -> None:
        """Ctrl+C the running command and close the output pipe so partial output is flushed."""
        await self._write_stdin(CTRL_C)
        await asyncio.sleep(1)
        await self._write_stdin(f" printf '\\033]{PIPE_CLOSE_OSC};\\007'\n".encode())
        try:
            await asyncio.wait_for(cmd.done.wait(), timeout=5)
        except asyncio.TimeoutError:
            # The shell is stuck (command ignores SIGINT); drop the session so the next call reconnects.
            self._error = "Command did not stop after Ctrl+C; session was closed"
            await self.close()

    def _build_result(self, cmd: _PendingCommand, timed_out: bool, duration: float) -> CommandResult:
        truncated = cmd.total > self.max_output_bytes
        text = _clean(bytes(cmd.data))

        exit_code = None
        rc_pattern = rf"\n?{re.escape(cmd.rc_marker)}(-?\d+)\n?"
        match = re.search(rc_pattern, text)
        if match:
            exit_code = int(match.group(1))
            text = text[: match.start()]
        elif truncated and (tail_match := re.search(rc_pattern, _clean(cmd.tail))):
            exit_code = int(tail_match.group(1))
        elif timed_out and "^C" in text:
            # Drop the echoed prompt + pipe-close line typed after the interrupt.
            text = text[: text.rfind("^C") + 2] + "\n"
        if not cmd.opened.is_set() and not text:
            text = "(no output captured: the shell never opened the output pipe)"
        return CommandResult(output=text, exit_code=exit_code, timed_out=timed_out, duration=duration, truncated=truncated)


def _clean(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "")
    # Escape sequences are consumed by guacd; drop remaining control chars except \n and \t.
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text)
