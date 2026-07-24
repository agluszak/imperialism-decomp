"""Wine GDB proxy lifecycle and persistent GDB/MI supervision."""

from __future__ import annotations

import asyncio
from collections import deque
from concurrent.futures import Future
from dataclasses import dataclass
import json
from pathlib import Path
import socket
import subprocess
import threading
import time
from typing import Coroutine, TypeVar

from tools.runtime.debug.mi_process import DebuggerTransportError, GdbMiProcess
from tools.runtime.debug.mi_protocol import MiRecord
from tools.runtime.debug.symbols import LinkerMap, symbolize_gdb_report


REPO_ROOT = Path(__file__).resolve().parents[3]
PROXY_START_TIMEOUT_SECONDS = 45.0
T = TypeVar("T")


@dataclass(frozen=True)
class StopEvent:
    reason: str
    signal_name: str | None
    breakpoint_number: str | None
    raw: str


def stop_event_from_record(record: MiRecord) -> StopEvent | None:
    if record.message != "stopped" or not isinstance(record.payload, dict):
        return None
    reason = record.payload.get("reason")
    signal_name = record.payload.get("signal-name")
    breakpoint_number = record.payload.get("bkptno")
    return StopEvent(
        reason=reason if isinstance(reason, str) else "stopped",
        signal_name=signal_name if isinstance(signal_name, str) else None,
        breakpoint_number=breakpoint_number if isinstance(breakpoint_number, str) else None,
        raw=record.raw,
    )


def is_terminal_stop(event: StopEvent) -> bool:
    return event.reason in {"exited", "exited-normally", "exited-signalled"}


def allocate_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _port_is_listening(port: int) -> bool:
    suffix = f":{port:04X}"
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = table.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) >= 4 and fields[1].endswith(suffix) and fields[3] == "0A":
                return True
    return False


class WineGdbProxy:
    def __init__(
        self,
        executable: Path,
        cwd: Path,
        environment: dict[str, str],
        port: int | None = None,
        log_path: Path | None = None,
        arguments: tuple[str, ...] = (),
    ) -> None:
        self.executable = executable
        self.cwd = cwd
        self.environment = environment
        self.port = allocate_port() if port is None else port
        self.log_path = log_path
        self.arguments = arguments
        self.process: subprocess.Popen[bytes] | None = None
        self._log = None

    def start(self) -> subprocess.Popen[bytes]:
        if not self.executable.is_file():
            raise DebuggerTransportError(f"missing debugger inferior {self.executable}")
        output = subprocess.DEVNULL
        if self.log_path is not None:
            self._log = self.log_path.open("wb")
            output = self._log
        self.process = subprocess.Popen(
            [
                "winedbg",
                "--gdb",
                "--no-start",
                "--port",
                str(self.port),
                str(self.executable),
                *self.arguments,
            ],
            cwd=self.cwd,
            env=self.environment,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + PROXY_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise DebuggerTransportError(
                    f"winedbg --gdb exited early with {self.process.returncode}"
                )
            if _port_is_listening(self.port):
                return self.process
            time.sleep(0.1)
        self.close()
        raise DebuggerTransportError("winedbg --gdb did not open its port")

    def close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        if self._log is not None:
            self._log.close()
            self._log = None


class _AsyncController:
    """Run the MI asyncio transport without imposing asyncio on the test runner."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        self._ready.wait()

    def call(self, coroutine: Coroutine[object, object, T], timeout: float) -> T:
        future: Future[T] = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        return future.result(timeout)

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(timeout=5)
        self.loop.close()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self._ready.set()
        self.loop.run_forever()


class GdbSession:
    """Persistent passive GDB observer for one Wine inferior."""

    def __init__(
        self,
        executable: Path,
        cwd: Path,
        environment: dict[str, str],
        artifact_dir: Path,
        arguments: tuple[str, ...] = (),
    ) -> None:
        self.executable = executable
        self.artifact_dir = artifact_dir
        self.proxy = WineGdbProxy(
            executable,
            cwd,
            environment,
            log_path=artifact_dir / "winedbg.log",
            arguments=arguments,
        )
        self._controller: _AsyncController | None = None
        self._mi: GdbMiProcess | None = None
        self._stops: deque[StopEvent] = deque()
        self.stop_count = 0

    @property
    def process(self) -> subprocess.Popen[bytes]:
        if self.proxy.process is None:
            raise DebuggerTransportError("debugger proxy has not started")
        return self.proxy.process

    def start(self, auto_continue: bool = True) -> subprocess.Popen[bytes]:
        self.proxy.start()
        self._controller = _AsyncController()
        self._controller.start()
        self._mi = GdbMiProcess(REPO_ROOT, self.artifact_dir / "gdb.log")
        try:
            self._call(self._mi.start(self.executable), 15)
            self._command("-gdb-set pagination off")
            self._command("-gdb-set confirm off")
            self._command("-gdb-set mi-async on")
            self._console(f"source {REPO_ROOT / 'tools/runtime/gdb/imperialism.py'}")
            self._command(f"-target-select remote localhost:{self.proxy.port}", timeout=45)
            self._console("handle SIGTRAP stop print nopass")
            self._console("handle SIGSEGV stop print pass")
            self._drain_events()
            self._stops.clear()
            if auto_continue:
                self.continue_inferior()
        except Exception:
            self.close()
            raise
        return self.process

    def continue_inferior(self) -> None:
        self._command("-exec-continue --all")

    def set_breakpoint(self, address: int) -> str:
        mi = self._require_mi()
        result = self._call(mi.command(f"-break-insert *0x{address:08x}"), 32)
        payload = result.result.payload
        breakpoint = payload.get("bkpt") if isinstance(payload, dict) else None
        number = breakpoint.get("number") if isinstance(breakpoint, dict) else None
        if not isinstance(number, str):
            raise DebuggerTransportError(
                f"GDB returned no breakpoint number for 0x{address:08x}"
            )
        return number

    def delete_breakpoint(self, number: str) -> None:
        self._command(f"-break-delete {number}")

    def evaluate(self, expression: str, timeout: float = 10.0) -> str:
        mi = self._require_mi()
        command = f"-data-evaluate-expression {json.dumps(expression)}"
        result = self._call(mi.command(command, timeout), timeout + 2)
        payload = result.result.payload
        if not isinstance(payload, dict) or not isinstance(payload.get("value"), str):
            raise DebuggerTransportError(
                f"GDB expression returned no value: {expression}: {result.result.raw}"
            )
        return payload["value"]

    def assign(self, expression: str, value: int | str) -> None:
        self.evaluate(f"({expression})=({value})")

    def wait_for_stop(self, timeout: float) -> StopEvent | None:
        event = self.poll_stop()
        return event if event is not None else self._wait_for_stop(timeout)

    def poll_stop(self) -> StopEvent | None:
        self._drain_events()
        return self._stops.popleft() if self._stops else None

    def capture_stop(self, label: str, event: StopEvent) -> Path:
        self.stop_count += 1
        path = self.artifact_dir / f"debugger-stop-{self.stop_count:02d}-{label}.txt"
        snapshot_path = self.artifact_dir / f"runtime-snapshot-{self.stop_count:02d}.json"
        map_path = self.executable.with_suffix(".map")
        if map_path.is_file():
            symbol = LinkerMap.read(map_path).find_decorated("_g_runtimeDebugRecord")
            if symbol is not None:
                try:
                    self._console(
                        f'imperialism-runtime-snapshot "{snapshot_path}" '
                        f"0x{symbol.address:08x}"
                    )
                except DebuggerTransportError:
                    pass
        sections = [("stop", [event.raw])]
        for heading, command in (
            ("all threads", "thread apply all bt full"),
            ("registers", "info registers"),
            ("modules", "info sharedlibrary"),
            ("near pc", "x/32i $pc-32"),
            ("stack", "x/256wx $sp"),
        ):
            try:
                output = self._console(command, timeout=30)
            except DebuggerTransportError as error:
                output = [str(error)]
            sections.append((heading, output))
        if snapshot_path.is_file():
            sections.append(
                ("runtime snapshot", snapshot_path.read_text(encoding="utf-8").splitlines())
            )
        with path.open("w", encoding="utf-8") as report:
            for heading, output in sections:
                report.write(f"=== {heading} ===\n")
                report.writelines(
                    line if line.endswith("\n") else line + "\n" for line in output
                )
        symbolize_gdb_report(path, self.executable.with_suffix(".map"))
        return path

    def interrupt_and_capture(self, label: str) -> tuple[Path | None, StopEvent | None]:
        event = self.poll_stop()
        if event is None:
            self._command("-exec-interrupt --all", timeout=5)
            event = self._wait_for_stop(2)
        if event is None:
            self._console("interrupt", timeout=5)
            event = self._wait_for_stop(10)
        if event is None:
            raise DebuggerTransportError(
                "GDB accepted interrupt requests but the Wine remote target did not stop"
            )
        capture_label = label
        if event.signal_name not in {None, "SIGINT"}:
            capture_label = event.signal_name.lower()
        return self.capture_stop(capture_label, event), event

    def close(self) -> None:
        if self._controller is not None and self._mi is not None:
            try:
                self._call(self._mi.close(), 12)
            except Exception:
                pass
        if self._controller is not None:
            self._controller.close()
        self._mi = None
        self._controller = None
        self.proxy.close()

    def _command(self, command: str, timeout: float = 30.0) -> list[str]:
        mi = self._require_mi()
        result = self._call(mi.command(command, timeout), timeout + 2)
        return list(result.output)

    def _console(self, command: str, timeout: float = 30.0) -> list[str]:
        return self._command(
            f"-interpreter-exec console {json.dumps(command)}", timeout=timeout
        )

    def _drain_events(self) -> None:
        records = self._call(self._require_mi().drain_events(), 2)
        for record in records:
            self._record_event(record)

    def _wait_for_stop(self, timeout: float) -> StopEvent | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self._call(
                self._require_mi().next_event(deadline - time.monotonic()),
                deadline - time.monotonic() + 1,
            )
            if record is None:
                return None
            self._record_event(record)
            if self._stops:
                return self._stops.popleft()
        return None

    def _record_event(self, record: MiRecord) -> None:
        event = stop_event_from_record(record)
        if event is not None:
            self._stops.append(event)
        elif record.record_type == "debugger-exit":
            payload = record.payload if isinstance(record.payload, dict) else {}
            raise DebuggerTransportError(
                f"GDB exited with {payload.get('returncode', 'unknown')}"
            )

    def _call(self, coroutine: Coroutine[object, object, T], timeout: float) -> T:
        if self._controller is None:
            coroutine.close()
            raise DebuggerTransportError("GDB controller has not started")
        try:
            return self._controller.call(coroutine, timeout)
        except DebuggerTransportError:
            raise
        except Exception as error:
            raise DebuggerTransportError(str(error)) from error

    def _require_mi(self) -> GdbMiProcess:
        if self._mi is None:
            raise DebuggerTransportError("GDB has not started")
        return self._mi
