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

RUNTIME_INVARIANTS = {
    1: "stationed_military_unit_destructor",
    2: "nation_state_military_unit_overwrite",
}


@dataclass(frozen=True)
class StopEvent:
    reason: str
    signal_name: str | None
    breakpoint_number: str | None
    raw: str


@dataclass(frozen=True)
class DebuggerLifecycle:
    proxy_pid: int | None
    proxy_exit_code: int | None
    gdb_pid: int | None
    gdb_exit_code: int | None
    inferior_pid: int | None
    inferior_exit_code: int | None
    inferior_terminal_reason: str | None
    inferior_signal: str | None
    inferior_active: bool


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


def _parse_exit_code(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(value, 0)
    except ValueError:
        # GDB/MI reports remote exit codes in C-style octal (for example
        # ``0177``), which Python 3 deliberately does not accept with base 0.
        try:
            return int(value, 8) if value.startswith("0") else int(value, 10)
        except ValueError:
            return None


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
        self._inferior_pid: int | None = None
        self._inferior_exit_code: int | None = None
        self._inferior_terminal_reason: str | None = None
        self._inferior_signal: str | None = None
        self._inferior_active = False
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

    def lifecycle(self) -> DebuggerLifecycle:
        self._drain_events()
        proxy_process = self.proxy.process
        mi = self._mi
        return DebuggerLifecycle(
            proxy_pid=proxy_process.pid if proxy_process is not None else None,
            proxy_exit_code=proxy_process.poll() if proxy_process is not None else None,
            gdb_pid=mi.pid if mi is not None else None,
            gdb_exit_code=mi.returncode if mi is not None else None,
            inferior_pid=self._inferior_pid,
            inferior_exit_code=self._inferior_exit_code,
            inferior_terminal_reason=self._inferior_terminal_reason,
            inferior_signal=self._inferior_signal,
            inferior_active=self._inferior_active,
        )

    def continue_inferior(self) -> None:
        self._command("-exec-continue --all")

    def set_breakpoint(self, address: int, condition: str | None = None) -> str:
        mi = self._require_mi()
        # A conditional breakpoint is the difference between observing a hot helper and
        # drowning in it: the interesting call is usually one in hundreds.
        prefix = f"-break-insert -c {json.dumps(condition)} " if condition else "-break-insert "
        result = self._call(mi.command(f"{prefix}*0x{address:08x}"), 32)
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

    def read_memory(self, address: int, length: int, timeout: float = 30.0) -> bytes:
        """Read one contiguous inferior-memory range through GDB/MI."""
        if length < 0:
            raise ValueError("memory read length must be non-negative")
        if length == 0:
            return b""
        mi = self._require_mi()
        result = self._call(
            mi.command(f"-data-read-memory-bytes 0x{address:08x} {length}", timeout),
            timeout + 2,
        )
        payload = result.result.payload
        memory = payload.get("memory") if isinstance(payload, dict) else None
        if not isinstance(memory, list) or len(memory) != 1:
            raise DebuggerTransportError(
                f"GDB returned no contiguous memory block at 0x{address:08x}: "
                f"{result.result.raw}"
            )
        block = memory[0]
        contents = block.get("contents") if isinstance(block, dict) else None
        if not isinstance(contents, str):
            raise DebuggerTransportError(
                f"GDB returned no memory contents at 0x{address:08x}: {result.result.raw}"
            )
        try:
            data = bytes.fromhex(contents)
        except ValueError as error:
            raise DebuggerTransportError(
                f"GDB returned invalid memory contents at 0x{address:08x}: {contents!r}"
            ) from error
        if len(data) != length:
            raise DebuggerTransportError(
                f"GDB returned {len(data)} bytes at 0x{address:08x}, expected {length}"
            )
        return data

    def write_memory(self, address: int, data: bytes, timeout: float = 30.0) -> None:
        """Write one contiguous inferior-memory range through GDB/MI."""
        if not data:
            return
        self._command(
            f"-data-write-memory-bytes 0x{address:08x} {data.hex()}", timeout=timeout
        )

    def consume_runtime_invariant(self) -> str | None:
        value = self.evaluate("$imperialism_runtime_invariant")
        try:
            code = int(value, 0)
        except ValueError:
            return None
        if code == 0:
            return None
        self.assign("$imperialism_runtime_invariant", 0)
        return RUNTIME_INVARIANTS.get(code, f"unknown_{code}")

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
            linker_map = LinkerMap.read(map_path)
            symbol = linker_map.find_decorated("_g_runtimeDebugRecord")
            if symbol is not None:
                try:
                    arguments = [f"0x{symbol.address:08x}"]
                    sim_mgr_symbol = linker_map.find_decorated("_g_pSimMgr")
                    arguments.append(
                        f"0x{sim_mgr_symbol.address:08x}"
                        if sim_mgr_symbol is not None
                        else "0"
                    )
                    nation_aux_symbol = linker_map.find_decorated(
                        "_g_apNationAuxRuntimeStateSlots"
                    )
                    if nation_aux_symbol is None:
                        secondary_symbol = linker_map.find_decorated(
                            "_g_apSecondaryNationStateSlots"
                        )
                        nation_aux_address = (
                            secondary_symbol.address + 7 * 4
                            if secondary_symbol is not None
                            else 0
                        )
                    else:
                        nation_aux_address = nation_aux_symbol.address
                    arguments.append(f"0x{nation_aux_address:08x}")
                    self._console(
                        f'imperialism-runtime-snapshot "{snapshot_path}" '
                        + " ".join(arguments)
                    )
                except DebuggerTransportError:
                    pass
        sections = [("stop", [event.raw])]
        for heading, command in (
            ("all threads", "thread apply all bt full"),
            ("registers", "info registers"),
            ("modules", "info sharedlibrary"),
            ("near pc", "x/32i $pc-32"),
            ("eax pointee", "x/32bx $eax"),
            ("ebx pointee", "x/32bx $ebx"),
            ("ecx pointee", "x/32bx $ecx"),
            ("edx pointee", "x/32bx $edx"),
            ("esi pointee", "x/64bx $esi"),
            ("edi pointee", "x/64bx $edi"),
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

    def terminate_inferior(self) -> None:
        if not self._inferior_active:
            return
        try:
            self._console("kill", timeout=10)
        except DebuggerTransportError:
            pass
        self._drain_events()

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
            if is_terminal_stop(event):
                self._inferior_active = False
                self._inferior_terminal_reason = event.reason
                self._inferior_signal = event.signal_name
                payload = record.payload if isinstance(record.payload, dict) else {}
                self._inferior_exit_code = _parse_exit_code(payload.get("exit-code"))
            self._stops.append(event)
        elif record.record_type == "notify" and isinstance(record.payload, dict):
            if record.message == "thread-group-started":
                self._inferior_pid = _parse_exit_code(record.payload.get("pid"))
                self._inferior_active = True
            elif record.message == "thread-group-exited":
                self._inferior_active = False
                self._inferior_terminal_reason = "thread-group-exited"
                self._inferior_exit_code = _parse_exit_code(record.payload.get("exit-code"))
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
