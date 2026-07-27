"""Narrow direct-Wine and GDB transport boundary for runtime sessions."""

from __future__ import annotations

import os

from dataclasses import dataclass, replace
from pathlib import Path
import subprocess
from typing import Protocol

from tools.runtime.classification import classify_exit, classify_inferior_exit
from tools.runtime.debug.session import DebuggerTransportError, GdbSession, is_terminal_stop


@dataclass(frozen=True)
class TransportSnapshot:
    terminal: bool = False
    classification: str | None = None
    proxy_pid: int | None = None
    proxy_exit_code: int | None = None
    gdb_pid: int | None = None
    gdb_exit_code: int | None = None
    inferior_pid: int | None = None
    inferior_exit_code: int | None = None
    inferior_terminal_reason: str | None = None
    inferior_signal: str | None = None
    debugger_error: str | None = None
    debugger_invariant: str | None = None
    debugger_signal: str | None = None


class RuntimeTransport(Protocol):
    debugger_name: str

    @property
    def stop_count(self) -> int: ...

    @property
    def snapshot(self) -> TransportSnapshot: ...

    def start(self) -> TransportSnapshot: ...

    def poll(self, result_exists: bool) -> TransportSnapshot: ...

    def stop(self, classification: str) -> TransportSnapshot: ...

    def close(self) -> None: ...


class DirectWineTransport:
    debugger_name = "none"

    def __init__(
        self,
        executable: Path,
        cwd: Path,
        environment: dict[str, str],
        artifact_dir: Path,
        wine_log_name: str,
        process_factory=subprocess.Popen,
    ) -> None:
        self.executable = executable
        self.cwd = cwd
        self.environment = environment
        self.artifact_dir = artifact_dir
        self.wine_log_name = wine_log_name
        self.process_factory = process_factory
        self.process: subprocess.Popen[bytes] | None = None
        self._log = None
        self._snapshot = TransportSnapshot()

    @property
    def stop_count(self) -> int:
        return 0

    @property
    def snapshot(self) -> TransportSnapshot:
        return self._snapshot

    def start(self) -> TransportSnapshot:
        self._log = (self.artifact_dir / self.wine_log_name).open("wb")
        self.process = self.process_factory(
            ["wine", str(self.executable)],
            cwd=self.cwd,
            env=self.environment,
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )
        self._snapshot = replace(self._snapshot, inferior_pid=self.process.pid)
        return self._snapshot

    def poll(self, result_exists: bool) -> TransportSnapshot:
        if self.process is None:
            return self._snapshot
        returncode = self.process.poll()
        if returncode is None:
            return self._snapshot
        self._snapshot = replace(
            self._snapshot,
            terminal=True,
            classification=classify_exit(returncode, result_exists),
            inferior_exit_code=returncode,
            inferior_terminal_reason="process-exited",
        )
        return self._snapshot

    def stop(self, classification: str) -> TransportSnapshot:
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=30)
        returncode = self.process.returncode if self.process is not None else None
        self._snapshot = replace(
            self._snapshot,
            terminal=True,
            classification=classification,
            inferior_exit_code=returncode,
            inferior_terminal_reason="host-terminated",
        )
        return self._snapshot

    def close(self) -> None:
        if self._log is not None:
            self._log.close()
            self._log = None


WATCH_ENV = "IMPERIALISM_RUNTIME_GDB_WATCH"


def watch_addresses(raw: str | None = None) -> list[tuple[int, str | None]]:
    """Extra breakpoints for an investigation, from $IMPERIALISM_RUNTIME_GDB_WATCH.

    Recomp addresses, each optionally carrying a gdb condition after a colon:

        IMPERIALISM_RUNTIME_GDB_WATCH='0x4013d9:$eax == 0;0x4013d7'

    Entries are separated by `;` (not whitespace) so a condition may contain spaces.

    Each hit is captured like any other stop -- registers, stack, `x/32i $pc-32`,
    symbolized against the linker map -- and the run continues, so a scenario can be
    driven to a specific decision point without hand-building a gdb session around it.
    The condition matters: an unconditional breakpoint on a hot helper is captured once
    (identical stops are deduped) and then just slows the run down, while a condition
    puts the stop exactly on the call that misbehaves. Unparsable entries are ignored
    rather than failing a run that was only meant to be observed.
    """
    text = os.environ.get(WATCH_ENV, "") if raw is None else raw
    out: list[tuple[int, str | None]] = []
    for token in text.split(";"):
        token = token.strip()
        if not token:
            continue
        address_text, _, condition = token.partition(":")
        try:
            address = int(address_text, 16) if address_text.lower().startswith("0x") else int(address_text, 0)
        except ValueError:
            continue
        out.append((address, condition or None))
    return out


class GdbTransport:
    debugger_name = "gdb"

    def __init__(
        self,
        executable: Path,
        cwd: Path,
        environment: dict[str, str],
        artifact_dir: Path,
        _wine_log_name: str,
        session_factory=GdbSession,
    ) -> None:
        self.session = session_factory(executable, cwd, environment, artifact_dir)
        self._snapshot = TransportSnapshot()
        self._captured_stops: set[str] = set()

    @property
    def stop_count(self) -> int:
        return self.session.stop_count

    @property
    def snapshot(self) -> TransportSnapshot:
        return self._snapshot

    def _lifecycle_snapshot(self) -> TransportSnapshot:
        lifecycle = self.session.lifecycle()
        return replace(
            self._snapshot,
            proxy_pid=lifecycle.proxy_pid,
            proxy_exit_code=lifecycle.proxy_exit_code,
            gdb_pid=lifecycle.gdb_pid,
            gdb_exit_code=lifecycle.gdb_exit_code,
            inferior_pid=lifecycle.inferior_pid,
            inferior_exit_code=lifecycle.inferior_exit_code,
            inferior_terminal_reason=lifecycle.inferior_terminal_reason,
            inferior_signal=lifecycle.inferior_signal,
        )

    def _transport_failure(self, error: Exception | str) -> TransportSnapshot:
        self._snapshot = replace(
            self._snapshot,
            terminal=True,
            classification="debugger_transport_failure",
            debugger_error=str(error),
        )
        return self._snapshot

    def start(self) -> TransportSnapshot:
        try:
            watches = watch_addresses()
            if watches:
                # -break-insert is refused once the inferior is running, so a watched run
                # holds the auto-continue until the breakpoints are in. An unwatched run
                # is left byte-identical to before, kwarg included.
                self.session.start(auto_continue=False)
                for address, condition in watches:
                    self.session.set_breakpoint(address, condition)
                self.session.continue_inferior()
            else:
                self.session.start()
            self._snapshot = self._lifecycle_snapshot()
            return self._snapshot
        except DebuggerTransportError as error:
            return self._transport_failure(error)

    def poll(self, result_exists: bool) -> TransportSnapshot:
        try:
            stop = self.session.poll_stop()
            while stop is not None:
                if is_terminal_stop(stop):
                    break
                invariant = self.session.consume_runtime_invariant()
                if invariant is not None:
                    label = "invariant-" + invariant.replace("_", "-")
                    self.session.capture_stop(label, stop)
                    self._captured_stops.add(stop.raw)
                    self._snapshot = replace(
                        self._lifecycle_snapshot(),
                        terminal=True,
                        classification="runtime_invariant_violation",
                        debugger_invariant=invariant,
                    )
                    return self._snapshot
                if stop.signal_name not in {None, "SIGTRAP"}:
                    self._snapshot = replace(
                        self._snapshot, debugger_signal=stop.signal_name
                    )
                if stop.raw not in self._captured_stops:
                    label = (stop.signal_name or stop.reason).lower().replace("_", "-")
                    self.session.capture_stop(label, stop)
                    self._captured_stops.add(stop.raw)
                self.session.continue_inferior()
                stop = self.session.poll_stop()
            self._snapshot = self._lifecycle_snapshot()
        except DebuggerTransportError as error:
            return self._transport_failure(error)

        if self._snapshot.inferior_terminal_reason is not None:
            self._snapshot = replace(
                self._snapshot,
                terminal=True,
                classification=classify_inferior_exit(
                    self._snapshot.inferior_terminal_reason,
                    self._snapshot.inferior_exit_code,
                    self._snapshot.inferior_signal,
                    result_exists,
                ),
            )
        elif self._snapshot.proxy_exit_code is not None or self._snapshot.gdb_exit_code is not None:
            self._snapshot = replace(
                self._snapshot,
                terminal=True,
                classification="debugger_transport_failure",
                debugger_error=(
                    "debugger transport exited while inferior was active: "
                    f"proxy={self._snapshot.proxy_exit_code}, "
                    f"gdb={self._snapshot.gdb_exit_code}"
                ),
            )
        return self._snapshot

    def stop(self, classification: str) -> TransportSnapshot:
        if classification == "runtime_invariant_violation":
            self.session.terminate_inferior()
            return self._snapshot
        try:
            _, stop = self.session.interrupt_and_capture(classification)
            if stop is not None and stop.signal_name not in {None, "SIGINT", "SIGTRAP"}:
                classification = "crash"
                self._snapshot = replace(
                    self._snapshot, debugger_signal=stop.signal_name
                )
        except DebuggerTransportError as error:
            self._snapshot = replace(self._snapshot, debugger_error=str(error))
        self.session.terminate_inferior()
        self._snapshot = replace(
            self._lifecycle_snapshot(), terminal=True, classification=classification
        )
        return self._snapshot

    def close(self) -> None:
        try:
            self._snapshot = self._lifecycle_snapshot()
        except DebuggerTransportError:
            pass
        self.session.close()


def create_transport(
    use_gdb: bool,
    executable: Path,
    cwd: Path,
    environment: dict[str, str],
    artifact_dir: Path,
    wine_log_name: str,
) -> RuntimeTransport:
    transport_type = GdbTransport if use_gdb else DirectWineTransport
    return transport_type(
        executable, cwd, environment, artifact_dir, wine_log_name
    )
