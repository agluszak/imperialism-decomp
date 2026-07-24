"""Imperialism-specific commands loaded into GDB's embedded Python."""

import json
import pathlib
import struct

import gdb


RUNTIME_FIELDS = (
    "reason",
    "elapsedMs",
    "testName",
    "phase",
    "lastAction",
    "turnEvent",
    "modalDepth",
    "mainView",
    "activeModal",
    "simMgr",
    "exceptionPointers",
)


RUNTIME_FORMAT = "<IIIIIiiIIII"


def _read_string(inferior, address):
    if not address:
        return None
    result = bytearray()
    try:
        for offset in range(0, 1024, 64):
            chunk = bytes(inferior.read_memory(address + offset, 64))
            terminator = chunk.find(b"\0")
            if terminator >= 0:
                result.extend(chunk[:terminator])
                break
            result.extend(chunk)
    except gdb.MemoryError:
        return None
    return result.decode("latin-1", errors="replace")


def _pointer(inferior, address, include_string=False):
    result = {"address": "0x%08x" % address}
    if include_string:
        value = _read_string(inferior, address)
        if value is not None:
            result["string"] = value
    return result


def capture_runtime_snapshot(address):
    snapshot = {"schema": "imperialism.runtime-debug.v1"}
    inferior = gdb.selected_inferior()
    try:
        values = struct.unpack(
            RUNTIME_FORMAT,
            bytes(inferior.read_memory(address, struct.calcsize(RUNTIME_FORMAT))),
        )
        runtime = dict(zip(RUNTIME_FIELDS, values))
        for name in ("testName", "phase", "lastAction"):
            runtime[name] = _pointer(inferior, runtime[name], include_string=True)
        for name in ("mainView", "activeModal", "simMgr", "exceptionPointers"):
            runtime[name] = _pointer(inferior, runtime[name])
        snapshot["runtime"] = runtime
        snapshot["runtime_record_address"] = "0x%08x" % address
    except (gdb.MemoryError, struct.error) as error:
        snapshot["runtime_error"] = str(error)
    thread = gdb.selected_thread()
    if thread is not None:
        snapshot["selected_thread"] = {
            "global_num": thread.global_num,
            "name": thread.name,
        }
    return snapshot


class RuntimeSnapshotCommand(gdb.Command):
    def __init__(self):
        super().__init__("imperialism-runtime-snapshot", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        del from_tty
        arguments = gdb.string_to_argv(argument)
        if len(arguments) != 2:
            raise gdb.GdbError(
                "usage: imperialism-runtime-snapshot OUTPUT.json RECORD_ADDRESS"
            )
        output = pathlib.Path(arguments[0])
        try:
            address = int(arguments[1], 0)
        except ValueError as error:
            raise gdb.GdbError("invalid runtime-record address") from error
        output.write_text(
            json.dumps(capture_runtime_snapshot(address), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )


RuntimeSnapshotCommand()
