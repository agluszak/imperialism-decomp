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


def _read_u32(inferior, address):
    return struct.unpack("<I", bytes(inferior.read_memory(address, 4)))[0]


def _object_pointer(inferior, address, slots=()):
    result = _pointer(inferior, address)
    if not address:
        return result
    try:
        vtable = _read_u32(inferior, address)
        result["vtable"] = "0x%08x" % vtable
        if slots:
            result["virtuals"] = {
                "0x%02x" % slot: "0x%08x" % _read_u32(inferior, vtable + slot)
                for slot in slots
            }
    except (gdb.MemoryError, struct.error) as error:
        result["memory_error"] = str(error)
    return result


def _global_object_pointer(inferior, address, slots=()):
    result = {"global_address": "0x%08x" % address}
    try:
        value = _read_u32(inferior, address)
        result.update(_object_pointer(inferior, value, slots))
    except (gdb.MemoryError, struct.error) as error:
        result["memory_error"] = str(error)
    return result


def _pointer_array(inferior, address, count):
    result = {"address": "0x%08x" % address}
    try:
        values = struct.unpack(
            "<%dI" % count,
            bytes(inferior.read_memory(address, count * 4)),
        )
        result["values"] = ["0x%08x" % value for value in values]
    except (gdb.MemoryError, struct.error) as error:
        result["memory_error"] = str(error)
    return result


def capture_runtime_snapshot(address, sim_mgr_global=0, nation_aux_array=0):
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
    if sim_mgr_global:
        snapshot["sim_mgr"] = _global_object_pointer(
            inferior, sim_mgr_global, slots=(0x44, 0x4C)
        )
    if nation_aux_array:
        snapshot["nation_aux_runtime_state_slots"] = _pointer_array(
            inferior, nation_aux_array, 16
        )
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
        if len(arguments) not in (2, 4):
            raise gdb.GdbError(
                "usage: imperialism-runtime-snapshot OUTPUT.json RECORD_ADDRESS "
                "[SIM_MGR_GLOBAL NATION_AUX_ARRAY]"
            )
        output = pathlib.Path(arguments[0])
        try:
            address = int(arguments[1], 0)
        except ValueError as error:
            raise gdb.GdbError("invalid runtime-record address") from error
        sim_mgr_global = int(arguments[2], 0) if len(arguments) == 4 else 0
        nation_aux_array = int(arguments[3], 0) if len(arguments) == 4 else 0
        output.write_text(
            json.dumps(
                capture_runtime_snapshot(address, sim_mgr_global, nation_aux_array),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


RuntimeSnapshotCommand()


# Enrich the normal runtime snapshot with the objects implicated by an x86
# virtual-call failure.  Keep this outside the command implementation so the
# same structured capture remains useful for assertion traps and interrupts.
_capture_runtime_snapshot_without_registers = capture_runtime_snapshot


def _register_u32(name):
    try:
        return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFF
    except (gdb.error, ValueError):
        return None


def _memory_words(inferior, address, count):
    if address is None or address == 0:
        return []
    try:
        data = bytes(inferior.read_memory(address, count * 4))
    except gdb.MemoryError:
        return []
    return [
        "0x%08x" % struct.unpack_from("<I", data, offset)[0]
        for offset in range(0, len(data), 4)
    ]


def capture_runtime_snapshot(address, sim_mgr_global=0, nation_aux_array=0):
    snapshot = _capture_runtime_snapshot_without_registers(
        address, sim_mgr_global, nation_aux_array
    )
    inferior = gdb.selected_inferior()
    registers = {}
    register_objects = {}
    for name in ("pc", "eax", "ecx", "edx", "ebx", "esi", "edi", "esp", "ebp"):
        value = _register_u32(name)
        registers[name] = None if value is None else "0x%08x" % value
        if name in ("ecx", "edx", "esi", "edi") and value not in (None, 0):
            register_objects[name] = {
                "address": "0x%08x" % value,
                "words": _memory_words(inferior, value, 16),
                "object": _object_pointer(
                    inferior, value, slots=(0x0C, 0x34, 0x48, 0x4C)
                ),
            }
    snapshot["registers"] = registers
    snapshot["register_objects"] = register_objects
    return snapshot


import os


RUNTIME_INVARIANT_STATIONED_MILITARY_UNIT_DESTRUCTOR = 1
RUNTIME_INVARIANT_NATION_STATE_MILITARY_UNIT_OVERWRITE = 2
gdb.set_convenience_variable("imperialism_runtime_invariant", gdb.Value(0))


def _linker_map_symbol_address(mangled_name):
    executable = gdb.current_progspace().filename
    if not executable:
        return None
    map_path = os.path.splitext(executable)[0] + ".map"
    try:
        with open(map_path, "r") as map_file:
            for line in map_file:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == mangled_name:
                    return int(fields[2], 16)
    except (IOError, OSError, ValueError):
        return None
    return None


class StationedMilitaryUnitDestructorBreakpoint(gdb.Breakpoint):
    """Stop before destroying a military unit which is still linked to a province."""

    def stop(self):
        this_pointer = _register_u32("ecx")
        if this_pointer in (None, 0):
            return False
        try:
            tile_bytes = bytes(gdb.selected_inferior().read_memory(this_pointer + 6, 2))
            tile_index = struct.unpack("<h", tile_bytes)[0]
        except gdb.MemoryError:
            return False
        if tile_index == -1:
            return False
        gdb.write(
            "Imperialism runtime invariant: destroying stationed TMilitaryUnit "
            "0x%08x at tile %d\n" % (this_pointer, tile_index)
        )
        gdb.set_convenience_variable(
            "imperialism_runtime_invariant",
            gdb.Value(RUNTIME_INVARIANT_STATIONED_MILITARY_UNIT_DESTRUCTOR),
        )
        return True


_military_unit_destructor = _linker_map_symbol_address("??1TMilitaryUnit@@UAE@XZ")
if (
    os.environ.get("IMPERIALISM_RUNTIME_GDB_INVARIANTS") == "1"
    and _military_unit_destructor is not None
):
    StationedMilitaryUnitDestructorBreakpoint(
        "*0x%08x" % _military_unit_destructor,
        internal=True,
    )


class NationStateMilitaryUnitOverwriteWatchpoint(gdb.Breakpoint):
    """Stop when the primary nation table is overwritten with a military unit."""

    def __init__(self, nation_states_address, military_unit_vtable):
        self._nation_states_address = nation_states_address
        self._military_unit_vtable = military_unit_vtable
        gdb.Breakpoint.__init__(
            self,
            "*(unsigned int *)0x%08x" % nation_states_address,
            type=gdb.BP_WATCHPOINT,
            wp_class=gdb.WP_WRITE,
            internal=True,
        )

    def stop(self):
        nation_state = _read_u32(gdb.selected_inferior(), self._nation_states_address)
        if nation_state in (None, 0):
            return False
        vtable = _read_u32(gdb.selected_inferior(), nation_state)
        if vtable != self._military_unit_vtable:
            return False
        gdb.write(
            "Imperialism runtime invariant: g_apNationStates[0] overwritten "
            "with TMilitaryUnit 0x%08x\n" % nation_state
        )
        gdb.set_convenience_variable(
            "imperialism_runtime_invariant",
            gdb.Value(RUNTIME_INVARIANT_NATION_STATE_MILITARY_UNIT_OVERWRITE),
        )
        return True


_nation_states = _linker_map_symbol_address("_g_apNationStates")
_military_unit_vtable = _linker_map_symbol_address("??_7TMilitaryUnit@@6B@")
if (
    os.environ.get("IMPERIALISM_RUNTIME_GDB_INVARIANTS") == "1"
    and _nation_states is not None
    and _military_unit_vtable is not None
):
    NationStateMilitaryUnitOverwriteWatchpoint(_nation_states, _military_unit_vtable)
