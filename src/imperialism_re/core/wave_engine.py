from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from imperialism_re.core.typing_utils import parse_hex
from imperialism_re.core.wave_shared import (
    build_data_type,
    ensure_unique_name,
    parse_params,
    sanitize_symbol_name,
    single_jmp_to_target,
)


@dataclass(frozen=True)
class WaveApplyConfig:
    apply: bool
    create_missing: bool
    auto_thunk_mirrors: bool
    transaction_label: str
    save_message: str


@dataclass(frozen=True)
class WaveApplyResult:
    rename_ok: int
    rename_skip: int
    rename_fail: int
    rename_comments: int
    created_functions: int
    sig_ok: int
    sig_skip: int
    sig_fail: int
    thunk_sig_ok: int
    thunk_sig_skip: int
    thunk_sig_fail: int
    auto_thunk_rows: list[dict[str, str]]


def apply_wave_rows(
    program,
    *,
    rename_rows: Sequence[Mapping[str, str]],
    sig_rows: Sequence[Mapping[str, str]],
    thunk_sig_rows: Sequence[Mapping[str, str]],
    config: WaveApplyConfig,
) -> WaveApplyResult:
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.program.model.listing import Function, ParameterImpl
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()
    listing = program.getListing()
    dtm = program.getDataTypeManager()
    monitor = ConsoleTaskMonitor()

    existing_function_names: set[str] = set()
    fit_names = fm.getFunctions(True)
    while fit_names.hasNext():
        existing_function_names.add(fit_names.next().getName())

    rename_ok = rename_skip = rename_fail = rename_comments = created_functions = 0
    sig_ok = sig_skip = sig_fail = 0
    thunk_sig_ok = thunk_sig_skip = thunk_sig_fail = 0
    auto_thunk_rows: list[dict[str, str]] = []
    auto_thunk_sig_map: dict[int, int] = {}

    tx = None
    if config.apply:
        tx = program.startTransaction(config.transaction_label)
    try:
        for row in rename_rows:
            addr_txt = (row.get("address") or "").strip()
            new_name = (row.get("new_name") or "").strip()
            comment = (row.get("comment") or "").strip()
            if not addr_txt or not new_name:
                rename_fail += 1
                continue
            try:
                addr_int = parse_hex(addr_txt)
            except Exception:
                rename_fail += 1
                continue

            addr = af.getAddress(f"0x{addr_int:08x}")
            func = fm.getFunctionAt(addr)
            if func is None and config.create_missing and config.apply:
                try:
                    DisassembleCommand(addr, None, True).applyTo(program, monitor)
                    CreateFunctionCmd(None, addr, None, SourceType.USER_DEFINED).applyTo(
                        program, monitor
                    )
                    func = fm.getFunctionAt(addr)
                    if func is not None:
                        created_functions += 1
                except Exception:
                    pass
            if func is None:
                rename_fail += 1
                continue

            if config.apply:
                if func.getName() == new_name:
                    rename_skip += 1
                else:
                    try:
                        func.setName(new_name, SourceType.USER_DEFINED)
                        rename_ok += 1
                    except Exception:
                        rename_fail += 1
                        continue
                if comment:
                    try:
                        func.setComment(comment)
                        rename_comments += 1
                    except Exception:
                        pass
            else:
                print(f"[plan-rename] 0x{addr_int:08x} {func.getName()} -> {new_name}")

        if config.auto_thunk_mirrors:
            for row in rename_rows:
                addr_txt = (row.get("address") or "").strip()
                core_name = (row.get("new_name") or "").strip()
                if not addr_txt or not core_name:
                    continue
                try:
                    core_int = parse_hex(addr_txt)
                except Exception:
                    continue
                core_addr = af.getAddress(f"0x{core_int:08x}")

                for ref in rm.getReferencesTo(core_addr):
                    src = fm.getFunctionContaining(ref.getFromAddress())
                    if src is None:
                        continue
                    if src.getEntryPoint() != ref.getFromAddress():
                        continue
                    src_addr = src.getEntryPoint().getOffset() & 0xFFFFFFFF
                    if src_addr == core_int:
                        continue
                    if not single_jmp_to_target(listing, src, core_addr):
                        continue

                    old_name = src.getName()
                    if not (
                        old_name.startswith("thunk_")
                        or old_name.startswith("Cluster_")
                        or old_name.startswith("FUN_")
                    ):
                        continue

                    desired = f"thunk_{sanitize_symbol_name(core_name)}"
                    chosen = ensure_unique_name(existing_function_names, desired, src_addr)
                    auto_thunk_rows.append(
                        {
                            "address": f"0x{src_addr:08x}",
                            "old_name": old_name,
                            "new_name": chosen,
                            "target_addr": f"0x{core_int:08x}",
                            "target_name": core_name,
                        }
                    )
                    auto_thunk_sig_map[src_addr] = core_int
                    if config.apply and old_name != chosen:
                        try:
                            src.setName(chosen, SourceType.USER_DEFINED)
                            existing_function_names.add(chosen)
                        except Exception:
                            pass

            seen_auto = set()
            deduped: list[dict[str, str]] = []
            for row in auto_thunk_rows:
                addr_txt = row["address"]
                if addr_txt in seen_auto:
                    continue
                seen_auto.add(addr_txt)
                deduped.append(row)
            auto_thunk_rows = deduped

        for i, row in enumerate(sig_rows, start=1):
            addr_txt = (row.get("address") or "").strip()
            ret_txt = (row.get("return_type") or "").strip()
            cc_txt = (row.get("calling_convention") or "").strip()
            params_txt = row.get("params") or ""
            if not addr_txt or not ret_txt:
                sig_fail += 1
                print(f"[sig-row-fail] row={i} missing address/return_type")
                continue
            try:
                addr_int = parse_hex(addr_txt)
                ret_dt = build_data_type(ret_txt, dtm)
                params = parse_params(params_txt)
            except Exception as ex:
                sig_fail += 1
                print(f"[sig-row-fail] row={i} addr={addr_txt} err={ex}")
                continue

            func = fm.getFunctionAt(af.getAddress(f"0x{addr_int:08x}"))
            if func is None:
                sig_fail += 1
                continue
            if not config.apply:
                ptxt = ", ".join(f"{n}:{t}" for n, t in params) if params else "<none>"
                print(
                    f"[plan-signature] 0x{addr_int:08x} {func.getName()} "
                    f"cc={cc_txt or '<unchanged>'} ret={ret_txt} params={ptxt}"
                )
                continue

            try:
                old_sig = str(func.getSignature())
                if cc_txt:
                    func.setCallingConvention(cc_txt)
                p_objs = [
                    ParameterImpl(nm, build_data_type(tp, dtm), program, SourceType.USER_DEFINED)
                    for nm, tp in params
                ]
                func.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    p_objs,
                )
                func.setReturnType(ret_dt, SourceType.USER_DEFINED)
                if str(func.getSignature()) == old_sig:
                    sig_skip += 1
                else:
                    sig_ok += 1
            except Exception:
                sig_fail += 1

        merged_tsig: dict[int, int] = {}
        for row in thunk_sig_rows:
            src_txt = (row.get("address") or "").strip()
            dst_txt = (row.get("target_addr") or "").strip()
            if not src_txt or not dst_txt:
                continue
            try:
                merged_tsig[parse_hex(src_txt)] = parse_hex(dst_txt)
            except Exception:
                continue
        for src_addr, dst_addr in auto_thunk_sig_map.items():
            merged_tsig.setdefault(src_addr, dst_addr)

        for src_int, dst_int in sorted(merged_tsig.items()):
            src = fm.getFunctionAt(af.getAddress(f"0x{src_int:08x}"))
            dst = fm.getFunctionAt(af.getAddress(f"0x{dst_int:08x}"))
            if src is None or dst is None:
                thunk_sig_fail += 1
                continue
            if not src.getName().startswith("thunk_"):
                thunk_sig_skip += 1
                continue
            if not config.apply:
                print(
                    f"[plan-thunk-sig] 0x{src_int:08x} {src.getName()} <= "
                    f"0x{dst_int:08x} {dst.getName()}"
                )
                continue

            try:
                old_sig = str(src.getSignature())
                cc = dst.getCallingConventionName()
                if cc:
                    src.setCallingConvention(cc)
                params = []
                dst_params = dst.getParameters()
                for i in range(len(dst_params)):
                    p = dst_params[i]
                    nm = p.getName() or f"param_{i+1}"
                    params.append(
                        ParameterImpl(nm, p.getDataType(), program, SourceType.USER_DEFINED)
                    )
                src.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    params,
                )
                src.setReturnType(dst.getReturnType(), SourceType.USER_DEFINED)
                if str(src.getSignature()) == old_sig:
                    thunk_sig_skip += 1
                else:
                    thunk_sig_ok += 1
            except Exception:
                thunk_sig_fail += 1
    finally:
        if tx is not None:
            program.endTransaction(tx, config.apply)

    if config.apply:
        program.save(config.save_message, None)

    return WaveApplyResult(
        rename_ok=rename_ok,
        rename_skip=rename_skip,
        rename_fail=rename_fail,
        rename_comments=rename_comments,
        created_functions=created_functions,
        sig_ok=sig_ok,
        sig_skip=sig_skip,
        sig_fail=sig_fail,
        thunk_sig_ok=thunk_sig_ok,
        thunk_sig_skip=thunk_sig_skip,
        thunk_sig_fail=thunk_sig_fail,
        auto_thunk_rows=auto_thunk_rows,
    )
