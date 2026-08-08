"""Live-Ghidra smoke test for the projector's transactional safety primitive.

The apply path's correctness rests on one Ghidra property: an aborted
transaction (`endTransaction(id, False)`) restores the program EXACTLY, so a
projection classified "reverted" is byte-for-byte its prior self. The two prior
tooling failures in this area (the unsound `addParameter` fixer, and the manual
`_restore` that ignored custom storage) were both "the restore didn't restore".
This test exercises the rollback primitive directly against the real DB.

Skipped unless explicitly enabled with `IMPERIALISM_RUN_GHIDRA_TESTS=1` and a
Ghidra environment is available. This keeps ordinary unit-test runs independent
of whether the developer happens to have a live project configured.
"""

import os
import unittest


def _ghidra_available() -> bool:
    if os.environ.get("IMPERIALISM_RUN_GHIDRA_TESTS") != "1":
        return False
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        return False
    try:
        import pyghidra  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


@unittest.skipUnless(
    _ghidra_available(),
    "requires IMPERIALISM_RUN_GHIDRA_TESTS=1, GHIDRA_INSTALL_DIR, and pyghidra",
)
class TransactionRollbackSmokeTest(unittest.TestCase):
    def test_aborted_transaction_restores_signature_exactly(self):
        import pyghidra
        pyghidra.start()
        from tools.common import ghidra_env
        from ghidra.program.model.symbol import SourceType

        project = ghidra_env.open_project()
        consumer = program = None
        try:
            consumer, program = ghidra_env.open_program(project, writable=True)
            fm = program.getFunctionManager()
            # Pick the first ordinary (non-external, non-thunk) function.
            fn = None
            it = fm.getFunctions(True)
            while it.hasNext():
                cand = it.next()
                if not cand.isExternal() and not cand.isThunk():
                    fn = cand
                    break
            self.assertIsNotNone(fn, "no ordinary function in the DB")

            def snapshot():
                ps = tuple(
                    (p.getName(), p.getDataType().getName(),
                     p.getVariableStorage().toString())
                    for p in fn.getParameters())
                return (fn.getCallingConventionName(), fn.getReturnType().getName(),
                        fn.hasCustomVariableStorage(), fn.getStackPurgeSize(), ps)

            original = snapshot()
            # Mutate inside a transaction, then ABORT — the DB must roll back exactly.
            other_cc = "__cdecl" if original[0] != "__cdecl" else "__stdcall"
            tx = program.startTransaction("smoke: mutate then abort")
            mutated = None
            try:
                fn.setCallingConvention(other_cc)
                mutated = fn.getCallingConventionName()
            finally:
                program.endTransaction(tx, False)  # abort => rollback

            self.assertEqual(mutated, other_cc, "the in-transaction mutation took effect")
            self.assertEqual(snapshot(), original,
                             "aborted transaction did NOT restore the signature exactly")

            # And a committed transaction DOES persist — then abort-restore for cleanup.
            tx2 = program.startTransaction("smoke: mutate and commit")
            try:
                fn.setCallingConvention(other_cc)
            finally:
                program.endTransaction(tx2, True)  # commit
            self.assertEqual(fn.getCallingConventionName(), other_cc,
                             "committed transaction should persist the change")
            tx3 = program.startTransaction("smoke: restore original cc")
            try:
                fn.setCallingConvention(original[0])
            finally:
                program.endTransaction(tx3, True)
            self.assertEqual(snapshot(), original)
        finally:
            if program is not None:
                program.release(consumer)
            project.close()


@unittest.skipUnless(
    _ghidra_available(),
    "requires IMPERIALISM_RUN_GHIDRA_TESTS=1, GHIDRA_INSTALL_DIR, and pyghidra",
)
class DecompilerCacheFlushAfterRollbackTest(unittest.TestCase):
    """Regression test for the Task-4 fix: `run`/`run_divergent`/`run_packed` each
    call `ifc.flushCache()` right after `endTransaction`, so a rolled-back mutation
    can't leave stale post-mutation decompile results for the NEXT candidate to read
    off the same `DecompInterface`. Exercises the exact sequence those functions use:
    mutate in a transaction, decompile (forcing the cache to serve the mutated
    state), abort the transaction, flush, then decompile again and confirm the
    re-decompiled signature matches the ORIGINAL (rolled-back) DB state, not the
    since-reverted in-transaction one.
    """

    def test_decompile_after_rollback_and_flush_reflects_original_signature(self):
        import pyghidra
        pyghidra.start()
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from tools.common import ghidra_env

        project = ghidra_env.open_project()
        consumer = program = None
        try:
            consumer, program = ghidra_env.open_program(project, writable=True)
            fm = program.getFunctionManager()
            fn = None
            it = fm.getFunctions(True)
            while it.hasNext():
                cand = it.next()
                if not cand.isExternal() and not cand.isThunk():
                    fn = cand
                    break
            self.assertIsNotNone(fn, "no ordinary function in the DB")

            ifc = DecompInterface()
            ifc.setOptions(DecompileOptions())
            ifc.setSimplificationStyle("decompile")
            ifc.openProgram(program)
            monitor = pyghidra.task_monitor()

            original_cc = fn.getCallingConventionName()
            other_cc = "__cdecl" if original_cc != "__cdecl" else "__stdcall"

            tx = program.startTransaction("flush-after-rollback test: mutate")
            try:
                fn.setCallingConvention(other_cc)
                ifc.flushCache()
                res_mutated = ifc.decompileFunction(fn, 20, monitor)
                self.assertTrue(res_mutated.decompileCompleted())
            finally:
                program.endTransaction(tx, False)  # abort => rollback
                ifc.flushCache()  # the fix under test

            self.assertEqual(fn.getCallingConventionName(), original_cc,
                             "transaction did not roll back")
            res_after = ifc.decompileFunction(fn, 20, monitor)
            self.assertTrue(res_after.decompileCompleted())
            self.assertEqual(
                res_after.getFunction().getSignature().getCallingConventionName(),
                original_cc,
                "post-rollback decompile served a stale (mutated) signature — "
                "flushCache() after endTransaction did not clear it",
            )
        finally:
            if program is not None:
                program.release(consumer)
            project.close()


@unittest.skipUnless(
    _ghidra_available(),
    "requires IMPERIALISM_RUN_GHIDRA_TESTS=1, GHIDRA_INSTALL_DIR, and pyghidra",
)
class TypeResolverLiveTest(unittest.TestCase):
    """Live-DB coverage for the two Task-3 fixes to `TypeResolver`: project-local
    scalar typedefs (nation_domain_types.h) are invisible to Ghidra without
    `_SCALAR_TYPEDEF_ALIASES`, and CDataExchange/CView's real MFC layout
    (added via apply_mfc_datatypes.py) exposed a pre-existing `/Demangler/CView`
    stub that `select_named_datatype`'s stub exclusion must resolve past."""

    def test_project_scalar_typedef_resolves_to_its_primitive(self):
        import pyghidra
        pyghidra.start()
        from tools.common import ghidra_env
        from tools.ghidra.apply_source_signatures import TypeResolver

        project = ghidra_env.open_project()
        consumer = program = None
        try:
            consumer, program = ghidra_env.open_program(project, writable=False)
            resolver = TypeResolver(program)
            dt, quality = resolver.resolve_quality("NationSlot")
            self.assertEqual(quality, "canonical_alias")
            self.assertIsNotNone(dt)
            self.assertEqual(dt.getLength(), 2)  # short
        finally:
            if program is not None:
                program.release(consumer)
            project.close()

    def test_cview_resolves_unambiguously_despite_demangler_stub(self):
        import pyghidra
        pyghidra.start()
        from tools.common import ghidra_env
        from tools.ghidra.apply_source_signatures import TypeResolver

        project = ghidra_env.open_project()
        consumer = program = None
        try:
            consumer, program = ghidra_env.open_program(project, writable=False)
            dtm = program.getDataTypeManager()
            matches = [dt for dt in dtm.getAllDataTypes() if dt.getName() == "CView"]
            if not matches or not any(str(m.getCategoryPath()) == "/Demangler" for m in matches):
                self.skipTest("no /Demangler/CView stub present in this DB snapshot")
            resolver = TypeResolver(program)
            dt, quality = resolver.resolve_quality("CView*")
            self.assertNotEqual(quality, "ambiguous_simple_name")
            self.assertIsNotNone(dt)
        finally:
            if program is not None:
                program.release(consumer)
            project.close()


if __name__ == "__main__":
    unittest.main()
