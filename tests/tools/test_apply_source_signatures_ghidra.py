"""Live-Ghidra smoke test for the projector's transactional safety primitive.

The apply path's correctness rests on one Ghidra property: an aborted
transaction (`endTransaction(id, False)`) restores the program EXACTLY, so a
projection classified "reverted" is byte-for-byte its prior self. The two prior
tooling failures in this area (the unsound `addParameter` fixer, and the manual
`_restore` that ignored custom storage) were both "the restore didn't restore".
This test exercises the rollback primitive directly against the real DB.

Skipped unless a Ghidra environment is available (so the pure-Python
`just test` suite ignores it); run it where GHIDRA_INSTALL_DIR + the vendored
project are present, e.g. in the DB-tooling CI lane.
"""

import os
import unittest


def _ghidra_available() -> bool:
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        return False
    try:
        import pyghidra  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


@unittest.skipUnless(_ghidra_available(), "requires GHIDRA_INSTALL_DIR + pyghidra")
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


if __name__ == "__main__":
    unittest.main()
