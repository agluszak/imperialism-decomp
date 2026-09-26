"""Address-selected source synchronization cannot mutate unrelated DB entries."""

from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tools.common.vtable_extents import VerifiedVtableExtent
from tools.ghidra import apply_source
from tools.source_model import Claim, SourceModel


class ApplySourceSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        (root / "config").mkdir()
        (root / "config/original_entities.csv").write_text(
            "address|name\n402000|Other::Run\n", encoding="utf-8"
        )
        model = SourceModel(
            target="IMPERIALISM",
            functions={
                0x401000: Claim(0x401000, "FUNCTION", "A.cpp", 1, "Owner::Run"),
                0x402000: Claim(0x402000, "FUNCTION", "B.cpp", 1),
            },
            globals={0x500000: "g_selected", 0x500004: "g_other"},
            vtables={0x600000: "Owner", 0x610000: "Other"},
        )
        self.functions = {address: Mock() for address in (0x401000, 0x402000, 0x400008, 0x402008)}
        for fn in self.functions.values():
            fn.getName.return_value = "old"
        self.interior = Mock()
        self.interior.getName.return_value = "interior"
        self.interior.getSymbolType.return_value.toString.return_value = "Label"
        self.interior.isDynamic.return_value = False
        self.program = Mock()
        self.symbols = self.program.getSymbolTable.return_value
        self.symbols.getPrimarySymbol.return_value = None
        self.symbols.getNamespace.return_value = None
        self.symbols.getSymbols.side_effect = lambda address: (
            [self.interior] if address in (0x600004, 0x600008, 0x610004) else []
        )
        self.manager = self.program.getFunctionManager.return_value
        self.manager.getFunctionAt.side_effect = self.functions.get
        self.manager.getFunctions.return_value = []
        self.program.getDataTypeManager.return_value.getAllDataTypes.return_value = []
        self.space = self.program.getAddressFactory.return_value.getDefaultAddressSpace.return_value
        self.space.getAddress.side_effect = lambda address: address
        modules = {
            name: ModuleType(name) for name in (
                "ghidra", "ghidra.program", "ghidra.program.model",
                "ghidra.program.model.symbol", "ghidra.util", "ghidra.util.exception",
            )
        }
        modules["ghidra.program.model.symbol"].SourceType = SimpleNamespace(USER_DEFINED="user")
        modules["ghidra.util.exception"].DuplicateNameException = ValueError
        modules["ghidra.util.exception"].InvalidInputException = TypeError
        self.stack.enter_context(patch.dict("sys.modules", modules))
        self.stack.enter_context(patch.object(apply_source, "REPO_ROOT", root))
        self.stack.enter_context(patch.object(apply_source, "build_model", return_value=model))
        self.stack.enter_context(patch.object(
            apply_source, "load_verified_vtable_extents", return_value=(
                VerifiedVtableExtent(0x600000, 3, "Owner"),
                VerifiedVtableExtent(0x610000, 2, "Other"),
            ),
        ))
        self.stack.enter_context(patch.object(
            apply_source, "embedded_label_entries",
            return_value=[(0x400008, "SelectedInternal"), (0x402008, "OtherInternal")],
        ))
        self.stack.enter_context(patch.object(apply_source.ghidra_env, "open_project"))
        self.stack.enter_context(patch.object(
            apply_source.ghidra_env, "open_program", return_value=(object(), self.program)
        ))
        self.stack.enter_context(patch.object(apply_source.pyghidra, "task_monitor"))

    def run_apply(self, arguments: list[str]) -> int:
        args = apply_source.parse_args(arguments)
        with patch.object(apply_source, "parse_args", return_value=args), redirect_stdout(io.StringIO()):
            return apply_source.main()

    def touched(self) -> set[int]:
        return {call.args[0] for call in self.space.getAddress.call_args_list}

    def test_exact_selection_covers_names_vtables_and_boundary_repairs(self) -> None:
        selected = {0x401000, 0x500000, 0x600000, 0x600004, 0x400008}
        arguments = ["--apply"]
        for address in sorted(selected):
            arguments.extend(("--address", hex(address)))
        arguments.extend(("--address", "401000"))
        self.assertEqual(self.run_apply(arguments), 0)
        self.assertEqual(self.touched(), selected)
        self.functions[0x401000].setName.assert_called_once_with("Run", "user")
        self.functions[0x402000].setName.assert_not_called()
        self.manager.removeFunction.assert_called_once_with(0x400008)
        self.interior.delete.assert_called_once()
        label_addresses = {call.args[0] for call in self.symbols.createLabel.call_args_list}
        self.assertEqual(label_addresses, {0x500000, 0x600000, 0x400008})
        self.program.save.assert_called_once()

    def test_selecting_vtable_start_does_not_select_its_interior(self) -> None:
        self.assertEqual(self.run_apply(["--apply", "--address", "0x600000"]), 0)
        self.assertEqual(self.touched(), {0x600000})
        self.interior.delete.assert_not_called()
        self.manager.removeFunction.assert_not_called()

    def test_boundary_only_repair_respects_selection(self) -> None:
        self.assertEqual(self.run_apply([
            "--apply", "--demote-embedded-functions-only",
            "--address", "0x400008", "--address", "0x401000",
        ]), 0)
        self.assertEqual(self.touched(), {0x400008})
        self.manager.removeFunction.assert_called_once_with(0x400008)
        self.functions[0x401000].setName.assert_not_called()

    def test_unselected_dry_run_still_covers_the_whole_source_model(self) -> None:
        self.assertEqual(self.run_apply([]), 0)
        self.assertEqual(self.touched(), {
            0x401000, 0x402000, 0x500000, 0x500004, 0x600000, 0x610000,
            0x600004, 0x600008, 0x610004, 0x400008, 0x402008,
        })
        self.program.startTransaction.assert_not_called()
        self.program.save.assert_not_called()
        self.interior.delete.assert_not_called()
        self.manager.removeFunction.assert_not_called()


if __name__ == "__main__":
    unittest.main()
