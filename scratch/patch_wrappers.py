content = open("src/game/TCivToolbar.cpp").read()
import re

# Remove the static __inline wrappers
content = re.sub(r"static __inline void\* QuerySelectedCivilianOrderState\(\) \{[^\}]+\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"static __inline void DispatchPanelControlEvent[^\}]+\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"static __inline void SetActiveCivilianSelection[^\}]+\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"static __inline void QueueImmediateCivilianCommandAndCycleSelection[^\}]+\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"static __inline void ShowDisbandCivilianConfirmationDialog[^\}]+\}\n", "", content, flags=re.DOTALL)
content = re.sub(r"static __inline int IsCivilianOrderInIdleSelectionStateBridge[^\}]+\}\n", "", content, flags=re.DOTALL)

# Add the methods to SelectedCivilianState
replacement = """struct SelectedCivilianState {
  unsigned char pad_00[0x04];
  void* selectedEntry;

  void SetActiveCivilianSelection(void* entryContext, int refreshCommandPanel) {
    reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_SetActiveCivilianSelection)(
        this, 0, entryContext, refreshCommandPanel);
  }

  void QueueImmediateCivilianCommandAndCycleSelection(int commandType) {
    reinterpret_cast<void(__fastcall*)(void*, int, int)>(
        thunk_QueueImmediateCivilianCommandAndCycleSelection)(this, 0, commandType);
  }

  void ShowDisbandCivilianConfirmationDialog() {
    reinterpret_cast<void(__fastcall*)(void*)>(thunk_ShowDisbandCivilianConfirmationDialog)(
        this);
  }
};

struct CivilianOrderEntry {
  int IsInIdleSelectionState() {
    return reinterpret_cast<int(__fastcall*)(void*)>(thunk_IsCivilianOrderInIdleSelectionState)(
        this);
  }
};"""
content = content.replace("struct SelectedCivilianState {\n  unsigned char pad_00[0x04];\n  void* selectedEntry;\n};", replacement)

# Replace the calls
content = content.replace("QuerySelectedCivilianOrderState()", "(*reinterpret_cast<SelectedCivilianState**>(kAddrSelectedCivilianOrderState))")
content = content.replace("DispatchPanelControlEvent(this, ", "this->DispatchPanelControlEvent(")
content = content.replace("SetActiveCivilianSelection(selectedCivilianOrderState, ", "selectedCivilianOrderState->SetActiveCivilianSelection(")
content = content.replace("QueueImmediateCivilianCommandAndCycleSelection(selectedCivilianOrderState, ", "selectedCivilianOrderState->QueueImmediateCivilianCommandAndCycleSelection(")
content = content.replace("ShowDisbandCivilianConfirmationDialog(selectedCivilianOrderState)", "selectedCivilianOrderState->ShowDisbandCivilianConfirmationDialog()")
content = content.replace("IsCivilianOrderInIdleSelectionStateBridge(selectedCivilianOrderEntry)", "reinterpret_cast<CivilianOrderEntry*>(selectedCivilianOrderEntry)->IsInIdleSelectionState()")

open("src/game/TCivToolbar.cpp", "w").write(content)
