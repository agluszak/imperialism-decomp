import re

content = open("src/game/TCivToolbar.cpp").read()

# Remove the bridge functions
bridges_pattern = re.compile(r"static __inline void SetActiveCivilianSelection.*?static __inline int IsCivilianOrderInIdleSelectionStateBridge[^\}]+\}\n", re.DOTALL)
content = bridges_pattern.sub("", content)

# Remove thunk_SetActiveCivilianSelection up to IsCivilianOrderInIdleSelectionState
content = re.sub(r"undefined4 thunk_SetActiveCivilianSelection\(void\);\n.*undefined4 thunk_IsCivilianOrderInIdleSelectionState\(void\);\n", "", content, flags=re.DOTALL)

# Add #include "game/TControl.h" if missing
if 'include "game/TControl.h"' not in content:
    content = content.replace('#include "game/TCivToolbar.h"', '#include "game/TCivToolbar.h"\n#include "game/TControl.h"')

# Replace ResolveControlByTag(..., tag) -> ...->ResolveControlByTag(tag)
content = re.sub(r"ResolveControlByTag\(([^,]+),\s*([^)]+)\)", r"\1->ResolveControlByTag(\2)", content)

# Replace SetControlEnabledAndRefresh(control, a, b) -> control->SetControlEnabledAndRefresh(a, b)
content = re.sub(r"SetControlEnabledAndRefresh\(([^,]+),\s*([^,]+),\s*([^)]+)\)", r"\1->SetControlEnabledAndRefresh(\2, \3)", content)

# Replace SetControlClassAndRefresh
content = re.sub(r"SetControlClassAndRefresh\(([^,]+),\s*([^,]+),\s*([^)]+)\)", r"\1->SetControlClassAndRefresh(\2, \3)", content)

# Replace SetControlBoundEntry
content = re.sub(r"SetControlBoundEntry\(([^,]+),\s*([^)]+)\)", r"\1->NotifyControlSelectionChange(\2)", content)

# Replace RefreshControl
content = re.sub(r"RefreshControl\(([^)]+)\)", r"\1->RefreshControl()", content)

# Fix local variables
content = content.replace("int* backControl;", "TControl* backControl;")
content = content.replace("int* unitControl;", "TControl* unitControl;")
content = content.replace("int* selectedStackButton;", "TControl* selectedStackButton;")
content = content.replace("int* stackButton;", "TControl* stackButton;")

# Fix inline vtable call in RefreshCivilianStackButtonsForTile
inline_call = r"reinterpret_cast<void\(__fastcall\*\)\(void\*, int, int\)>\(\s*reinterpret_cast<int\*>\(\*reinterpret_cast<void\*\*>\(this\)\)\[0x72\]\)\(this, 0, selectedSlotTag\);"
content = re.sub(inline_call, r"this->SetControlClassAndRefresh(selectedSlotTag, 0);", content, flags=re.DOTALL)

# Fix GetTEventHandlerClassNamePointer usages or others if any

# Wait, selectedStackButton[7] -> reinterpret_cast<int*>(selectedStackButton)[7]
content = content.replace("selectedStackButton[7]", "reinterpret_cast<int*>(selectedStackButton)[7]")

open("src/game/TCivToolbar.cpp", "w").write(content)
