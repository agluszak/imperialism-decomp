import re

content = open("src/game/TCivToolbar.cpp").read()

# Add #include "game/TControl.h"
if 'include "game/TControl.h"' not in content:
    content = content.replace('#include "game/TCivToolbar.h"', '#include "game/TCivToolbar.h"\n#include "game/TControl.h"')

# Replace ResolveControlByTag
content = re.sub(r"ResolveControlByTag\(([^,]+),\s*([^)]+)\)", r"\1->ResolveControlByTag(\2)", content)

# Replace SetControlEnabledAndRefresh
content = re.sub(r"SetControlEnabledAndRefresh\(([^,]+),\s*([^,]+),\s*([^)]+)\)", r"\1->SetControlEnabledAndRefresh(\2, \3)", content)

# Replace SetControlClassAndRefresh
content = re.sub(r"SetControlClassAndRefresh\(([^,]+),\s*([^,]+),\s*([^)]+)\)", r"\1->SetControlClassAndRefresh(\2, \3)", content)

# Replace SetControlBoundEntry
content = re.sub(r"SetControlBoundEntry\(([^,]+),\s*([^)]+)\)", r"\1->NotifyControlSelectionChange(\2)", content)

# Replace RefreshControl
content = re.sub(r"RefreshControl\(([^)]+)\)", r"\1->RefreshControl()", content)

# Remove the bridge definitions
content = re.sub(r"static __inline int\* ResolveControlByTag.*?\n}\n", "", content, flags=re.DOTALL)
content = re.sub(r"static __inline void SetControlEnabledAndRefresh.*?\n}\n", "", content, flags=re.DOTALL)
content = re.sub(r"static __inline void SetControlClassAndRefresh.*?\n}\n", "", content, flags=re.DOTALL)
content = re.sub(r"static __inline void SetControlBoundEntry.*?\n}\n", "", content, flags=re.DOTALL)
content = re.sub(r"static __inline void RefreshControl.*?\n}\n", "", content, flags=re.DOTALL)

# Fix pointer types
content = content.replace("int* backControl;", "TControl* backControl;")
content = content.replace("int* unitControl;", "TControl* unitControl;")
content = content.replace("int* selectedStackButton;", "TControl* selectedStackButton;")
content = content.replace("int* stackButton;", "TControl* stackButton;")

# Fix inline vtable call in RefreshCivilianStackButtonsForTile
inline_call = r"reinterpret_cast<void\(__fastcall\*\)\(void\*, int, int\)>\(\s*reinterpret_cast<int\*>\(\*reinterpret_cast<void\*\*>\(this\)\)\[0x72\]\)\(this, 0, selectedSlotTag\);"
content = re.sub(inline_call, r"this->SetControlClassAndRefresh(selectedSlotTag, 0);", content, flags=re.DOTALL)

# Fix pointer arithmetic
content = content.replace("backControl + 0x18", "reinterpret_cast<char*>(backControl) + 0x18")

# Fix selectedStackButton[7]
content = content.replace("selectedStackButton[7]", "reinterpret_cast<int*>(selectedStackButton)[7]")

open("src/game/TCivToolbar.cpp", "w").write(content)
