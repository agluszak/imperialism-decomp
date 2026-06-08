content = open("src/game/TCivToolbar.cpp").read()
import re
content = re.sub(r"undefined4 thunk_ConstructUiResourceEntryType4B0C0\(void\);\n", "", content)
content = re.sub(r"undefined4 thunk_DestructEngineerDialogBaseState\(void\);\n", "", content)
content = re.sub(r"undefined4 thunk_ShowCivilianLedgerDialogAndSelectUnit\(void\);\n", "", content)
open("src/game/TCivToolbar.cpp", "w").write(content)
