content = open("src/game/TCivToolbar.cpp").read()
content = content.replace("newCivilianClassId =\n      (selectedCivilianOrderEntry == 0) ? (short)-1 : (short)selectedCivilianOrderEntry[1];", "newCivilianClassId = (short)selectedCivilianOrderEntry[1];")
content = content.replace("newCivilianClassId = (selectedCivilianOrderEntry == 0) ? (short)-1 : (short)selectedCivilianOrderEntry[1];", "newCivilianClassId = (short)selectedCivilianOrderEntry[1];")
open("src/game/TCivToolbar.cpp", "w").write(content)
