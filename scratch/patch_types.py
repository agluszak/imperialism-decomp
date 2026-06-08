content = open("src/game/TCivToolbar.cpp").read()
content = content.replace("void* selectedCivilianOrderState =", "SelectedCivilianState* selectedCivilianOrderState =")
open("src/game/TCivToolbar.cpp", "w").write(content)
