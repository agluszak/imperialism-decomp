content = open("src/game/TCivToolbar.cpp").read()
content = content.replace("backControl + 0x18", "reinterpret_cast<char*>(backControl) + 0x18")
open("src/game/TCivToolbar.cpp", "w").write(content)
