content = open("src/game/TCivToolbar.cpp").read()
import re
content = re.sub(r"class RuntimeBridge \{[^\}]+\};\n", "", content, flags=re.DOTALL)
open("src/game/TCivToolbar.cpp", "w").write(content)
