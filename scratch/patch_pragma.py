content = open("src/game/TCivToolbar.cpp").read()
if '#pragma optimize' not in content:
    content = '#pragma optimize("y", on)\n' + content
    open("src/game/TCivToolbar.cpp", "w").write(content)
