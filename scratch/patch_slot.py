import re

# Update TView.h
content = open("include/game/TView.h").read()
# Replace vmethod_0041 with SetEnabled
content = content.replace("virtual void vmethod_0041() {}", "virtual void SetEnabled(int enabledState, int refreshFlag) {}")
# Replace SetControlEnabledAndRefresh with SetState
content = content.replace("virtual void SetControlEnabledAndRefresh(int enabledState, int refreshFlag) {}", "virtual void SetState(int state, int refreshFlag) {}")
open("include/game/TView.h", "w").write(content)

# Update TCivToolbar.cpp usages
content = open("src/game/TCivToolbar.cpp").read()
content = content.replace("SetControlEnabledAndRefresh", "SetEnabled")
open("src/game/TCivToolbar.cpp", "w").write(content)
