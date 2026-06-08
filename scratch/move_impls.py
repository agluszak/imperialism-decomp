import re

tview_h = open("include/game/TView.h").read()
tview_h = re.sub(r"virtual void vmethod_([0-9a-fA-F]+)\(\) \{\}", r"virtual void vmethod_\1();", tview_h)
tview_h = tview_h.replace("virtual class TControl* ResolveControlByTag(unsigned int controlTag) { return 0; }", "virtual class TControl* ResolveControlByTag(unsigned int controlTag);")
tview_h = tview_h.replace("virtual void SetEnabled(int enabledState, int refreshFlag) {}", "virtual void SetEnabled(int enabledState, int refreshFlag);")
tview_h = tview_h.replace("virtual void RefreshControl() {}", "virtual void RefreshControl();")
tview_h = tview_h.replace("virtual void SetState(int state, int refreshFlag) {}", "virtual void SetState(int state, int refreshFlag);")
tview_h = tview_h.replace("virtual void SetControlClassAndRefresh(int classState, int refreshFlag) {}", "virtual void SetControlClassAndRefresh(int classState, int refreshFlag);")
tview_h = tview_h.replace("virtual void NotifyControlSelectionChange(void* boundEntry) {}", "virtual void NotifyControlSelectionChange(void* boundEntry);")
open("include/game/TView.h", "w").write(tview_h)

tcontrol_h = open("include/game/TControl.h").read()
tcontrol_h = re.sub(r"virtual void vmethod_([0-9a-fA-F]+)\(\) \{\}", r"virtual void vmethod_\1();", tcontrol_h)
tcontrol_h = tcontrol_h.replace("virtual void SetControlClassAndRefresh(int classState, int refreshFlag) {}", "virtual void SetControlClassAndRefresh(int classState, int refreshFlag);")
tcontrol_h = tcontrol_h.replace("virtual void NotifyControlSelectionChange(void* boundEntry) {}", "virtual void NotifyControlSelectionChange(void* boundEntry);")
open("include/game/TControl.h", "w").write(tcontrol_h)

# Write cpp files
tview_cpp = open("src/game/TView.cpp").read()
tview_cpp += "\n// Dummy methods\n"
for i in range(2, 112):
    if i == 37:
        tview_cpp += "class TControl* TView::ResolveControlByTag(unsigned int controlTag) { return 0; }\n"
    elif i == 41:
        tview_cpp += "void TView::SetEnabled(int enabledState, int refreshFlag) {}\n"
    elif i == 42:
        tview_cpp += "void TView::SetState(int state, int refreshFlag) {}\n"
    elif i == 57:
        tview_cpp += "void TView::RefreshControl() {}\n"
    else:
        tview_cpp += f"void TView::vmethod_{i:04d}() {{}}\n"
open("src/game/TView.cpp", "w").write(tview_cpp)

tcontrol_cpp = open("src/game/TControl.cpp").read()
tcontrol_cpp += "\n// Dummy methods\n"
for i in range(112, 118):
    if i == 114:
        tcontrol_cpp += "void TControl::SetControlClassAndRefresh(int classState, int refreshFlag) {}\n"
    elif i == 117:
        tcontrol_cpp += "void TControl::NotifyControlSelectionChange(void* boundEntry) {}\n"
    else:
        tcontrol_cpp += f"void TControl::vmethod_{i:04d}() {{}}\n"
open("src/game/TControl.cpp", "w").write(tcontrol_cpp)
