import re

for filename in ["include/game/TView.h", "include/game/TControl.h"]:
    content = open(filename).read()
    content = re.sub(r"virtual void vmethod_([0-9a-fA-F]+)\(\);", r"virtual void vmethod_\1() {}", content)
    content = re.sub(r"virtual class TControl\* ResolveControlByTag\(unsigned int controlTag\);", r"virtual class TControl* ResolveControlByTag(unsigned int controlTag) { return 0; }", content)
    content = re.sub(r"virtual void SetControlEnabledAndRefresh\(int enabledState, int refreshFlag\);", r"virtual void SetControlEnabledAndRefresh(int enabledState, int refreshFlag) {}", content)
    content = re.sub(r"virtual void RefreshControl\(\);", r"virtual void RefreshControl() {}", content)
    content = re.sub(r"virtual void SetControlClassAndRefresh\(int classState, int refreshFlag\);", r"virtual void SetControlClassAndRefresh(int classState, int refreshFlag) {}", content)
    content = re.sub(r"virtual void NotifyControlSelectionChange\(void\* boundEntry\);", r"virtual void NotifyControlSelectionChange(void* boundEntry) {}", content)
    open(filename, "w").write(content)
