import re

tview_h = open("include/game/TView.h").read()
tcontrol_h = open("include/game/TControl.h").read()

tview_vmethods = []
for i in range(2, 112):
    if i == 37:
        tview_vmethods.append("  virtual class TControl* ResolveControlByTag(unsigned int controlTag);")
    elif i == 42:
        tview_vmethods.append("  virtual void SetControlEnabledAndRefresh(int enabledState, int refreshFlag);")
    elif i == 57:
        tview_vmethods.append("  virtual void RefreshControl();")
    else:
        tview_vmethods.append(f"  virtual void vmethod_{i:04d}();")

tcontrol_vmethods = []
for i in range(112, 118):
    if i == 114:
        tcontrol_vmethods.append("  virtual void SetControlClassAndRefresh(int classState, int refreshFlag);")
    elif i == 117:
        tcontrol_vmethods.append("  virtual void NotifyControlSelectionChange(void* boundEntry);")
    else:
        tcontrol_vmethods.append(f"  virtual void vmethod_{i:04d}();")

# Insert into TView.h before `virtual ~TView();`
tview_replacement = "\n".join(tview_vmethods) + "\n  virtual ~TView();"
tview_h = tview_h.replace("  virtual ~TView();", tview_replacement)
open("include/game/TView.h", "w").write(tview_h)

# Insert into TControl.h before `};`
# TControl.h ends with:
#   void InvalidateCityDialogRectRegion(struct RECT* rect, int flag);
# };
tcontrol_replacement = "  void InvalidateCityDialogRectRegion(struct RECT* rect, int flag);\n\n" + "\n".join(tcontrol_vmethods) + "\n"
tcontrol_h = tcontrol_h.replace("  void InvalidateCityDialogRectRegion(struct RECT* rect, int flag);", tcontrol_replacement)
open("include/game/TControl.h", "w").write(tcontrol_h)

