def gen():
    for i in range(2, 118):
        if i == 37:
            print("  virtual TControl* ResolveControlByTag(unsigned int controlTag);")
        elif i == 42:
            print("  virtual void SetControlEnabledAndRefresh(int enabledState, int refreshFlag);")
        elif i == 57:
            print("  virtual void RefreshControl();")
        elif i == 114:
            print("  virtual void SetControlClassAndRefresh(int classState, int refreshFlag);")
        elif i == 117:
            print("  virtual void SetControlBoundEntry(void* boundEntry);")
        else:
            print(f"  virtual void vmethod_{i:04d}();")
gen()
