#pragma once

// Mac: TMission — base mission class (hierarchy recovery in progress).
class TMission {
public:
  // Factory (0x5350d0). TEMP: forwards to stub until mission ctors use real inheritance.
  static void* CreateByKindAndNodeContext(int sourceNation, int missionKind, int arg2, int arg3,
                                          int arg4);
};
