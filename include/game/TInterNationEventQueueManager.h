#pragma once

#include "decomp_types.h"

// Global singleton at g_pInterNationEventQueueManager (0x006A43E8).
// Ghidra labels calls through this pointer as TCountry*; that is the Windows
// nation-state vtable bucket (g_vtblTCountry @ 0x00653868), not this manual
// slice. Mac lists TCountry as a separate 48-method nation class sibling to
// TGreatPower — do not conflate with this queue-manager object.
class TInterNationEventQueueManager {
public:
  void QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB,
                                          char isReplayBypass);
  void thunk_QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB,
                                                char isReplayBypass);
};
