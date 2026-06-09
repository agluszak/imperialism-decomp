#pragma once

#include "decomp_types.h"

// Inter-nation event queue manager (g_pInterNationEventQueueManager).
class TCountry {
public:
  void QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB,
                                          char isReplayBypass);
  void thunk_QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB,
                                                char isReplayBypass);
};

