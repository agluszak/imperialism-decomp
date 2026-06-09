#include "game/TInterNationEventQueueManager.h"
#include "game/diplomacy_globals.h"
#include "game/TLocalizationRuntime.h"

// FUNCTION: IMPERIALISM 0x00406758
void TInterNationEventQueueManager::thunk_QueueInterNationEventRecordDeduped(
    int eventCode, int nationA, int nationB, char isReplayBypass) {
  QueueInterNationEventRecordDeduped(eventCode, nationA, nationB, isReplayBypass);
}

// FUNCTION: IMPERIALISM 0x0055c9f0
void TInterNationEventQueueManager::QueueInterNationEventRecordDeduped(int eventCode, int nationA,
                                                                       int nationB,
                                                                       char isReplayBypass) {
  TLocalizationRuntime* localization = reinterpret_cast<TLocalizationRuntime*>(g_pLocalizationTable);
  if (reinterpret_cast<char*>(localization)[0x7a] != 0) {
    return;
  }
  if ((isReplayBypass == 0) && (reinterpret_cast<int*>(localization)[0x11] != 0)) {
    if (reinterpret_cast<int*>(localization)[0x11] == 1) {
      reinterpret_cast<void(__cdecl*)(void)>(0x00409650)();
    }
    return;
  }
  if ((eventCode >= 5) && (eventCode <= 0x15)) {
    reinterpret_cast<void(__cdecl*)(void)>(0x00407919)();
    return;
  }
  if (nationA < 7) {
    short packet[4];
    packet[0] = static_cast<short>(eventCode);
    packet[2] = static_cast<short>(1 << nationB);
    packet[1] = static_cast<short>(nationA);
    void* queueObject = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x58c);
    reinterpret_cast<void(__fastcall*)(void*, int, short*)>(0x00409679)(queueObject, 0, packet);
  }
  if ((nationB < 7) && (eventCode > 1) && (eventCode < 0x19)) {
    short packet[4];
    packet[0] = static_cast<short>(eventCode);
    packet[2] = static_cast<short>(1 << nationA);
    packet[1] = static_cast<short>(nationB);
    void* queueObject = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x58c);
    reinterpret_cast<void(__fastcall*)(void*, int, short*)>(0x00409679)(queueObject, 0, packet);
  }
}
