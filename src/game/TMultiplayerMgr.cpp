#include "game/TMultiplayerMgr.h"

#include "decomp_types.h"
#include "game/TNetMgr.h"
#include "game/TStream.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/global_data_tables.h"
#include <cstring>

// Leaf helpers reached through ILT thunks / autogen stubs. They are genuine __cdecl free
// functions (verified against the disassembly — none consume ECX as `this` on entry; the
// ECX loads before some calls are optimizer reuse, not a this-arg). Declared extern in the
// generic repo form per Hard Rule 9 and cast to their real typed signatures at the call sites.
extern undefined4 NoOpInitializeGlobalTurnEventQueueManager();
extern undefined4 ResetTurnEventQueueRuntimeRecordBuffer();
extern undefined4 GenerateMappedFlavorTextByCurrentContextNation();
extern undefined4 LoadProfileStringAndAssignSharedRef();
extern undefined4 AssignStringSharedRefFromPointer();

// 0x006a6014 — global turn-event-queue manager pointer. Profile-section string literals.
extern TNetMgr* DAT_006a6014;
extern "C" const char s_PlayerName_0069801c[];
extern "C" const char s_GameName_00698010[];

// FUNCTION: IMPERIALISM 0x00542650
CRuntimeClass* TMultiplayerMgr::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00542670
TMultiplayerMgr::TMultiplayerMgr()
    : TEventHandler(),
      gameNameString(),
      defaultNationTextSlots(),
      nationDisplayNameSlots(),
      playerNameString(),
      playerNameMirror(),
      fieldb8() {
  InitializeUiResourceEntryBaseHeaderDefaults();
  memset(nationStatusControlSlots, 0, sizeof(nationStatusControlSlots));
  field40 = 0;
  primaryTurnEventQueueHead = 0;
  secondaryTurnEventQueueHead = 0;
  sessionPhaseTag = 0x6e616461;
  fieldF4 = 0;
}

// SYNTHETIC: IMPERIALISM 0x005427e0
// TMultiplayerMgr::`scalar deleting destructor'
TMultiplayerMgr::~TMultiplayerMgr() {}

// FUNCTION: IMPERIALISM 0x00542900
undefined TMultiplayerMgr::InitializeMultiplayerManagerForSessionContext(CString param_1) {
  this->InitializePacketHeaderFields_Tag20202020(0);
  field10 = reinterpret_cast<int>(static_cast<LPCSTR>(param_1));
  diplomacyQueueContext = 0;
  sessionReadyFlag = 0;
  processPrimaryEventQueue = 1;
  processSecondaryEventQueue = 1;

  TNetMgr* queueStorage = new TNetMgr();
  DAT_006a6014 = queueStorage;
  reinterpret_cast<void (*)()>(NoOpInitializeGlobalTurnEventQueueManager)();

  CString loadedString;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&loadedString, 0x2759, 1);

  for (int i = 0; i < kNationSlotCount; ++i) {
    nationSessionIds[0] = 0;
    nationStatusTags[0] = 0x756e6173;
    nationDisplayNameSlots[i] = loadedString;
    reinterpret_cast<void (*)(CString*)>(AssignStringSharedRefFromPointer)(
        &nationDisplayNameSlots[i]);
  }

  queueSyncDword = 0;
  activeNationSlotIndex = -1;
  pendingNationSlotIndex = -1;
  reinterpret_cast<void (*)()>(ResetTurnEventQueueRuntimeRecordBuffer)();

  reinterpret_cast<void (*)(CString*)>(GenerateMappedFlavorTextByCurrentContextNation)(
      &playerNameString);
  reinterpret_cast<void (*)(CString*, const char*, const char*)>(LoadProfileStringAndAssignSharedRef)(
      &loadedString, s_PlayerName_0069801c, static_cast<LPCSTR>(playerNameString));
  playerNameString = loadedString;
  playerNameMirror = playerNameString;

  reinterpret_cast<void (*)(CString*)>(GenerateMappedFlavorTextByCurrentContextNation)(&gameNameString);
  reinterpret_cast<void (*)(CString*, const char*, const char*)>(LoadProfileStringAndAssignSharedRef)(
      &loadedString, s_GameName_00698010, static_cast<LPCSTR>(gameNameString));
  gameNameString = loadedString;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00542b10
void TMultiplayerMgr::Free() {}

// FUNCTION: IMPERIALISM 0x00542be0
void TMultiplayerMgr::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00542ff0
void TMultiplayerMgr::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00544e30
char TMultiplayerMgr::CanHandleCityDialogActionFalse(int action) {
  (void)action;
  return 0;
}
