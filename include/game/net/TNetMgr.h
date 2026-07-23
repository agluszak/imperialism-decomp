#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

struct NetMessage;
struct TurnEventQueuePacket;
class TView;

// Global turn-event queue manager handle (ConstructGlobalTurnEventQueueManager @ 0x005e33e0
// only stores vptr 0x0066fa20 on a 4-byte heap block). Plain TObject derivative — no extra
// bases. The adjacent vtables at 0x0066fa50/0x0066fa68 are NOT TNetMgr slots: they are the
// WNetMgr.cpp TU's twin copies of the CList<void*,void*> / CArray<void*,void*> template
// vtables for the file-scope statics g_WNetPendingPacketList006a5f40 /
// g_WNetSerializedPtrArray{A,B} (ctor/dtor evidence 0x5e4540/0x5e4580, 0x5e4780/0x5e47b0;
// Serialize instantiations 0x5e4610/0x5e4830).
// VTABLE: IMPERIALISM 0x0066fa20
class TNetMgr : public TObject {
public:
  DECLARE_DYNCREATE(TNetMgr)
  virtual ~TNetMgr() override;  // slot 0x01 (scalar deleting destructor)
  virtual void Free() override; // slot 0x07 0x5e3470
  // slot 0x0a null (0x00000000)
  // slot 0x0b null (0x00000000)

  TNetMgr();

  // Mac oracle: TNetMgr::StartMultiplayerSupport(). The Windows body is empty, but
  // the caller dispatches it on the newly constructed global network manager.
  void StartMultiplayerSupport(); // 0x5e3450

  // Queue the message for the local player and/or send it over DirectPlay
  // (message->toNetworkId == -1 broadcasts). `this` carries no state — the queue and
  // session-manager state are file-scope globals of the original WNetMgr.cpp TU.
  // Mac oracle: TNetMgr::Send(NSpMessageHeader*, unsigned char).
  unsigned char Send(NetMessage* message, unsigned char queueOnly);

  unsigned char DefaultUnhandledTurnEventHookReturnsFalse(TurnEventQueuePacket* packet);
  void FreeTurnEventPacketBuffer(TurnEventQueuePacket* packet);
  TurnEventQueuePacket* PopNextTurnEventPacketOrProcessSpecialQueueRecords();
  unsigned char CheckConnectivityOrShowLocalizedWarningAndReturnReady();
  int GetSessionActiveNationId(); // 0x5e4280

  // 0x5e42c0 — destroy the DirectPlay player when `nationId` is the local session id
  // (name kept from Ghidra; the body destroys, it does not notify). Real __thiscall on
  // the singleton (callers load g_pNetMgr006a6014 into ecx); `this` unused.
  void NoOpDialogModeTagChangedHook(int arg); // 0x5e42a0 (empty)
  void NotifyIfNationMatchesSessionActiveNation(int nationId);

  // 0x5e43e0 — probe every eligible nation with an event-0x2b packet through the
  // DirectPlay session manager; returns the bitmask of unreachable (AWOL) slots and
  // dispatches the drop notices for newly failed sends. Real __thiscall on the
  // g_pNetMgr006a6014 singleton (every caller loads it into ecx); `this` unused.
  int ProbeNationReachabilityAndMarkAwolBitmask();

  // Reset the DirectPlay runtime-selection buffer on the global session manager.
  // The body does not use `this`, but both retail callers load g_pNetMgr006a6014
  // into ECX before dispatching it.
  void ResetTurnEventQueueRuntimeRecordBuffer(); // 0x5e3ef0
  // Same reset as ResetTurnEventQueueRuntimeRecordBuffer, but returns true; `this`
  // unused (a singleton-dispatched wrapper, callers load g_pNetMgr006a6014 into ecx).
  unsigned char ResetRuntimeSelectionRecordBufferAndReturnTrue(); // 0x5e34d0
  // Always-true no-op hook bracketing runtime-selection credential setup; `this`
  // unused (singleton-dispatched, like the pair above). The init half of the pair
  // (0x5e34b0) is already claimed as the free function
  // ReturnTrueRuntimeCredentialInitStub() in TMultiplayerMgr.cpp.
  unsigned char ReturnTrueRuntimeCredentialFinalizeStub(); // 0x5e3c00

  // Copies seed (up to 32 chars) into the DirectPlay session-name buffer and opens the
  // selection source at index via OpenRuntimeSelectionSourceWithOptionalSeed, posing
  // the localized error dialog on failure.
  unsigned char OpenRuntimeSelectionSourceByIndexAndCopyPath(int index, int flag,
                                                             const char* seed); // 0x5e3a60

  // Stages seedPath/emptyOrSeed into the shared session-name buffers, opens the
  // session via g_NetworkSessionManager006a5f60's current context, creates the local
  // player (short name = localPlayerName), tags the default/broadcast nation ids from
  // the new player's DPID, and sets the small player-data payload. Poses the DirectPlay
  // error dialog and returns 0 on any failed step.
  unsigned char
  OpenRuntimeSelectionSourceAndApplyActiveNationState(const char* seedPath,
                                                      const char* localPlayerName,
                                                      const char* emptyOrSeed); // 0x5e3ad0

  // Joins the game named by outGameName's current value (staged into a static
  // player-name buffer), lets the user pick the session
  // (OpenRuntimeSelectionSourceWithUserChoice), creates the local player, tags the
  // local player id as the default nation id, sets a small player-data payload, and
  // enumerates existing players to resolve the broadcast nation id. Copies the
  // chosen name back into *outGameName. Returns success.
  unsigned char OpenJoinGameRuntimeSelectionAndStartSession(int selectionTag, CString* outGameName,
                                                            const char* seed); // 0x5e3c20

  // Resolves provider's 'prot' control (asserting it valid), rebuilds the enumerated-
  // protocol selection list (g_WNetSerializedPtrArrayA006a5f10) and re-enumerates via
  // TWNetSessionManager::RebuildRuntimeSelectionSource (takes no argument).
  unsigned char ResetRuntimeProtocolOptionsAndRebuildSelectionSource(TView* provider); // 0x5e39a0

  // Map a DirectPlay error HRESULT to detail text and pose the localized error dialog.
  // Mac oracle: TNetMgr::HandleError(int). Asserts with D:\Ambit\WNetMgr.cpp line 451.
  void HandleError(int errorCode);
};
