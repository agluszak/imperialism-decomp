#include "game/net/TWNetSessionManager.h"
#include "game/TScopedWaitCursor.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TRadioText.h"
#include "game/gfx/TTemplateDialogs.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TEditText.h"
#include "game/net/TJoinSelectorDialog.h"
#include "game/net/TNetMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/net_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

#include <cstring>

// FUNCTION: IMPERIALISM 0x0047f7f0
RuntimeSelectionRecord::~RuntimeSelectionRecord() {}

// FUNCTION: IMPERIALISM 0x0047f810
static BOOL FAR PASCAL ForwardEnumSessionToCallbackTable(LPGUID sessionGuid, LPSTR sessionName,
                                                         DWORD majorVersion, DWORD minorVersion,
                                                         LPVOID context) {
  TWNetSessionManager* mgr = static_cast<TWNetSessionManager*>(context);
  return mgr->OnEnumerateServiceProvider(sessionGuid, sessionName, majorVersion, minorVersion);
}

// IDirectPlay2::EnumSessions callback: DPESC_TIMEDOUT asks the manager whether to keep
// waiting, anything else is a real session offer.
// FUNCTION: IMPERIALISM 0x0047f870
static BOOL FAR PASCAL ForwardEnumSessionsToSessionManager(const DPSESSIONDESC2* sessionDescription,
                                                           DWORD* timeout, DWORD flags,
                                                           LPVOID context) {
  TDirectPlaySessionManagerBase* manager = static_cast<TDirectPlaySessionManagerBase*>(context);
  if ((flags & DPESC_TIMEDOUT) != 0) {
    // 0x0047f883 dispatches slot 6 (byte 0x18), not slot 5 (byte 0x14): on timeout the
    // callback extends the wait while Ctrl is held rather than returning FALSE outright.
    return manager->ExtendEnumSessionsTimeoutWhileCtrlHeld(timeout);
  }
  return manager->OnEnumerateJoinableSession(sessionDescription, timeout, flags);
}

// FUNCTION: IMPERIALISM 0x0047f8b0
BOOL TDirectPlaySessionManagerBase::OnEnumerateServiceProvider(LPGUID providerGuid,
                                                               LPSTR providerName,
                                                               DWORD majorVersion,
                                                               DWORD minorVersion) {
  (void)majorVersion;
  (void)minorVersion;

  RuntimeSelectionRecord* record = new RuntimeSelectionRecord;
  record->providerGuid = *providerGuid;
  record->label = providerName;
  int index = g_RuntimeSelectionRecords006a15e0.GetSize();
  g_RuntimeSelectionRecords006a15e0.SetSize(index + 1, -1);
  g_RuntimeSelectionRecords006a15e0[index] = record;
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x0047fb20
BOOL TDirectPlaySessionManagerBase::OnDirectPlayAssertion111(void* arg1, void* arg2, void* arg3,
                                                             void* arg4) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\DirectPlay.cpp", 0x6f);
  return FALSE;
}

// FUNCTION: IMPERIALISM 0x0047fb50
BOOL TDirectPlaySessionManagerBase::OnEnumerateJoinableSession(
    const DPSESSIONDESC2* sessionDescription, DWORD* timeout, DWORD flags) {
  (void)sessionDescription;
  (void)timeout;
  (void)flags;
  TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\DirectPlay.cpp", 0x76);
  return FALSE;
}

// FUNCTION: IMPERIALISM 0x0047fb80
BOOL TDirectPlaySessionManagerBase::CreateDirectPlayLobbyAndStoreResult() {
  lastErrorCode0c = DirectPlayLobbyCreateA(0, &directPlayLobby08, 0, 0, 0);
  return lastErrorCode0c >= 0;
}

// FUNCTION: IMPERIALISM 0x0047fcb0
char TWNetSessionManager::CreatePlayerAndStoreResult(LPDPID idOut, LPSTR shortName) {
  DPNAME name;
  memset(&name, 0, sizeof(name));
  name.lpszShortNameA = shortName;
  name.dwSize = sizeof(name);
  long createResult = directPlayInterface04->CreatePlayer(idOut, &name, 0, 0, 0, 0);
  lastErrorCode0c = createResult;
  return createResult >= 0;
}

// FUNCTION: IMPERIALISM 0x0047fd30
unsigned char TWNetSessionManager::DestroyPlayerAndStoreResult(DWORD idPlayer) {
  long destroyResult = this->directPlayInterface04->DestroyPlayer(idPlayer);
  this->lastErrorCode0c = destroyResult;
  return destroyResult >= 0;
}

static void ClearRuntimeSelectionRecordArray() {
  for (int index = 0; index < g_RuntimeSelectionRecords006a15e0.GetSize(); ++index) {
    delete g_RuntimeSelectionRecords006a15e0[index];
  }
  g_RuntimeSelectionRecords006a15e0.RemoveAll();
}

// FUNCTION: IMPERIALISM 0x0047fd70
BOOL TDirectPlaySessionManagerBase::GetRuntimeSelectionAuxStatus(void* value) {
  (void)value;
  return FALSE;
}

// FUNCTION: IMPERIALISM 0x0047fd90
BOOL TWNetSessionManager::RebuildRuntimeSelectionSource() {
  for (int index = 0; index < g_RuntimeSelectionRecords006a15e0.GetSize(); ++index) {
    delete g_RuntimeSelectionRecords006a15e0[index];
  }
  g_RuntimeSelectionRecords006a15e0.RemoveAll();
  lastErrorCode0c = DirectPlayEnumerate(ForwardEnumSessionToCallbackTable, this);
  return lastErrorCode0c == 0;
}

// FUNCTION: IMPERIALISM 0x0047fe50
bool TWNetSessionManager::InitializeDirectPlayForProviderGuidOrEnumerate(const GUID* providerGuid) {
  if (providerGuid != 0) {
    if (directPlayInterface04 != 0) {
      directPlayInterface04->Close();
      directPlayInterface04->Release();
      directPlayInterface04 = 0;
    }
  }
  if (directPlayInterface04 != 0) {
    return 1;
  }

  IDirectPlay* createdInterface = 0;
  GUID selectedProviderGuid;
  if (providerGuid != 0) {
    selectedProviderGuid = *providerGuid;
    lastErrorCode0c = DirectPlayCreate(&selectedProviderGuid, &createdInterface, 0);
  } else {
    ClearRuntimeSelectionRecordArray();
    g_RuntimeSelectionRecords006a15e0.SetSize(0, -1);
    lastErrorCode0c = DirectPlayEnumerate(ForwardEnumSessionToCallbackTable, this);
    if (lastErrorCode0c >= 0 && SelectRuntimeProvider(&selectedProviderGuid)) {
      lastErrorCode0c = DirectPlayCreate(&selectedProviderGuid, &createdInterface, 0);
    } else {
      return lastErrorCode0c >= 0;
    }
  }

  if (lastErrorCode0c >= 0 && createdInterface != 0) {
    union DirectPlay2OutParameter {
      IDirectPlay2** typed;
      void** opaque;
    } directPlay2Out;
    directPlay2Out.typed = &directPlayInterface04;
    lastErrorCode0c = createdInterface->QueryInterface(IID_IDirectPlay2, directPlay2Out.opaque);
  }
  if (createdInterface != 0) {
    createdInterface->Release();
  }

  ClearRuntimeSelectionRecordArray();
  return lastErrorCode0c >= 0;
}

// FUNCTION: IMPERIALISM 0x00480030
BOOL TWNetSessionManager::OpenRuntimeSelectionSourceFromCurrentContext() {
  InitializeDirectPlayForProviderGuidOrEnumerate(0);
  memset(&sessionDescription10, 0, sizeof(sessionDescription10));
  sessionDescription10.dwSize = sizeof(sessionDescription10);
  sessionDescription10.dwFlags = 0x40;
  InitializeSessionDescription();
  lastErrorCode0c = directPlayInterface04->Open(&sessionDescription10, DPOPEN_CREATE);
  if (lastErrorCode0c < 0) {
    for (int index = 0; index < g_RuntimeSelectionRecords006a15e0.GetSize(); ++index) {
      delete g_RuntimeSelectionRecords006a15e0[index];
    }
    g_RuntimeSelectionRecords006a15e0.RemoveAll();

    if (directPlayInterface04 != 0) {
      directPlayInterface04->Close();
      directPlayInterface04->Release();
      directPlayInterface04 = 0;
    }
    if (directPlayLobby08 != 0) {
      directPlayLobby08->Release();
      directPlayLobby08 = 0;
    }
  }
  return lastErrorCode0c >= 0;
}

// FUNCTION: IMPERIALISM 0x00480150
BOOL TWNetSessionManager::OpenRuntimeSelectionSourceWithUserChoice() {
  InitializeDirectPlayForProviderGuidOrEnumerate(0);

  memset(&sessionDescription10, 0, sizeof(sessionDescription10));
  sessionDescription10.dwSize = sizeof(DPSESSIONDESC2);
  ResetSessionDescription();

  {
    TScopedWaitCursor waitCursor;
    // Holding Ctrl during discovery stretches the enumeration window from 1s to 5s.
    DWORD enumerationTimeout = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0 ? 5000 : 1000;
    lastErrorCode0c = directPlayInterface04->EnumSessions(&sessionDescription10, enumerationTimeout,
                                                          ForwardEnumSessionsToSessionManager, this,
                                                          DPENUMSESSIONS_AVAILABLE);
  }

  if (lastErrorCode0c >= 0) {
    GUID selectedSessionGuid;
    if (ShowJoinGameSelectionDialogAndCaptureChoice(&selectedSessionGuid) != 0) {
      memset(&sessionDescription10, 0, sizeof(sessionDescription10));
      sessionDescription10.dwSize = sizeof(DPSESSIONDESC2);
      sessionDescription10.guidInstance = selectedSessionGuid;
      lastErrorCode0c = directPlayInterface04->Open(&sessionDescription10, DPOPEN_JOIN);
      if (lastErrorCode0c >= 0) {
        return 1;
      }
    }
  }

  for (int index = 0; index < g_RuntimeSelectionRecords006a15e0.GetSize(); ++index) {
    delete g_RuntimeSelectionRecords006a15e0[index];
  }
  g_RuntimeSelectionRecords006a15e0.SetSize(0, -1);

  if (directPlayInterface04 != 0) {
    directPlayInterface04->Close();
    directPlayInterface04->Release();
    directPlayInterface04 = 0;
  }
  if (directPlayLobby08 != 0) {
    directPlayLobby08->Release();
    directPlayLobby08 = 0;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004803d0
unsigned char TWNetSessionManager::OpenCurrentSessionDescriptionForJoin() {
  long result = directPlayInterface04->Open(&sessionDescription10, DPOPEN_JOIN);
  lastErrorCode0c = result;
  return result >= 0;
}

// FUNCTION: IMPERIALISM 0x00480400
void TWNetSessionManager::ResetRuntimeSelectionRecordBuffer() {
  for (int index = 0; index < g_RuntimeSelectionRecords006a15e0.GetSize(); ++index) {
    delete g_RuntimeSelectionRecords006a15e0[index];
  }
  g_RuntimeSelectionRecords006a15e0.RemoveAll();

  if (directPlayInterface04 != 0) {
    directPlayInterface04->Close();
    directPlayInterface04->Release();
    directPlayInterface04 = 0;
  }
  if (directPlayLobby08 != 0) {
    directPlayLobby08->Release();
    directPlayLobby08 = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004804c0
BOOL TDirectPlaySessionManagerBase::ExtendEnumSessionsTimeoutWhileCtrlHeld(DWORD* timeoutMs) {
  if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0) {
    *timeoutMs += 500;
    return TRUE;
  }
  return FALSE;
}

// FUNCTION: IMPERIALISM 0x00480500
BOOL TDirectPlaySessionManagerBase::SelectRuntimeProvider(GUID* providerGuid) {
  T104TemplateDialog dialog(0);
  for (int index = 0; index < g_RuntimeSelectionRecords006a15e0.GetSize(); ++index) {
    RuntimeSelectionRecord* record = g_RuntimeSelectionRecords006a15e0[index];
    int row = dialog.listbox.AddString(record->label);
    dialog.listbox.SetItemDataPtr(row, record);
  }
  if (dialog.DoModal() != IDOK) {
    return FALSE;
  }
  RuntimeSelectionRecord* selected = static_cast<RuntimeSelectionRecord*>(
      dialog.listbox.GetItemDataPtr(dialog.listbox.GetCurSel()));
  *providerGuid = selected->providerGuid;
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x00480820
BOOL TDirectPlaySessionManagerBase::ShowJoinGameSelectionDialogAndCaptureChoice(
    GUID* selectedSessionGuid) {
  (void)selectedSessionGuid;
  TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\DirectPlay.cpp", 0x1b3);
  return FALSE;
}

// FUNCTION: IMPERIALISM 0x00480850
int TWNetSessionManager::TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount) {
  IDirectPlay2* directPlay = this->directPlayInterface04;
  if (directPlay != 0) {
    long sendResult = directPlay->Send(this->localPlayerId60, nationId, 1, packet, byteCount);
    this->lastErrorCode0c = sendResult;
    return sendResult >= 0;
  }
  return 0;
}

// Pulls the next pending DirectPlay message into *bufferHandle, growing the GlobalAlloc
// buffer until IDirectPlay2::Receive stops reporting DPERR_BUFFERTOOSMALL.
// DPERR_NOMESSAGES ends the loop without a message.
// FUNCTION: IMPERIALISM 0x004808a0
int TWNetSessionManager::TryReceiveNetworkPacketIntoResizableBuffer(DWORD* fromId, DWORD* toId,
                                                                    void** bufferHandle) {
  if (directPlayInterface04 == 0) {
    return 1;
  }
  *bufferHandle = 0;
  DWORD neededSize = 0;
  long receiveResult;
  do {
    if (neededSize > 0) {
      HGLOBAL grownBuffer;
      if (*bufferHandle != 0) {
        grownBuffer = GlobalReAlloc(*bufferHandle, neededSize, 0);
      } else {
        grownBuffer = GlobalAlloc(0, neededSize);
      }
      *bufferHandle = grownBuffer;
    }
    receiveResult = directPlayInterface04->Receive(fromId, toId, 1, *bufferHandle, &neededSize);
    this->lastErrorCode0c = receiveResult;
  } while (receiveResult != DPERR_NOMESSAGES &&
           (*bufferHandle == 0 || receiveResult == DPERR_BUFFERTOOSMALL));
  if (receiveResult < 0 && receiveResult != DPERR_NOMESSAGES) {
    GlobalFree(*bufferHandle);
    *bufferHandle = 0;
    return 0;
  }
  return receiveResult >= 0;
}

// FUNCTION: IMPERIALISM 0x00480990
BOOL TWNetSessionManager::SetLocalPlayerDataAndStoreResult(LPVOID data, DWORD size) {
  long setResult = directPlayInterface04->SetPlayerData(localPlayerId60, data, size, 2);
  lastErrorCode0c = setResult;
  return setResult >= 0;
}

// FUNCTION: IMPERIALISM 0x004809d0
BOOL TDirectPlaySessionManagerBase::GetPlayerData(DPID playerId, void* buffer, DWORD* sizeInOut) {
  lastErrorCode0c = directPlayInterface04->GetPlayerData(playerId, buffer, sizeInOut, 0);
  return lastErrorCode0c >= 0;
}

// FUNCTION: IMPERIALISM 0x005e2900
static BOOL FAR PASCAL RecordHostPlayerIdDuringEnumeration(DPID dpId, DWORD dwPlayerType,
                                                           LPCDPNAME lpName, DWORD dwFlags,
                                                           LPVOID lpContext) {
  (void)dwPlayerType;
  (void)lpName;
  (void)dwFlags;
  TDirectPlaySessionManagerBase* session = static_cast<TDirectPlaySessionManagerBase*>(lpContext);
  DWORD playerRole = 0;
  DWORD playerRoleSize = sizeof(playerRole);
  if (session->GetPlayerData(dpId, &playerRole, &playerRoleSize) == 0) {
    g_pNetMgr006a6014->HandleError(session->lastErrorCode0c);
    return FALSE;
  }
  if (playerRole == 1) {
    session->broadcastPlayerId64 = dpId;
    return FALSE;
  }
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x005e2980
BOOL TDirectPlaySessionManagerBase::FindHostPlayerIdByEnumeration() {
  broadcastPlayerId64 = 0;
  lastErrorCode0c = directPlayInterface04->EnumPlayers(0, RecordHostPlayerIdDuringEnumeration, this,
                                                       DPENUMPLAYERS_REMOTE);
  return lastErrorCode0c >= 0 && broadcastPlayerId64 != 0;
}

// FUNCTION: IMPERIALISM 0x005e2a20
TWNetSessionManager::~TWNetSessionManager() {
  for (int i = 0; i < g_WNetSerializedPtrArrayB006a5f28.GetSize(); ++i) {
    delete g_WNetSerializedPtrArrayB006a5f28[i];
  }
  g_WNetSerializedPtrArrayB006a5f28.RemoveAll();
  for (int j = 0; j < g_WNetSerializedPtrArrayA006a5f10.GetSize(); ++j) {
    delete static_cast<RuntimeSelectionRecord*>(g_WNetSerializedPtrArrayA006a5f10[j]);
  }
  g_WNetSerializedPtrArrayA006a5f10.RemoveAll();
}

// FUNCTION: IMPERIALISM 0x005e2b50
void TDirectPlaySessionManagerBase::InitializeSessionDescription() {}

// FUNCTION: IMPERIALISM 0x005e2b70
void TDirectPlaySessionManagerBase::ResetSessionDescription() {}

// FUNCTION: IMPERIALISM 0x005e2bb0
void TWNetSessionManager::ResetSessionDescription() {
  joinGamePlayerDataTagAC = 0;
  sessionDescription10.guidApplication = g_ImperialismDirectPlayApplicationGuid0066f968;
  sessionDescription10.lpszPasswordA = joinGameSeed68;
  for (int index = 0; index < g_WNetSerializedPtrArrayB006a5f28.GetSize(); ++index) {
    delete g_WNetSerializedPtrArrayB006a5f28[index];
  }
  g_WNetSerializedPtrArrayB006a5f28.RemoveAll();
}

// FUNCTION: IMPERIALISM 0x005e2c80
void TWNetSessionManager::InitializeSessionDescription() {
  joinGamePlayerDataTagAC = 1;
  sessionDescription10.guidApplication = g_ImperialismDirectPlayApplicationGuid0066f968;
  sessionDescription10.dwMaxPlayers = 7;
  sessionDescription10.lpszSessionNameA = runtimeSelectionSeed88;
}

// FUNCTION: IMPERIALISM 0x005e2cf0
BOOL TWNetSessionManager::OnEnumerateJoinableSession(const DPSESSIONDESC2* sessionDescription,
                                                     DWORD* timeout, DWORD flags) {
  (void)timeout;
  (void)flags;
  RuntimeSelectionRecord* record = new RuntimeSelectionRecord;
  record->providerGuid = sessionDescription->guidInstance;
  record->label = sessionDescription->lpszSessionNameA;
  int index = g_WNetSerializedPtrArrayB006a5f28.GetSize();
  g_WNetSerializedPtrArrayB006a5f28.SetSize(index + 1, -1);
  g_WNetSerializedPtrArrayB006a5f28[index] = record;
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x005e2f60
BOOL TWNetSessionManager::OnEnumerateServiceProvider(LPGUID providerGuid, LPSTR providerName,
                                                     DWORD majorVersion, DWORD minorVersion) {
  (void)majorVersion;
  (void)minorVersion;

  if (memcmp(providerGuid, &DPSPGUID_MODEM, sizeof(GUID)) != 0 &&
      memcmp(providerGuid, &DPSPGUID_SERIAL, sizeof(GUID)) != 0) {
    RuntimeSelectionRecord* record = new RuntimeSelectionRecord;
    record->providerGuid = *providerGuid;
    record->label = providerName;

    int index = g_WNetSerializedPtrArrayA006a5f10.GetSize();
    g_WNetSerializedPtrArrayA006a5f10.SetSize(index + 1, -1);
    g_WNetSerializedPtrArrayA006a5f10[index] = record;

    TRadioText* item =
        activeProtocolControlB0->AddItem(kControlTagPro0 + index, index, record->label, 0xf, -1);
    ApplyUiTextStyleAndThemeFlags(item, 0, 0xc, 0x2b6b, 0x2b6c);
  }
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x005e30c0
BOOL TWNetSessionManager::ShowJoinGameSelectionDialogAndCaptureChoice(GUID* selectedSessionGuid) {
  if (g_WNetSerializedPtrArrayB006a5f28.GetSize() < 1) {
    CString message("No games found to join.");
    g_pViewMgr->ModalMessage(message, g_ptNetworkModalMessage006a5ed8, 0, 0);
    return FALSE;
  }

  TWindow* dialog = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventMultiplayerPickGame));
  dialog->SetModality(1);
  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = kControlTagOkay; // 'okay'
  }

  CPoint placement;
  g_pViewMgr->ComputeTurnEventDialogPlacementByCode(dialog, &placement);
  dialog->Resize(placement, 0);

  TJoinSelectorDialog* selector =
      static_cast<TJoinSelectorDialog*>(dialog->ResolveControlByTag(kControlTagDialog)); // 'GOLD'
  selector->AssertValid();
  for (int index = 0; index < g_WNetSerializedPtrArrayB006a5f28.GetSize(); ++index) {
    RuntimeSelectionRecord* record = g_WNetSerializedPtrArrayB006a5f28[index];
    selector->AddJoinableGameOptionEntry(record->label, record);
  }

  TEditText* nameControl =
      static_cast<TEditText*>(selector->ResolveControlByTag(kControlTagName)); // 'name'
  nameControl->AssertValid();
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&joinGamePlayerNameA8, 0);

  int command = dialog->PoseModally();
  RuntimeSelectionRecord* selected = selector->GetSelectedJoinableGame();
  if (command == kControlTagOkay) {
    *selectedSessionGuid = selected->providerGuid;
    nameControl->GetCurrentText(&joinGamePlayerNameA8);
  }

  for (int cleanupIndex = 0; cleanupIndex < g_WNetSerializedPtrArrayB006a5f28.GetSize();
       ++cleanupIndex) {
    delete g_WNetSerializedPtrArrayB006a5f28[cleanupIndex];
  }
  g_WNetSerializedPtrArrayB006a5f28.RemoveAll();
  dialog->Close();
  dialog->Free();
  return command == kControlTagOkay;
}

// FUNCTION: IMPERIALISM 0x005e3310
TWNetSessionManager::TWNetSessionManager() : TDirectPlaySessionManagerBase() {}
