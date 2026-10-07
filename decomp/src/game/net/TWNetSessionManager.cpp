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

// FUNCTION: IMPERIALISM 0x0047f840
BOOL FAR PASCAL ForwardDirectPlayAssertionToManager(void* arg1, void* arg2, void* arg3, void* arg4,
                                                    LPVOID context) {
  TDirectPlaySessionManagerBase* manager = static_cast<TDirectPlaySessionManagerBase*>(context);
  return manager->OnDirectPlayAssertion111(arg1, arg2, arg3, arg4);
}

// FUNCTION: IMPERIALISM 0x0047f870
static BOOL FAR PASCAL ForwardEnumSessionsToSessionManager(const DPSESSIONDESC2* sessionDescription,
                                                           DWORD* timeout, DWORD flags,
                                                           LPVOID context) {
  TDirectPlaySessionManagerBase* manager = static_cast<TDirectPlaySessionManagerBase*>(context);
  if ((flags & DPESC_TIMEDOUT) != 0) {
    return manager->ExtendEnumSessionsTimeoutWhileCtrlHeld(timeout);
  }
  return manager->OnEnumerateJoinableSession(sessionDescription, timeout, flags);
}

// FUNCTION: IMPERIALISM 0x0047f8b0
BOOL TDirectPlaySessionManagerBase::OnEnumerateServiceProvider(LPGUID providerGuid,
                                                               LPSTR providerName,
                                                               DWORD majorVersion,
                                                               DWORD minorVersion) {

  RuntimeSelectionRecord* record = new RuntimeSelectionRecord;
  record->providerGuid = *providerGuid;
  record->label = providerName;
  int index = g_RuntimeSelectionRecords.GetSize();
  g_RuntimeSelectionRecords.SetSize(index + 1, -1);
  g_RuntimeSelectionRecords[index] = record;
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x0047fb20
BOOL TDirectPlaySessionManagerBase::OnDirectPlayAssertion111(void* arg1, void* arg2, void* arg3,
                                                             void* arg4) {
  ReportAssertionFailure("D:\\Ambit\\DirectPlay.cpp", 0x6f);
  return FALSE;
}

// FUNCTION: IMPERIALISM 0x0047fb50
BOOL TDirectPlaySessionManagerBase::OnEnumerateJoinableSession(
    const DPSESSIONDESC2* sessionDescription, DWORD* timeout, DWORD flags) {
  ReportAssertionFailure("D:\\Ambit\\DirectPlay.cpp", 0x76);
  return FALSE;
}

// FUNCTION: IMPERIALISM 0x0047fb80
BOOL TDirectPlaySessionManagerBase::CreateDirectPlayLobbyAndStoreResult() {
  lastErrorCode = DirectPlayLobbyCreateA(0, &directPlayLobby, 0, 0, 0);
  return lastErrorCode >= 0;
}

// FUNCTION: IMPERIALISM 0x0047fbc0
BOOL TDirectPlaySessionManagerBase::ConnectDirectPlayFromLobbySettingsAndStoreResult() {
  DWORD settingsSize = 0;
  lastErrorCode = directPlayLobby->GetConnectionSettings(0, 0, &settingsSize);
  if (lastErrorCode != DPERR_BUFFERTOOSMALL) {
    return FALSE;
  }

  DPLCONNECTION* settings = new DPLCONNECTION;
  if (settings == 0) {
    lastErrorCode = E_OUTOFMEMORY;
    return FALSE;
  }

  lastErrorCode = directPlayLobby->GetConnectionSettings(0, settings, &settingsSize);
  if (lastErrorCode < 0 || lastErrorCode == DPERR_NOCONNECTION) {
    return FALSE;
  }
  if (GetRuntimeSelectionAuxStatus(settings) != FALSE) {
    lastErrorCode = directPlayLobby->SetConnectionSettings(0, 0, settings);
  }
  if (lastErrorCode < 0) {
    return FALSE;
  }
  lastErrorCode = directPlayLobby->Connect(0, &directPlayInterface, 0);
  return lastErrorCode >= 0;
}

// FUNCTION: IMPERIALISM 0x0047fcb0
bool TWNetSessionManager::CreatePlayerAndStoreResult(LPDPID idOut, LPSTR shortName) {
  DPNAME name;
  memset(&name, 0, sizeof(name));
  name.lpszShortNameA = shortName;
  name.dwSize = sizeof(name);
  long createResult = directPlayInterface->CreatePlayer(idOut, &name, 0, 0, 0, 0);
  lastErrorCode = createResult;
  return createResult >= 0;
}

// FUNCTION: IMPERIALISM 0x0047fd30
bool TWNetSessionManager::DestroyPlayerAndStoreResult(DWORD idPlayer) {
  long destroyResult = directPlayInterface->DestroyPlayer(idPlayer);
  lastErrorCode = destroyResult;
  return destroyResult >= 0;
}

// FUNCTION: IMPERIALISM 0x0047fd70
BOOL TDirectPlaySessionManagerBase::GetRuntimeSelectionAuxStatus(void* value) {
  return FALSE;
}

// FUNCTION: IMPERIALISM 0x0047fd90
BOOL TWNetSessionManager::RebuildRuntimeSelectionSource() {
  for (int index = 0; index < g_RuntimeSelectionRecords.GetSize(); ++index) {
    delete g_RuntimeSelectionRecords[index];
  }
  g_RuntimeSelectionRecords.RemoveAll();
  lastErrorCode = DirectPlayEnumerate(ForwardEnumSessionToCallbackTable, this);
  return lastErrorCode == 0;
}

// FUNCTION: IMPERIALISM 0x0047fe50
bool TWNetSessionManager::InitializeDirectPlayForProviderGuidOrEnumerate(const GUID* providerGuid) {
  if (providerGuid != 0) {
    if (directPlayInterface != 0) {
      directPlayInterface->Close();
      directPlayInterface->Release();
      directPlayInterface = 0;
    }
  }
  if (directPlayInterface != 0) {
    return true;
  }

  IDirectPlay* createdInterface = 0;
  GUID selectedProviderGuid;
  if (providerGuid != 0) {
    selectedProviderGuid = *providerGuid;
    lastErrorCode = DirectPlayCreate(&selectedProviderGuid, &createdInterface, 0);
  } else {
    for (int index = 0; index < g_RuntimeSelectionRecords.GetSize(); ++index) {
      delete g_RuntimeSelectionRecords[index];
    }
    g_RuntimeSelectionRecords.RemoveAll();
    g_RuntimeSelectionRecords.SetSize(0, -1);
    lastErrorCode = DirectPlayEnumerate(ForwardEnumSessionToCallbackTable, this);
    if (lastErrorCode >= 0 && SelectRuntimeProvider(&selectedProviderGuid)) {
      lastErrorCode = DirectPlayCreate(&selectedProviderGuid, &createdInterface, 0);
    } else {
      return lastErrorCode >= 0;
    }
  }

  if (lastErrorCode >= 0 && createdInterface != 0) {
    lastErrorCode = createdInterface->QueryInterface(
        IID_IDirectPlay2, reinterpret_cast<void**>(&directPlayInterface));
  }
  if (createdInterface != 0) {
    createdInterface->Release();
  }

  for (int index = 0; index < g_RuntimeSelectionRecords.GetSize(); ++index) {
    delete g_RuntimeSelectionRecords[index];
  }
  g_RuntimeSelectionRecords.RemoveAll();
  return lastErrorCode >= 0;
}

// FUNCTION: IMPERIALISM 0x00480030
BOOL TWNetSessionManager::OpenRuntimeSelectionSourceFromCurrentContext() {
  InitializeDirectPlayForProviderGuidOrEnumerate(0);
  memset(&sessionDescription, 0, sizeof(sessionDescription));
  sessionDescription.dwSize = sizeof(sessionDescription);
  sessionDescription.dwFlags = 0x40;
  InitializeSessionDescription();
  lastErrorCode = directPlayInterface->Open(&sessionDescription, DPOPEN_CREATE);
  if (lastErrorCode < 0) {
    for (int index = 0; index < g_RuntimeSelectionRecords.GetSize(); ++index) {
      delete g_RuntimeSelectionRecords[index];
    }
    g_RuntimeSelectionRecords.RemoveAll();

    if (directPlayInterface != 0) {
      directPlayInterface->Close();
      directPlayInterface->Release();
      directPlayInterface = 0;
    }
    if (directPlayLobby != 0) {
      directPlayLobby->Release();
      directPlayLobby = 0;
    }
  }
  return lastErrorCode >= 0;
}

// FUNCTION: IMPERIALISM 0x00480150
BOOL TWNetSessionManager::OpenRuntimeSelectionSourceWithUserChoice() {
  InitializeDirectPlayForProviderGuidOrEnumerate(0);

  memset(&sessionDescription, 0, sizeof(sessionDescription));
  sessionDescription.dwSize = sizeof(DPSESSIONDESC2);
  ResetSessionDescription();

  {
    TScopedWaitCursor waitCursor;
    // Holding Ctrl during discovery stretches the enumeration window from 1s to 5s.
    DWORD enumerationTimeout = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0 ? 5000 : 1000;
    lastErrorCode = directPlayInterface->EnumSessions(&sessionDescription, enumerationTimeout,
                                                      ForwardEnumSessionsToSessionManager, this,
                                                      DPENUMSESSIONS_AVAILABLE);
  }

  if (lastErrorCode >= 0) {
    GUID selectedSessionGuid;
    if (ShowJoinGameSelectionDialogAndCaptureChoice(&selectedSessionGuid) != 0) {
      memset(&sessionDescription, 0, sizeof(sessionDescription));
      sessionDescription.dwSize = sizeof(DPSESSIONDESC2);
      sessionDescription.guidInstance = selectedSessionGuid;
      lastErrorCode = directPlayInterface->Open(&sessionDescription, DPOPEN_JOIN);
      if (lastErrorCode >= 0) {
        return 1;
      }
    }
  }

  for (int index = 0; index < g_RuntimeSelectionRecords.GetSize(); ++index) {
    delete g_RuntimeSelectionRecords[index];
  }
  g_RuntimeSelectionRecords.SetSize(0, -1);

  if (directPlayInterface != 0) {
    directPlayInterface->Close();
    directPlayInterface->Release();
    directPlayInterface = 0;
  }
  if (directPlayLobby != 0) {
    directPlayLobby->Release();
    directPlayLobby = 0;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004803d0
bool TWNetSessionManager::OpenCurrentSessionDescriptionForJoin() {
  long result = directPlayInterface->Open(&sessionDescription, DPOPEN_JOIN);
  lastErrorCode = result;
  return result >= 0;
}

// FUNCTION: IMPERIALISM 0x00480400
void TDirectPlaySessionManagerBase::ResetRuntimeSelectionRecordBuffer() {
  for (int index = 0; index < g_RuntimeSelectionRecords.GetSize(); ++index) {
    delete g_RuntimeSelectionRecords[index];
  }
  g_RuntimeSelectionRecords.RemoveAll();

  if (directPlayInterface != 0) {
    directPlayInterface->Close();
    directPlayInterface->Release();
    directPlayInterface = 0;
  }
  if (directPlayLobby != 0) {
    directPlayLobby->Release();
    directPlayLobby = 0;
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
  TPickGameDialog dialog(0);
  for (int index = 0; index < g_RuntimeSelectionRecords.GetSize(); ++index) {
    RuntimeSelectionRecord* record = g_RuntimeSelectionRecords[index];
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
  ReportAssertionFailure("D:\\Ambit\\DirectPlay.cpp", 0x1b3);
  return FALSE;
}

// FUNCTION: IMPERIALISM 0x00480850
int TWNetSessionManager::TrySendNetworkPacket(int nationId, void* packet, unsigned int byteCount) {
  IDirectPlay2* directPlay = directPlayInterface;
  if (directPlay != 0) {
    long sendResult = directPlay->Send(localPlayerId, nationId, 1, packet, byteCount);
    lastErrorCode = sendResult;
    return sendResult >= 0;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004808a0
int TWNetSessionManager::TryReceiveNetworkPacketIntoResizableBuffer(DWORD* fromId, DWORD* toId,
                                                                    void** bufferHandle) {
  if (directPlayInterface == 0) {
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
    receiveResult = directPlayInterface->Receive(fromId, toId, 1, *bufferHandle, &neededSize);
    lastErrorCode = receiveResult;
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
  long setResult = directPlayInterface->SetPlayerData(localPlayerId, data, size, 2);
  lastErrorCode = setResult;
  return setResult >= 0;
}

// FUNCTION: IMPERIALISM 0x004809d0
BOOL TDirectPlaySessionManagerBase::GetPlayerData(DPID playerId, void* buffer, DWORD* sizeInOut) {
  lastErrorCode = directPlayInterface->GetPlayerData(playerId, buffer, sizeInOut, 0);
  return lastErrorCode >= 0;
}

// FUNCTION: IMPERIALISM 0x005e2900
static BOOL FAR PASCAL RecordHostPlayerIdDuringEnumeration(DPID dpId, DWORD dwPlayerType,
                                                           LPCDPNAME lpName, DWORD dwFlags,
                                                           LPVOID lpContext) {
  TDirectPlaySessionManagerBase* session = static_cast<TDirectPlaySessionManagerBase*>(lpContext);
  DWORD playerRole = 0;
  DWORD playerRoleSize = sizeof(playerRole);
  if (session->GetPlayerData(dpId, &playerRole, &playerRoleSize) == 0) {
    g_pNetMgr->HandleError(session->lastErrorCode);
    return FALSE;
  }
  if (playerRole == 1) {
    session->broadcastPlayerId = dpId;
    return FALSE;
  }
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x005e2980
BOOL TDirectPlaySessionManagerBase::FindHostPlayerIdByEnumeration() {
  broadcastPlayerId = 0;
  lastErrorCode = directPlayInterface->EnumPlayers(0, RecordHostPlayerIdDuringEnumeration, this,
                                                   DPENUMPLAYERS_REMOTE);
  return lastErrorCode >= 0 && broadcastPlayerId != 0;
}

// FUNCTION: IMPERIALISM 0x005e2a20
TWNetSessionManager::~TWNetSessionManager() {
  for (int i = 0; i < g_WNetSerializedPtrArrayB.GetSize(); ++i) {
    delete g_WNetSerializedPtrArrayB[i];
  }
  g_WNetSerializedPtrArrayB.RemoveAll();
  for (int j = 0; j < g_WNetSerializedPtrArrayA.GetSize(); ++j) {
    delete g_WNetSerializedPtrArrayA[j];
  }
  g_WNetSerializedPtrArrayA.RemoveAll();
}

// FUNCTION: IMPERIALISM 0x005e2b50
void TDirectPlaySessionManagerBase::InitializeSessionDescription() {}

// FUNCTION: IMPERIALISM 0x005e2b70
void TDirectPlaySessionManagerBase::ResetSessionDescription() {}

// FUNCTION: IMPERIALISM 0x005e2b90
TDirectPlaySessionManagerBase::~TDirectPlaySessionManagerBase() {
  ResetRuntimeSelectionRecordBuffer();
}

// FUNCTION: IMPERIALISM 0x005e2bb0
void TWNetSessionManager::ResetSessionDescription() {
  joinGamePlayerDataTag = 0;
  sessionDescription.guidApplication = g_ImperialismDirectPlayApplicationGuid;
  sessionDescription.lpszPasswordA = joinGameSeed;
  for (int index = 0; index < g_WNetSerializedPtrArrayB.GetSize(); ++index) {
    delete g_WNetSerializedPtrArrayB[index];
  }
  g_WNetSerializedPtrArrayB.RemoveAll();
}

// FUNCTION: IMPERIALISM 0x005e2c80
void TWNetSessionManager::InitializeSessionDescription() {
  joinGamePlayerDataTag = 1;
  sessionDescription.guidApplication = g_ImperialismDirectPlayApplicationGuid;
  sessionDescription.dwMaxPlayers = 7;
  sessionDescription.lpszSessionNameA = runtimeSelectionSeed;
}

// FUNCTION: IMPERIALISM 0x005e2cf0
BOOL TWNetSessionManager::OnEnumerateJoinableSession(const DPSESSIONDESC2* sessionDescription,
                                                     DWORD* timeout, DWORD flags) {
  WNetSelectionRecord* record = new WNetSelectionRecord;
  record->providerGuid = sessionDescription->guidInstance;
  record->label = sessionDescription->lpszSessionNameA;
  int index = g_WNetSerializedPtrArrayB.GetSize();
  g_WNetSerializedPtrArrayB.SetSize(index + 1, -1);
  g_WNetSerializedPtrArrayB[index] = record;
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x005e2f60
BOOL TWNetSessionManager::OnEnumerateServiceProvider(LPGUID providerGuid, LPSTR providerName,
                                                     DWORD majorVersion, DWORD minorVersion) {

  if (memcmp(providerGuid, &DPSPGUID_MODEM, sizeof(GUID)) != 0 &&
      memcmp(providerGuid, &DPSPGUID_SERIAL, sizeof(GUID)) != 0) {
    WNetSelectionRecord* record = new WNetSelectionRecord;
    record->providerGuid = *providerGuid;
    record->label = providerName;

    int index = g_WNetSerializedPtrArrayA.GetSize();
    g_WNetSerializedPtrArrayA.SetSize(index + 1, -1);
    g_WNetSerializedPtrArrayA[index] = record;

    TRadioText* item =
        activeProtocolControl->AddItem(kControlTagPro0 + index, index, record->label, 0xf, -1);
    ApplyUiTextStyleAndThemeFlags(item, 0, 0xc, 0x2b6b, 0x2b6c);
  }
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x005e30c0
BOOL TWNetSessionManager::ShowJoinGameSelectionDialogAndCaptureChoice(GUID* selectedSessionGuid) {
  if (g_WNetSerializedPtrArrayB.GetSize() < 1) {
    CString message("No games found to join.");
    g_pViewMgr->ModalMessage(message, g_ptNetworkModalMessage, 0, 0);
    return FALSE;
  }

  TWindow* dialog =
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventMultiplayerPickGame);
  dialog->SetModality(true);
  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = kControlTagOkay; // 'okay'
  }

  CPoint placement;
  g_pViewMgr->GetTopLeftFor(dialog, &placement);
  dialog->Resize(placement, false);

  TJoinSelectorDialog* selector =
      static_cast<TJoinSelectorDialog*>(dialog->FindSubView(kControlTagDialog)); // 'GOLD'
  selector->AssertValid();
  for (int index = 0; index < g_WNetSerializedPtrArrayB.GetSize(); ++index) {
    WNetSelectionRecord* record = g_WNetSerializedPtrArrayB[index];
    selector->AddJoinableGameOptionEntry(record->label, record);
  }

  TEditText* nameControl =
      static_cast<TEditText*>(selector->FindSubView(kControlTagName)); // 'name'
  nameControl->AssertValid();
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&joinGamePlayerName, 0);

  int command = dialog->PoseModally();
  WNetSelectionRecord* selected = selector->GetSelectedJoinableGame();
  if (command == kControlTagOkay) {
    *selectedSessionGuid = selected->providerGuid;
    nameControl->GetCurrentText(&joinGamePlayerName);
  }

  for (int cleanupIndex = 0; cleanupIndex < g_WNetSerializedPtrArrayB.GetSize(); ++cleanupIndex) {
    delete g_WNetSerializedPtrArrayB[cleanupIndex];
  }
  g_WNetSerializedPtrArrayB.RemoveAll();
  dialog->Close();
  dialog->Free();
  return command == kControlTagOkay;
}

// FUNCTION: IMPERIALISM 0x005e3310
TWNetSessionManager::TWNetSessionManager() : TDirectPlaySessionManagerBase() {}
