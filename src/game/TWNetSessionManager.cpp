#include "game/TWNetSessionManager.h"

#include "game/TRadioTextCluster.h"
#include "game/TRadioText.h"
#include "game/TC2TemplateDialog.h"
#include "game/TAssetMgr.h"
#include "game/TEditText.h"
#include "game/TJoinSelectorDialog.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
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

// FUNCTION: IMPERIALISM 0x0047fcb0
unsigned char TWNetSessionManager::CreatePlayerAndStoreResult(LPDPID idOut, LPSTR shortName) {
  DPNAME name;
  name.dwSize = sizeof(DPNAME);
  name.dwFlags = 0;
  name.lpszShortNameA = shortName;
  name.lpszLongNameA = 0;
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
unsigned char TWNetSessionManager::RebuildRuntimeSelectionSource() {
  for (int index = 0; index < g_RuntimeSelectionRecords006a15e0.GetSize(); ++index) {
    delete g_RuntimeSelectionRecords006a15e0[index];
  }
  g_RuntimeSelectionRecords006a15e0.RemoveAll();
  lastErrorCode0c = DirectPlayEnumerate(ForwardEnumSessionToCallbackTable, this);
  return static_cast<unsigned char>(lastErrorCode0c == 0);
}

// FUNCTION: IMPERIALISM 0x0047fe50
unsigned char
TWNetSessionManager::OpenRuntimeSelectionSourceWithOptionalSeed(const GUID* sessionEntry,
                                                                int flag) {
  (void)flag;
  if (sessionEntry != 0) {
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
  GUID selectedGuid;
  if (sessionEntry != 0) {
    selectedGuid = *sessionEntry;
    lastErrorCode0c = DirectPlayCreate(&selectedGuid, &createdInterface, 0);
  } else {
    ClearRuntimeSelectionRecordArray();
    g_RuntimeSelectionRecords006a15e0.SetSize(0, -1);
    lastErrorCode0c = DirectPlayEnumerate(ForwardEnumSessionToCallbackTable, this);
    if (lastErrorCode0c >= 0 && SelectRuntimeProvider(&selectedGuid)) {
      lastErrorCode0c = DirectPlayCreate(&selectedGuid, &createdInterface, 0);
    } else {
      return static_cast<unsigned char>(lastErrorCode0c >= 0);
    }
  }

  if (lastErrorCode0c >= 0 && createdInterface != 0) {
    lastErrorCode0c = createdInterface->QueryInterface(
        IID_IDirectPlay2, reinterpret_cast<void**>(&directPlayInterface04));
  }
  if (createdInterface != 0) {
    createdInterface->Release();
  }

  ClearRuntimeSelectionRecordArray();
  return static_cast<unsigned char>(lastErrorCode0c >= 0);
}

// FUNCTION: IMPERIALISM 0x00480030
unsigned char TWNetSessionManager::OpenRuntimeSelectionSourceFromCurrentContext() {
  OpenRuntimeSelectionSourceWithOptionalSeed(0, 0);
  memset(&sessionDescription10, 0, sizeof(sessionDescription10));
  sessionDescription10.dwSize = sizeof(sessionDescription10);
  sessionDescription10.dwFlags = 0x40;
  InitializeSessionDescription();
  lastErrorCode0c = directPlayInterface04->Open(&sessionDescription10, DPOPEN_CREATE);
  if (lastErrorCode0c < 0) {
    ResetRuntimeSelectionRecordBuffer();
  }
  return static_cast<unsigned char>(lastErrorCode0c >= 0);
}

// FUNCTION: IMPERIALISM 0x00480150
unsigned char TWNetSessionManager::OpenRuntimeSelectionSourceWithUserChoice() {
  // TODO(class-recovery): the retail body drives the remaining recovered virtual slots plus
  // AfxGetMainWnd()-backed message-box
  // progress UI and IDirectPlay2::EnumSessions. Ported as an honest stub rather
  // than guessed until that table's owner is recovered.
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
BOOL TDirectPlaySessionManagerBase::ApplyCtrlScrollAcceleration(int* value) {
  if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0) {
    *value += 500;
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
  if (directPlay == 0) {
    return 0;
  }
  long sendResult = directPlay->Send(this->localPlayerId60, nationId, 1, packet, byteCount);
  this->lastErrorCode0c = sendResult;
  return sendResult >= 0;
}

// Pulls the next pending DirectPlay message into *bufferHandle, growing the GlobalAlloc
// buffer until IDirectPlay2::Receive stops reporting DPERR_BUFFERTOOSMALL.
// DPERR_NOMESSAGES ends the loop without a message.
// FUNCTION: IMPERIALISM 0x004808a0
int TWNetSessionManager::TryReceiveNetworkPacketIntoResizableBuffer(DWORD* fromId, DWORD* toId,
                                                                    void** bufferHandle) {
  IDirectPlay2* directPlay = this->directPlayInterface04;
  if (directPlay == 0) {
    return 1;
  }
  *bufferHandle = 0;
  DWORD neededSize = 0;
  long receiveResult;
  do {
    if (neededSize != 0) {
      HGLOBAL grownBuffer;
      if (*bufferHandle == 0) {
        grownBuffer = GlobalAlloc(0, neededSize);
      } else {
        grownBuffer = GlobalReAlloc(*bufferHandle, neededSize, 0);
      }
      *bufferHandle = grownBuffer;
    }
    receiveResult = directPlay->Receive(fromId, toId, 1, *bufferHandle, &neededSize);
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
unsigned char TWNetSessionManager::SetLocalPlayerDataAndStoreResult(LPVOID data, DWORD size) {
  long setResult = directPlayInterface04->SetPlayerData(localPlayerId60, data, size, DPSET_LOCAL);
  lastErrorCode0c = setResult;
  return setResult >= 0;
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
        activeProtocolControlB0->AddItem(0x70726f30 + index, index, record->label, 0xf, -1);
    ApplyUiTextStyleAndThemeFlags(item, 0, 0xc, 0x2b6b, 0x2b6c);
  }
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x005e30c0
BOOL TWNetSessionManager::ShowJoinGameSelectionDialogAndCaptureChoice(GUID* selectedSessionGuid) {
  if (g_WNetSerializedPtrArrayB006a5f28.GetSize() < 1) {
    CString message("No games found to join.");
    g_pUiRuntimeContext->ModalMessage(message, g_ptNetworkModalMessage006a5ed8, 0, 0);
    return FALSE;
  }

  TWindow* dialog = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventMultiplayerPickGame));
  dialog->SetModality(1);
  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = 0x6f6b6179; // 'okay'
  }

  POINT placement;
  g_pUiRuntimeContext->ComputeTurnEventDialogPlacementByCode(dialog, &placement);
  dialog->CaptureLayout((int*)&placement, 0);

  TJoinSelectorDialog* selector =
      static_cast<TJoinSelectorDialog*>(dialog->ResolveControlByTag(0x444c4f47)); // 'GOLD'
  selector->AssertValid();
  for (int index = 0; index < g_WNetSerializedPtrArrayB006a5f28.GetSize(); ++index) {
    RuntimeSelectionRecord* record = g_WNetSerializedPtrArrayB006a5f28[index];
    selector->AddJoinableGameOptionEntry(record->label, record);
  }

  TEditText* nameControl =
      static_cast<TEditText*>(selector->ResolveControlByTag(0x6e616d65)); // 'name'
  nameControl->AssertValid();
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&joinGamePlayerNameA8, 0);

  int command = dialog->PoseModally();
  RuntimeSelectionRecord* selected = selector->GetSelectedJoinableGame();
  if (command == 0x6f6b6179) {
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
  return command == 0x6f6b6179;
}

// FUNCTION: IMPERIALISM 0x005e3310
TWNetSessionManager::TWNetSessionManager() : TDirectPlaySessionManagerBase() {}
