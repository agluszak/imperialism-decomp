#include "game/TWNetSessionManager.h"

#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x0047f7f0
RuntimeSelectionRecord::~RuntimeSelectionRecord() {}

// FUNCTION: IMPERIALISM 0x0047f810
static BOOL FAR PASCAL ForwardEnumSessionToCallbackTable(LPGUID sessionGuid, LPSTR sessionName,
                                                          DWORD majorVersion, DWORD minorVersion,
                                                          LPVOID context) {
  TWNetSessionManager* mgr = static_cast<TWNetSessionManager*>(context);
  return mgr->enumCallbackTable00->onEnumSession(sessionGuid, sessionName, majorVersion,
                                                 minorVersion);
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

// FUNCTION: IMPERIALISM 0x0047fe50
unsigned char TWNetSessionManager::OpenRuntimeSelectionSourceWithOptionalSeed(
    const GUID* sessionEntry, int flag) {
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
  if (sessionEntry != 0) {
    GUID seededGuid = *sessionEntry;
    lastErrorCode0c = DirectPlayCreate(&seededGuid, &createdInterface, 0);
  } else {
    ClearRuntimeSelectionRecordArray();
    g_RuntimeSelectionRecords006a15e0.SetSize(0, -1);
    lastErrorCode0c = DirectPlayEnumerate(ForwardEnumSessionToCallbackTable, this);
    if (lastErrorCode0c >= 0) {
      // enumCallbackTable00 is always null in the retail binary (see its comment) --
      // this indirect call is unreached but ported to match the original shape.
      if (enumCallbackTable00->onEnumerationComplete(&createdInterface) == 0) {
        return static_cast<unsigned char>(lastErrorCode0c >= 0);
      }
    }
  }

  if (lastErrorCode0c >= 0 && createdInterface != 0) {
    lastErrorCode0c = createdInterface->QueryInterface(IID_IDirectPlay2,
                                                        reinterpret_cast<void**>(&directPlayInterface04));
  }
  if (createdInterface != 0) {
    createdInterface->Release();
  }

  ClearRuntimeSelectionRecordArray();
  return static_cast<unsigned char>(lastErrorCode0c >= 0);
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
int __stdcall ApplyCtrlScrollAccelerationToListStep(int* value) {
  if ((GetAsyncKeyState(0x11) & 0x8000) != 0) {
    *value += 500;
    return 1;
  }
  return 0;
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
