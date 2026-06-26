#include "game/TNetMgr.h"

#include <new>

extern "C" {
char g_pClassDescTNetMgr = 0;
}

// FUNCTION: IMPERIALISM 0x005e33c0
CRuntimeClass* TNetMgr::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTNetMgr);
}

TNetMgr::TNetMgr() : TObject() {}

// FUNCTION: IMPERIALISM 0x005e33e0
TNetMgr* TNetMgr::ConstructGlobalTurnEventQueueManager(TNetMgr* storage) {
  return new (storage) TNetMgr();
}

TNetMgr::~TNetMgr() {}

void TNetMgr::Free() {}

undefined TNetMgr::SerializeLinkedRecordListWithFreeNodePool(CArchive* param_1) {
  (void)param_1;
  return 0;
}

undefined TNetMgr::SerializeDynamicDwordPointerArrayState(CArchive* param_1) {
  (void)param_1;
  return 0;
}

undefined TNetMgr::WrapperFor_FreeHeapBufferIfNotNull_At005e4a30(byte param_1) {
  (void)param_1;
  return 0;
}

undefined TNetMgr::WrapperFor_FreeHeapBufferIfNotNull_At005e4a60(byte param_1) {
  (void)param_1;
  return 0;
}
