#include "game/TNewsMgr.h"
#include "game/TInterNationEventQueueManager.h"

// SYNTHETIC: IMPERIALISM 0x0055b6a0
// TNewsMgr::`scalar deleting destructor'
TNewsMgr::~TNewsMgr() {}
// SYNTHETIC: IMPERIALISM 0x0055b670
// TNewsMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x0055b6f0
// TNewsMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNewsMgr, TObject)

TNewsMgr::TNewsMgr() {}

void TNewsMgr::Free() {}

void TNewsMgr::ReadFrom(TStream* stream) {}

void TNewsMgr::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x0055b710
void TInterNationEventQueueManager::InitializeInterNationEventQueueManager() {
  reinterpret_cast<void(__fastcall*)(void*, int)>(0x0055b710)(this, 0);
}
