#include "game/TMultiplayerMgr.h"

#include "game/TStream.h"
#include <cstring>

// FUNCTION: IMPERIALISM 0x00542650
CRuntimeClass* TMultiplayerMgr::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00542670
TMultiplayerMgr::TMultiplayerMgr() : TEventHandler() {
  memset(field20, 0, sizeof(field20));
  field40 = 0;
  field6c = 0;
  field70 = 0;
  fieldd8 = 0x6e616461;
  fieldf4 = 0;
}

// SYNTHETIC: IMPERIALISM 0x005427e0
// TMultiplayerMgr::`scalar deleting destructor'
TMultiplayerMgr::~TMultiplayerMgr() {}

// FUNCTION: IMPERIALISM 0x00542900
undefined TMultiplayerMgr::InitializeMultiplayerManagerForSessionContext(CString param_1) {
  (void)param_1;
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
