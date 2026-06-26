#include "game/THelpMgr.h"

#include "game/TSortedPtrList.h"

// FUNCTION: IMPERIALISM 0x005005e0
THelpMgr::THelpMgr() : TObject() {
  field8 = 0;
  fieldC = 0;
  helpIndexReady = 0;
  field1a = 0;
  field1e = 0;
  field22 = 0;
  field26 = 0;
  field2a = 0;
  field2c = 0;
  field10 = 0;
  field14 = 0;
  field18 = 0;
  indexList = nullptr;
}

CRuntimeClass* THelpMgr::GetRuntimeClass() const { return 0; }

THelpMgr::~THelpMgr() {}

undefined THelpMgr::OrphanCallChain_C1_I22_00500f10() { return 0; }

void THelpMgr::ReadFrom(TStream* stream) { (void)stream; }

void THelpMgr::WriteTo(TStream* stream) { (void)stream; }

void THelpMgr::Free() {}

// FUNCTION: IMPERIALISM 0x00500680
undefined THelpMgr::InitializeHelpManagerIndexArrayAndState() {
  helpIndexReady = 1;
  if (indexList == nullptr) {
    indexList = new TSortedPtrList();
    if (indexList != nullptr) {
      indexList->relationType = 0xe;
    }
  }
  return 0;
}
