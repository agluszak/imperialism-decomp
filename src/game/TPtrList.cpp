#include "game/TPtrList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
char g_pClassDescTPtrList = 0;
}

undefined4 DestructCPtrListBaseState(void);
void FreeHeapBufferIfNotNull(undefined4 ptrValue);

extern "C" {
char g_vtblCPtrList = 0;
}

// FUNCTION: IMPERIALISM 0x00601F1D
CPtrListSentinelView* CPtrListSentinelView::CPtrList(int ownerContext) {
  this->nodeCount = 0;
  this->freeNodeList = 0;
  this->tailNode = 0;
  this->headNode = 0;
  this->blockChain = 0;
  this->vftable = reinterpret_cast<void*>(&g_vtblCPtrList);
  this->blockSize = ownerContext;
  return this;
}

// FUNCTION: IMPERIALISM 0x00601F40
void* CPtrListSentinelView::DestructCPtrListAndMaybeFree(byte freeSelfFlag) {
  reinterpret_cast<void(__fastcall*)(void*)>(::DestructCPtrListBaseState)(this);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x00488510
void* TPtrList::GetTPtrListClassNamePointer() {
  return &g_pClassDescTPtrList;
}

// FUNCTION: IMPERIALISM 0x004885D0
void TPtrList::ConstructTPtrListBaseState(int ownerContext) {
  this->listState.CPtrList(ownerContext);
}

// FUNCTION: IMPERIALISM 0x004885F0
void* TPtrList::DestructTPtrListAndMaybeFree(byte freeSelfFlag, int, int) {
  return this->listState.DestructCPtrListAndMaybeFree(freeSelfFlag);
}
