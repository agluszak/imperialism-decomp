#include "game/TSortedList.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
CRuntimeClass g_pClassDescTSortedList = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x00487a90
TSortedList* TSortedList::CreateTSortedListInstance() {
  return new TSortedList();
}

// FUNCTION: IMPERIALISM 0x00487b10
CRuntimeClass* TSortedList::GetRuntimeClass() const {
  return &g_pClassDescTSortedList;
}

// Destructor is compiler-generated (implicit) from real TPtrList inheritance.
// SYNTHETIC: IMPERIALISM 0x004888f0
// TSortedList::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

// Real default constructor: the TObject/TPtrList bases set their vptrs and construct the
// embedded CPtrList (default block size 10); TSortedList then stamps its own vptr. Replaces
// the inline no-op ctor and the fake __fastcall sentinel-init bridge in TGreatPower.cpp.
// This out-of-line copy is FPO (no ebp frame) like the original.
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
// FUNCTION: IMPERIALISM 0x004a8640
TSortedList::TSortedList() {}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
