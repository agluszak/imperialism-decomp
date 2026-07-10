#pragma once

#include "compat.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TStream;

// TObject-derived linked-list base (vtable 0x00648ee0).
// Base recovered from CRuntimeClass descriptor: TSortedList -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00648ee0
class TSortedList : public TObject {
public:
  DECLARE_DYNCREATE(TSortedList)

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  int GetIntByOrdinal(int ordinal);

  // Several lists store plain integer ids as payloads (ownedRegionList region ids,
  // TAutoGreatPower missionQueue stream markers); GetIntByOrdinal is the existing
  // read-side accessor. These shims confine the one int<->pointer pun.
  POSITION AddHeadInt(int value) {
    return AddHead(reinterpret_cast<void*>(value));
  }
  POSITION AddTailInt(int value) {
    return AddTail(reinterpret_cast<void*>(value));
  }
  POSITION AddTailIntEx(int value) {
    return AddTailEx(reinterpret_cast<void*>(value));
  }

  // Slots 0x28/0x2c and 0x30/0x34 can't be real C++ overloads of one name: both
  // parameters of the *Ex forms are always-unused/defaulted, so a same-named overload
  // would be ambiguous against the plain form at every 1-arg call site (confirmed by a
  // real compile error when tried). The original source must have used distinct names;
  // "Ex" marks the extra-args sibling until real evidence recovers its actual name.
  // AddHeadEx (slot 0x2c) has no manual caller yet; AddTailEx (slot 0x34) is called from
  // the *_RemoveRegionIdFromNationOwnedRegionList family (TCountry/TGreatPower/TMinor)
  // despite the "AddTail" name -- worth revisiting once that mismatch is understood.
  virtual POSITION AddHead(void* item);
  virtual POSITION AddHeadEx(void* item, int unused1 = 0, int unused2 = 0);
  virtual POSITION AddTail(void* item);
  virtual POSITION AddTailEx(void* item, int unused1 = 0, int unused2 = 0);
  // Slots 0x38 and 0x40 have IDENTICAL signatures and bodies at this base level, so they
  // can't share one overload name without evidence of a real distinction; kept numbered.
  // Confirmed callers of slot 0x38 (TCountry::Free, TCountry::ReadFrom,
  // TGreatPower::Free) always invoke it with zero args right before discarding the list
  // pointer -- possibly vestigial/dead code in the original. Slot 0x40 has no manual
  // caller yet.
  virtual POSITION AddTailSlot38(void* item = 0);
  virtual void* RemoveTail();
  virtual POSITION AddTailSlot40(void* item = 0);
  virtual void* RemoveHead();
  virtual int GetCount();
  virtual void* GetEntryByOrdinal(int ordinal = 0);
  virtual void RemoveAtOrdinal(int ordinal);
  virtual void FreePayloads();
  virtual void FreePayloadsAndDestroy();
  virtual void RemoveAll();
  virtual void SetAtOrdinal(int ordinal, void** entryPtr, int unusedFlag);
  virtual int VirtualSlot64();
  // Sorts the list with a caller-supplied comparator (evidence: both auto-deploy
  // strategies at 0x59bcf0/0x59bf20 push (&comparator, 0)).
  virtual int SortEntriesWithComparator(int(__cdecl* compare)(void*, void*), int unused = 0);
  virtual int VirtualSlot6C();
  virtual int VirtualSlot70();
  virtual int VirtualSlot74();
  virtual int VirtualSlot78();

  CPtrList listState; // +0x04

  void ConstructTSortedListBaseState(int blockSize);

  TSortedList();
};

ASSERT_SIZE(TSortedList, 0x20);
