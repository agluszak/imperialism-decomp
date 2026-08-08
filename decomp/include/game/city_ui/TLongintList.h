#pragma once

#include "game/mfc.h"

#include <afxtempl.h>

class TStream;

// MacApp-heritage list-of-longs facade over the MFC CList<long, long> template base
// (Mac oracle names: TLongintList::InsertLast/At/AtDelete/Delete, 1-based indexing).
// Everything structural comes from the template: the ctor observed inlined at every
// `new` site is CList's own header-inline ctor (nBlockSize = 10), the InsertLast body
// is the inlined AddTail/NewNode/ConstructElement chain, and slot 2 of the vtable is
// the CList<long, long>::Serialize instantiation (280 bytes, same as the
// CList<TView*, TView*> instantiation at 0x479be0). AssertValid stays the inherited
// CObject::AssertValid (0x412bf0); Dump is a real override that virtual-dispatches At.
// Known instances: TCountry::ownedRegionList (region ids), TMinor home-tile candidate
// lists, TSoundPlayer channel bookkeeping, TTradeMgr rows, TPageView slot +0x80.
// VTABLE: IMPERIALISM 0x00650a08
class TLongintList : public CList<long, long> {
public:
  // NOOP: verified empty in original 0x004d6a5d (trivial inline ctor: the CList
  // template base ctor supplies every store, inlined at each `new` site).
  TLongintList() {}

  void Dump(CDumpContext& dc) const override; // slot 0x10 0x4c6b60

  virtual void InsertLast(long value); // slot 0x14 0x4c6740
  // Identical append body with two always-unused trailing args (same idiom as
  // TSortedList's AddTailEx); a same-named overload would be ambiguous at 1-arg call
  // sites, so it keeps the "Ex" marker until the real name is recovered.
  virtual void InsertLastEx(long value, int unused1 = 0, int unused2 = 0); // slot 0x18 0x4c67e0
  // Stream-hook no-ops: TCountry::ReadFrom (0x4d6bf0) invokes slot 0x20 with its
  // stream right before re-filling the list, so the pair reads as WriteTo/ReadFrom
  // hooks this class leaves empty.
  virtual void NoOpWriteTo(TStream* stream);  // slot 0x1c 0x487f70
  virtual void NoOpReadFrom(TStream* stream); // slot 0x20 0x487f90
  virtual long At(long oneBasedIndex);        // slot 0x24 0x4c6880
  virtual int GetSize();                      // slot 0x28 0x4c68c0
  virtual void AtDelete(long oneBasedIndex);  // slot 0x2c 0x4c68e0
  // Hides (and wraps) the non-virtual CList::RemoveAll; Free dispatches through this
  // slot in the original.
  virtual void RemoveAll();        // slot 0x30 0x4c69a0
  virtual void Delete(long value); // slot 0x34 0x4c69e0
  virtual void Free();             // slot 0x38 0x4c6bf0
};

ASSERT_SIZE(TLongintList, 0x1c);

// Mac oracle: CLongintIterator::FirstLong/NextLong. The Windows implementation is a
// three-word cursor over the CList<long, long> node chain owned by TLongintList.
class CLongintIterator {
public:
  CLongintIterator(TLongintList* list) : ownerList(list) {}

  long FirstLong();
  int More();
  long NextLong();

  POSITION nextPosition;   // +0x00
  TLongintList* ownerList; // +0x04
  long current;            // +0x08
};

ASSERT_SIZE(CLongintIterator, 0x0c);
