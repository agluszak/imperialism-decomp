#include "game/TLongintList.h"

#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x00487f70
void TLongintList::NoOpWriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00487f90
void TLongintList::NoOpReadFrom(TStream* stream) {
  (void)stream;
}

// SYNTHETIC: IMPERIALISM 0x004bec10
// TLongintList::`scalar deleting destructor'

// Compiler-emitted copies of the CList<long,long> base destructor. The 0x650a50
// table is this template base, not a standalone linked-block state class.
// TEMPLATE: IMPERIALISM 0x004bec40
// ??1?$CList@JJ@@UAE@XZ

// TEMPLATE: IMPERIALISM 0x004c6ad0
// ??1?$CList@JJ@@UAE@XZ

// The CList<long,long> base's compiler-emitted Serialize instantiation (this class
// does not override Serialize; the vtable slot points at the template body).
// TEMPLATE: IMPERIALISM 0x004c65d0
// ?Serialize@?$CList@JJ@@UAEXAAVCArchive@@@Z

// FUNCTION: IMPERIALISM 0x004c6740
void TLongintList::InsertLast(long value) {
  AddTail(value);
}

// FUNCTION: IMPERIALISM 0x004c67e0
void TLongintList::InsertLastEx(long value, int unused1, int unused2) {
  (void)unused1;
  (void)unused2;
  AddTail(value);
}

// FUNCTION: IMPERIALISM 0x004c6880
long TLongintList::At(long oneBasedIndex) {
  // Out of range FindIndex returns null and GetAt dereferences it, exactly like the
  // original (assert stripped).
  return GetAt(FindIndex(oneBasedIndex - 1));
}

// FUNCTION: IMPERIALISM 0x004c68c0
int TLongintList::GetSize() {
  return GetCount();
}

// FUNCTION: IMPERIALISM 0x004c68e0
void TLongintList::AtDelete(long oneBasedIndex) {
  RemoveAt(FindIndex(oneBasedIndex - 1));
}

// FUNCTION: IMPERIALISM 0x004c69a0
void TLongintList::RemoveAll() {
  CList<long, long>::RemoveAll();
}

// FUNCTION: IMPERIALISM 0x004c69e0
void TLongintList::Delete(long value) {
  POSITION position = Find(value);
  if (position != 0) {
    RemoveAt(position);
  }
}

// FUNCTION: IMPERIALISM 0x004c6b60
void TLongintList::Dump(CDumpContext& dc) const {
  dc << "\n";
  TLongintList* self = const_cast<TLongintList*>(this);
  long ordinal;
  for (ordinal = 1; ordinal <= GetCount(); ++ordinal) {
    dc << static_cast<unsigned long>(ordinal) << s_szSpaceSeparator_00695794
       << static_cast<unsigned int>(self->At(ordinal)) << "\n";
  }
}

// FUNCTION: IMPERIALISM 0x004c6bf0
void TLongintList::Free() {
  RemoveAll();
  delete this;
}
