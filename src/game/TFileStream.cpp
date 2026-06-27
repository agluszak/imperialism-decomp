#include "game/TFileStream.h"
#include "game/ArchiveStreamAdapter.h"
#include "game/GameAssert.h"
#include "game/mfc.h"
#include "game/CString.h"
#include "game/ui_invalidation_guard.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

typedef void* hwnd_t;

extern "C" {
char g_pClassDescTFileStream = 0;
}

// Nil-pointer assert: pop a message box, then forward to the game's assert
// reporter with the source path and line.
static __inline void FailNilPointer(int line) {
  GAME_FAIL_NIL_POINTER();
  TemporarilyClearAndRestoreUiInvalidationFlag();
}

// The backing pointer is an ArchiveStreamAdapter whose archive field holds the
// CArchive that actually moves bytes.
static __inline CArchive* BackingArchive(ArchiveStreamAdapter* backingArchiveOrStream) {
  return backingArchiveOrStream->archive;
}
IMPLEMENT_DYNCREATE(TFileStream, TStream)

// FUNCTION: IMPERIALISM 0x00489110
TFileStream::TFileStream() {
  backingArchiveOrStream = 0;
}

// Destructors are compiler-generated (implicit) from real TStream inheritance.

// SYNTHETIC: IMPERIALISM 0x00489130
// TFileStream::`scalar deleting destructor'
TFileStream::~TFileStream() {}

// FUNCTION: IMPERIALISM 0x00489160
void TFileStream::SetBackingArchive(ArchiveStreamAdapter* backingArchive) {
  backingArchiveOrStream = backingArchive;
}

// FUNCTION: IMPERIALISM 0x00489180
int TFileStream::streamSlot28() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004891a0
int TFileStream::streamSlot30() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004891c0
void TFileStream::streamSlot2c() {}

// FUNCTION: IMPERIALISM 0x004891f0
void TFileStream::streamSlot34() {}

// FUNCTION: IMPERIALISM 0x00489220
void TFileStream::ReadBytes(void* destination, int requestedCount) {
  if (this->backingArchiveOrStream == 0) {
    FailNilPointer(0x3cc);
  }
  BackingArchive(this->backingArchiveOrStream)
      ->Read(destination, static_cast<unsigned int>(requestedCount));
}

// FUNCTION: IMPERIALISM 0x00489290
void TFileStream::WriteBytesSlot78(void* source, int byteCount) {
  if (this->backingArchiveOrStream == 0) {
    FailNilPointer(0x410);
  }
  BackingArchive(this->backingArchiveOrStream)->Write(source, static_cast<unsigned int>(byteCount));
}

// FUNCTION: IMPERIALISM 0x00489300
char TFileStream::ReadByte(void* outObject) {
  *reinterpret_cast<void**>(outObject) = BackingArchive(this->backingArchiveOrStream)
                                             ->ReadObject(static_cast<const CRuntimeClass*>(0));
  return 1;
}

// FUNCTION: IMPERIALISM 0x00489330
void TFileStream::WriteObjectSlotB4(void* objectRef, int flag) {
  (void)flag;
  BackingArchive(this->backingArchiveOrStream)->WriteObject(static_cast<const CObject*>(objectRef));
}

// FUNCTION: IMPERIALISM 0x00489360
void TFileStream::streamSlot70() {}

// FUNCTION: IMPERIALISM 0x00489390
void TFileStream::streamSlotAc(CString* sharedString) {
  (void)sharedString;
}
