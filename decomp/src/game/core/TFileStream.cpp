#include "game/core/TFileStream.h"
#include "game/ArchiveStreamAdapter.h"
#include "game/GameAssert.h"
#include "game/mfc.h"
#include "game/core/CString.h"
#include "game/gfx/ui_invalidation_guard.h"

typedef void* hwnd_t;

static CArchive* BackingArchive(ArchiveStreamAdapter* backingArchiveOrStream) {
  return backingArchiveOrStream->archive;
}

IMPLEMENT_DYNCREATE(TFileStream, TStream)

// FUNCTION: IMPERIALISM 0x00489110
TFileStream::TFileStream() {
  backingArchiveOrStream = 0;
}

// NOOP: verified empty in original 0x00489133
TFileStream::~TFileStream() {}

// FUNCTION: IMPERIALISM 0x00489160
void TFileStream::IFileStream(ArchiveStreamAdapter* backingArchive) {
  backingArchiveOrStream = backingArchive;
}

// FUNCTION: IMPERIALISM 0x00489180
int TFileStream::GetPosition() {
  return BackingArchive(backingArchiveOrStream)->GetFile()->GetPosition();
}

// FUNCTION: IMPERIALISM 0x004891a0
int TFileStream::GetLength() {
  return BackingArchive(backingArchiveOrStream)->GetFile()->GetLength();
}

// FUNCTION: IMPERIALISM 0x004891c0
void TFileStream::SetPosition(int position) {
  BackingArchive(backingArchiveOrStream)->GetFile()->Seek(position, CFile::begin);
}

// FUNCTION: IMPERIALISM 0x004891f0
void TFileStream::SetLength(int length) {
  BackingArchive(backingArchiveOrStream)->GetFile()->SetLength(length);
}

// FUNCTION: IMPERIALISM 0x00489220
void TFileStream::ReadBytes(void* destination, int requestedCount) {
  if (backingArchiveOrStream == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\McAppStream.cpp", 0x3cc);
  }
  BackingArchive(backingArchiveOrStream)
      ->Read(destination, static_cast<unsigned int>(requestedCount));
}

// FUNCTION: IMPERIALISM 0x00489290
void TFileStream::WriteBytes(const void* source, int byteCount) {
  if (backingArchiveOrStream == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\McAppStream.cpp", 0x410);
  }
  BackingArchive(backingArchiveOrStream)->Write(source, static_cast<unsigned int>(byteCount));
}

// FUNCTION: IMPERIALISM 0x00489300
bool TFileStream::ReadObject(void* outObject) {
  *static_cast<void**>(outObject) =
      BackingArchive(backingArchiveOrStream)->ReadObject(static_cast<const CRuntimeClass*>(0));
  return true;
}

// FUNCTION: IMPERIALISM 0x00489330
void TFileStream::WriteObject(void* objectRef, int flag) {
  BackingArchive(backingArchiveOrStream)->WriteObject(static_cast<const CObject*>(objectRef));
}

// FUNCTION: IMPERIALISM 0x00489360
void TFileStream::ReadSharedString(CString* dest, int maxLen) {
  *BackingArchive(backingArchiveOrStream) >> *dest;
}

// FUNCTION: IMPERIALISM 0x00489390
void TFileStream::WriteSharedString(CString* sharedString) {
  *BackingArchive(backingArchiveOrStream) << *sharedString;
}
