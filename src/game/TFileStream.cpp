#include "game/TFileStream.h"
#include "game/GameAssert.h"
#include "game/CString.h"

#include "game/generated/vcall_facades.h"

extern "C" unsigned int __cdecl strlen(const char* s);
#if defined(_MSC_VER)
#pragma intrinsic(strlen)
#pragma optimize("y", on)
#endif

typedef void* hwnd_t;

undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);

extern "C" {
char g_pClassDescTFileStream = 0;
}

// Nil-pointer assert: pop a message box, then forward to the game's assert
// reporter with the source path and line.
static __inline void FailNilPointer(int line) {
  GAME_FAIL_NIL_POINTER();
  reinterpret_cast<void(__cdecl*)(const char*, int)>(
      thunk_TemporarilyClearAndRestoreUiInvalidationFlag)("D:\\Ambit\\McAppStream.cpp", line);
}

// The backing pointer references a wrapper object whose +4 field holds the
// CArchive that actually moves bytes.
static __inline CArchive* BackingArchive(void* backingArchiveOrStream) {
  return *reinterpret_cast<CArchive**>(reinterpret_cast<char*>(backingArchiveOrStream) + 4);
}

// FUNCTION: IMPERIALISM 0x00489030
void TFileStream::WriteCString(const CString& text) {
  int length = reinterpret_cast<SharedStringHeader*>(text.data_ptr - sizeof(SharedStringHeader))
                   ->text_length;
  this->WriteCountSlot88(length);
  this->WriteBytesSlot78(reinterpret_cast<void*>(text.data_ptr), length);
}

// FUNCTION: IMPERIALISM 0x00489070
void TFileStream::WriteLengthPrefixedCString(char* text) {
  unsigned int length = strlen(text);
  this->WriteCountSlot88(length);
  this->WriteBytesSlot78(text, length);
}

// FUNCTION: IMPERIALISM 0x004890f0
CRuntimeClass* TFileStream::GetRuntimeClass() {
  return reinterpret_cast<CRuntimeClass*>(&g_pClassDescTFileStream);
}

// FUNCTION: IMPERIALISM 0x00489110
TFileStream::TFileStream() {
  backingArchiveOrStream = 0;
}

// Destructors are compiler-generated (implicit) from real TStream inheritance.
// SYNTHETIC: IMPERIALISM 0x00489130
// TFileStream::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00489160
void TFileStream::SetBackingArchive(void* backingArchive) {
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
      ->ReadBytesFromSerializedBuffer(destination, static_cast<unsigned int>(requestedCount));
}

// FUNCTION: IMPERIALISM 0x00489290
void TFileStream::WriteBytesSlot78(void* source, int byteCount) {
  if (this->backingArchiveOrStream == 0) {
    FailNilPointer(0x410);
  }
  BackingArchive(this->backingArchiveOrStream)
      ->WriteBytesToSerializedBuffer(source, static_cast<unsigned int>(byteCount));
}

// FUNCTION: IMPERIALISM 0x00489300
char TFileStream::ReadObjectFromBackingArchive(void* outObject) {
  *reinterpret_cast<void**>(outObject) =
      BackingArchive(this->backingArchiveOrStream)->ReadObject(0);
  return 1;
}

// FUNCTION: IMPERIALISM 0x00489330
void TFileStream::WriteObjectToBackingArchive(void* objectRef) {
  BackingArchive(this->backingArchiveOrStream)->WriteObject(objectRef);
}

// FUNCTION: IMPERIALISM 0x00489360
void TFileStream::streamSlot70() {}
