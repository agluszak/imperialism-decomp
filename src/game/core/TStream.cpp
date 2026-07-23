#include <string.h>

#include "game/core/TStream.h"
#include "game/ui_screens/CString.h"
#include "game/globals/prelude.h"
#include "game/globals/core_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

#if defined(_MSC_VER)
#pragma intrinsic(strlen)
#endif

// SYNTHETIC: IMPERIALISM 0x004889a0
// TStream::CreateObject

// SYNTHETIC: IMPERIALISM 0x004889d0
// TStream::GetRuntimeClass

IMPLEMENT_DYNCREATE(TStream, TObject)

// MFC-style serialization foundation: compiled favor-size in the original.

// ---------------------------------------------------------------------------
// Genuine no-op bodies in the original (the base class is never streamed through
// directly). These make TStream concrete so the typed accessors below — and the
// concrete stream subclasses — can be instantiated.
// ---------------------------------------------------------------------------
TStream::TStream() {}
TStream::~TStream() {}

// FUNCTION: IMPERIALISM 0x00488a80
char TStream::IsAtEnd() {
  return GetPosition() >= GetLength();
}

// FUNCTION: IMPERIALISM 0x00488ab0
void TStream::Free() { // slot 0x1c override
  delete this;
}

// FUNCTION: IMPERIALISM 0x00488ad0
int TStream::GetPosition() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00488af0
int TStream::GetLength() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00488b10
int TStream::AssertMcAppStreamLine304(int) {
  if (g_streamLine304AssertGuard == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\McAppStream.cpp", 0x130);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00488b40
void TStream::ReadBytes(void*, int) {} // slot 0x3c primitive; subclasses keep this default

// Read a single byte through the ReadBytes primitive (slot 0x3c) and return it; callers
// sign-extend at the call site (identical body to streamSlot44 at a different slot).
// FUNCTION: IMPERIALISM 0x00488b60
char TStream::ReadInteger() {
  char value;
  ReadBytes(&value, 1);
  return value;
}

// Read a single byte through the ReadBytes primitive (slot 0x3c) and return it.
// FUNCTION: IMPERIALISM 0x00488b90
char TStream::streamSlot44() {
  char value;
  ReadBytes(&value, 1);
  return value;
}

// FUNCTION: IMPERIALISM 0x00488bc0
void TStream::streamSlot48(void* out) {
  *reinterpret_cast<short*>(out) = 0;
  ReadBytes(reinterpret_cast<char*>(out) + 1, 1);
}

// FUNCTION: IMPERIALISM 0x00488bf0
short TStream::ReadShort() {
  short value;
  ReadBytes(&value, 2);
  return value;
}

// FUNCTION: IMPERIALISM 0x00488c20
int TStream::streamSlot50() {
  int value;
  ReadBytes(&value, 4);
  return value;
}

// Read a length-prefixed shared string into dest: pull the length via ReadShort
// (slot 0x4c), size dest's buffer, read that many raw bytes, null-terminate, and
// release. maxLen is a caller-supplied capacity hint the base impl does not use.
// FUNCTION: IMPERIALISM 0x00488c50
void TStream::streamSlot70(CString* dest, int maxLen) {
  (void)maxLen;
  int length = this->ReadShort();
  char* buffer = dest->GetBuffer(length + 1);
  this->ReadBytes(buffer, length);
  buffer[length] = 0;
  dest->ReleaseBuffer(-1);
}

// Read a short length prefix (slot 0x4c), then that many raw bytes into buffer,
// and null-terminate. maxLen is a caller capacity hint the base impl ignores.
// FUNCTION: IMPERIALISM 0x00488ca0
void TStream::streamSlot6c(void* buffer, int maxLen) {
  (void)maxLen;
  int length = this->ReadShort();
  this->ReadBytes(buffer, length);
  static_cast<char*>(buffer)[length] = 0;
}

// FUNCTION: IMPERIALISM 0x00488ce0
void TStream::streamSlot54(void* out) {
  int tmp[2];
  ReadBytes(tmp, 8);
  reinterpret_cast<int*>(out)[0] = tmp[0];
  reinterpret_cast<int*>(out)[1] = tmp[1];
}

// FUNCTION: IMPERIALISM 0x00488d20
void TStream::streamSlot58(void* out) {
  ReadBytes(out, 8);
}

// FUNCTION: IMPERIALISM 0x00488d40
void TStream::streamSlot5c(void* out) {
  ReadBytes(out, 0x10);
}

// FUNCTION: IMPERIALISM 0x00488d60
void TStream::streamSlot60(void* out) {
  ReadBytes(out, 0x10);
}

// FUNCTION: IMPERIALISM 0x00488d80
void TStream::streamSlot64(void* out) {
  ReadBytes(out, 4);
}

// FUNCTION: IMPERIALISM 0x00488da0
int TStream::streamSlot68() {
  int value;
  ReadBytes(&value, 4);
  return value;
}

// If the guard predicate (slot 0x28) has bit 0 set, consume one byte.
// FUNCTION: IMPERIALISM 0x00488dd0
void TStream::SkipPaddingToEvenByteBoundary() {
  if ((GetPosition() & 1) != 0) {
    char discarded;
    ReadBytes(&discarded, 1);
  }
}

// FUNCTION: IMPERIALISM 0x00488e00
void TStream::AssertMcAppStreamLine596(int, int) {
  if (g_streamLine596AssertGuard == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\McAppStream.cpp", 0x254);
  }
}

// FUNCTION: IMPERIALISM 0x00488e30
void TStream::SetPosition(int) {}

// FUNCTION: IMPERIALISM 0x00488e50
void TStream::SetLength(int) {}

// FUNCTION: IMPERIALISM 0x00488e70
void TStream::WriteBytesSlot78(void*, int) {} // primitive; concrete subclass overrides

// FUNCTION: IMPERIALISM 0x00488e90
void TStream::streamSlot7c(unsigned char value) {
  WriteBytesSlot78(&value, 1);
}

// FUNCTION: IMPERIALISM 0x00488eb0
void TStream::streamSlot80(unsigned char value) {
  WriteBytesSlot78(&value, 1);
}

// Write the high byte of `value` through the WriteBytesSlot78 primitive (slot 0x78) —
// the write-side counterpart of streamSlot48's high-byte read.
// FUNCTION: IMPERIALISM 0x00488ed0
void TStream::streamSlot84(short value) {
  WriteBytesSlot78(reinterpret_cast<char*>(&value) + 1, 1);
}

// ---------------------------------------------------------------------------
// Typed read/write accessors: each delegates to a primitive vtable slot
// (ReadBytes @0x3c / WriteBytesSlot78 @0x78). Default implementations on the
// base, inherited by every concrete stream.
// ---------------------------------------------------------------------------

// FUNCTION: IMPERIALISM 0x00488ef0
void TStream::WriteCountSlot88(int count) {
  WriteBytesSlot78(&count, 2);
}

// FUNCTION: IMPERIALISM 0x00488f10
void TStream::streamSlot8c(int value) {
  WriteBytesSlot78(&value, 4);
}

// FUNCTION: IMPERIALISM 0x00488f30
void TStream::streamSlot90(double value) {
  WriteBytesSlot78(&value, 8);
}

// FUNCTION: IMPERIALISM 0x00488f50
void TStream::streamSlot94(void* data) {
  WriteBytesSlot78(data, 8);
}

// FUNCTION: IMPERIALISM 0x00488f70
void TStream::streamSlot98(void* data) {
  WriteBytesSlot78(data, 0x10);
}

// FUNCTION: IMPERIALISM 0x00488f90
void TStream::streamSlot9c(void* data) {
  WriteBytesSlot78(data, 0x10);
}

// FUNCTION: IMPERIALISM 0x00488fb0
void TStream::streamSlotA0(void* data) {
  WriteBytesSlot78(data, 4);
}

// FUNCTION: IMPERIALISM 0x00488fd0
void TStream::streamSlotA4(int value) {
  WriteBytesSlot78(&value, 4);
}

// FUNCTION: IMPERIALISM 0x00488ff0
void TStream::WritePaddingToEvenByteBoundary() {
  if ((GetPosition() & 1) != 0) {
    unsigned char padding = 0;
    WriteBytesSlot78(&padding, 1);
  }
}

// FUNCTION: IMPERIALISM 0x00489030
void TStream::streamSlotAc(CString* sharedString) {
  int length = sharedString->GetLength();
  this->WriteCountSlot88(length);
  this->WriteBytesSlot78(reinterpret_cast<void*>((char*)static_cast<LPCSTR>(*sharedString)),
                         length);
}

// FUNCTION: IMPERIALISM 0x00489070
void TStream::WriteLengthPrefixedCString(char* text) {
  unsigned int length = strlen(text);
  this->WriteCountSlot88(length);
  this->WriteBytesSlot78(text, length);
}

// FUNCTION: IMPERIALISM 0x00489980
char TStream::ReadByte(void*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004899a0
void TStream::WriteObjectSlotB4(void*, int) {}

// SYNTHETIC: IMPERIALISM 0x00488a10
// TStream::`scalar deleting destructor'
