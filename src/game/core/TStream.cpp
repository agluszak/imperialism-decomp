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
// FUNCTION: IMPERIALISM 0x00488a40
TStream::~TStream() {}

// FUNCTION: IMPERIALISM 0x00488a80
char TStream::IsAtEnd() {
  // The original calls GetPosition (slot 0x28) before GetLength (slot 0x30) at
  // 0x00488a87/0x00488a8e. Operand evaluation order is unspecified and VC5 will emit the
  // calls the other way round unless the first result is sequenced into a local.
  int position = GetPosition();
  return position >= GetLength();
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
// sign-extend at the call site (identical body to ReadBoolean at a different slot).
// FUNCTION: IMPERIALISM 0x00488b60
char TStream::ReadByte() {
  char value;
  ReadBytes(&value, 1);
  return value;
}

// Read a single byte through the ReadBytes primitive (slot 0x3c) and return it.
// FUNCTION: IMPERIALISM 0x00488b90
char TStream::ReadBoolean() {
  char value;
  ReadBytes(&value, 1);
  return value;
}

// FUNCTION: IMPERIALISM 0x00488bc0
void TStream::ReadCharacter(short* outCharacter) {
  unsigned char* characterBytes = static_cast<unsigned char*>(static_cast<void*>(outCharacter));
  *outCharacter = 0;
  ReadBytes(characterBytes + 1, 1);
}

// FUNCTION: IMPERIALISM 0x00488bf0
short TStream::ReadInteger() {
  short value;
  ReadBytes(&value, 2);
  return value;
}

// FUNCTION: IMPERIALISM 0x00488c20
int TStream::ReadLong() {
  int value;
  ReadBytes(&value, 4);
  return value;
}

// Read a length-prefixed shared string into dest: pull the length via ReadInteger
// (slot 0x4c), size dest's buffer, read that many raw bytes, null-terminate, and
// release. maxLen is a caller-supplied capacity hint the base impl does not use.
// FUNCTION: IMPERIALISM 0x00488c50
void TStream::ReadSharedString(CString* dest, int maxLen) {
  (void)maxLen;
  int length = this->ReadInteger();
  char* buffer = dest->GetBuffer(length + 1);
  this->ReadBytes(buffer, length);
  buffer[length] = 0;
  dest->ReleaseBuffer(-1);
}

// Read a short length prefix (slot 0x4c), then that many raw bytes into buffer,
// and null-terminate. maxLen is a caller capacity hint the base impl ignores.
// FUNCTION: IMPERIALISM 0x00488ca0
void TStream::ReadString(void* buffer, int maxLen) {
  (void)maxLen;
  int length = this->ReadInteger();
  this->ReadBytes(buffer, length);
  static_cast<char*>(buffer)[length] = 0;
}

// FUNCTION: IMPERIALISM 0x00488ce0
void TStream::ReadVPoint(VPoint* outPoint) {
  VPoint point;
  ReadBytes(&point, sizeof(point));
  *outPoint = point;
}

// FUNCTION: IMPERIALISM 0x00488d20
void TStream::ReadRect(void* out) {
  ReadBytes(out, 8);
}

// FUNCTION: IMPERIALISM 0x00488d40
void TStream::ReadVRect(void* out) {
  ReadBytes(out, 0x10);
}

// FUNCTION: IMPERIALISM 0x00488d60
void TStream::ReadUnclassified16ByteRecord(void* out) {
  ReadBytes(out, 0x10);
}

// FUNCTION: IMPERIALISM 0x00488d80
void TStream::ReadPoint(void* out) {
  ReadBytes(out, 4);
}

// FUNCTION: IMPERIALISM 0x00488da0
int TStream::ReadIDType() {
  int value;
  ReadBytes(&value, 4);
  return value;
}

// If the guard predicate (slot 0x28) has bit 0 set, consume one byte.
// FUNCTION: IMPERIALISM 0x00488dd0
void TStream::ReadWordAlign() {
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
void TStream::WriteBytes(const void*, int) {} // primitive; concrete subclass overrides

// FUNCTION: IMPERIALISM 0x00488e90
void TStream::WriteByte(unsigned char value) {
  WriteBytes(&value, 1);
}

// FUNCTION: IMPERIALISM 0x00488eb0
void TStream::WriteBoolean(unsigned char value) {
  WriteBytes(&value, 1);
}

// Write the high byte of `value` through the WriteBytes primitive (slot 0x78) —
// the write-side counterpart of ReadCharacter's high-byte read.
// FUNCTION: IMPERIALISM 0x00488ed0
void TStream::WriteCharacter(short value) {
  const unsigned char* characterBytes =
      static_cast<const unsigned char*>(static_cast<const void*>(&value));
  WriteBytes(characterBytes + 1, 1);
}

// ---------------------------------------------------------------------------
// Typed read/write accessors: each delegates to a primitive vtable slot
// (ReadBytes @0x3c / WriteBytes @0x78). Default implementations on the
// base, inherited by every concrete stream.
// ---------------------------------------------------------------------------

// FUNCTION: IMPERIALISM 0x00488ef0
void TStream::WriteInteger(int count) {
  WriteBytes(&count, 2);
}

// FUNCTION: IMPERIALISM 0x00488f10
void TStream::WriteLong(int value) {
  WriteBytes(&value, 4);
}

// FUNCTION: IMPERIALISM 0x00488f30
void TStream::WriteVPoint(double value) {
  WriteBytes(&value, 8);
}

// FUNCTION: IMPERIALISM 0x00488f50
void TStream::WriteRect(void* data) {
  WriteBytes(data, 8);
}

// FUNCTION: IMPERIALISM 0x00488f70
void TStream::WriteVRect(void* data) {
  WriteBytes(data, 0x10);
}

// FUNCTION: IMPERIALISM 0x00488f90
void TStream::WriteUnclassified16ByteRecord(void* data) {
  WriteBytes(data, 0x10);
}

// FUNCTION: IMPERIALISM 0x00488fb0
void TStream::WritePoint(void* data) {
  WriteBytes(data, 4);
}

// FUNCTION: IMPERIALISM 0x00488fd0
void TStream::WriteIDType(int value) {
  WriteBytes(&value, 4);
}

// FUNCTION: IMPERIALISM 0x00488ff0
void TStream::WriteWordAlign() {
  if ((GetPosition() & 1) != 0) {
    unsigned char padding = 0;
    WriteBytes(&padding, 1);
  }
}

// FUNCTION: IMPERIALISM 0x00489030
void TStream::WriteSharedString(CString* sharedString) {
  int length = sharedString->GetLength();
  this->WriteInteger(length);
  this->WriteBytes(static_cast<LPCSTR>(*sharedString), length);
}

// FUNCTION: IMPERIALISM 0x00489070
void TStream::WriteString(char* text) {
  unsigned int length = strlen(text);
  this->WriteInteger(length);
  this->WriteBytes(text, length);
}

// FUNCTION: IMPERIALISM 0x00489980
char TStream::ReadObject(void*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004899a0
void TStream::WriteObject(void*, int) {}

// SYNTHETIC: IMPERIALISM 0x00488a10
// TStream::`scalar deleting destructor'
