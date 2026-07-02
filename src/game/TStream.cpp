#include "game/TStream.h"
#include "game/CString.h"

extern "C" unsigned int __cdecl strlen(const char* s);
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
// Placeholder defaults (honest empty bodies; real shared/primitive bodies are
// ported in a follow-up). These make TStream concrete so the typed accessors
// below — and the concrete stream subclasses — can be instantiated.
// ---------------------------------------------------------------------------
TStream::TStream() {}
TStream::~TStream() {}

// FUNCTION: IMPERIALISM 0x00488a80
char TStream::streamSlot38() {
  return streamSlot28() >= streamSlot30();
}

// FUNCTION: IMPERIALISM 0x00488ab0
void TStream::Free() {} // slot 0x1c override

// FUNCTION: IMPERIALISM 0x00488ad0
int TStream::streamSlot28() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00488af0
int TStream::streamSlot30() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00488b10
void TStream::AssertMcAppStreamLine304() {}

// FUNCTION: IMPERIALISM 0x00488b40
void TStream::ReadBytes(void*, int) {} // slot 0x3c primitive; subclasses keep this default

// FUNCTION: IMPERIALISM 0x00488b60
int TStream::ReadInteger() {
  return 0;
} // TODO: 0x00488b60

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
void TStream::streamSlot74() {
  if ((streamSlot28() & 1) != 0) {
    char discarded;
    ReadBytes(&discarded, 1);
  }
}

// FUNCTION: IMPERIALISM 0x00488e00
void TStream::AssertMcAppStreamLine596() {}

// FUNCTION: IMPERIALISM 0x00488e30
void TStream::streamSlot2c(void*) {}

// FUNCTION: IMPERIALISM 0x00488e50
void TStream::streamSlot34(void*) {}

// FUNCTION: IMPERIALISM 0x00488e70
void TStream::WriteBytesSlot78(void*, int) {} // TODO: primitive (subclass overrides)

// FUNCTION: IMPERIALISM 0x00488e90
void TStream::streamSlot7c(unsigned char value) {
  WriteBytesSlot78(&value, 1);
}

// FUNCTION: IMPERIALISM 0x00488eb0
void TStream::streamSlot80(unsigned char value) {
  WriteBytesSlot78(&value, 1);
}

// FUNCTION: IMPERIALISM 0x00488ed0
void TStream::streamSlot84() {} // TODO: 0x00488ed0

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
void TStream::OrphanCallChain_C2_I18_00488ff0() {}

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
