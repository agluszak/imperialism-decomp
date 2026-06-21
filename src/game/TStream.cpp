#include "game/TStream.h"

// MFC-style serialization foundation: compiled favor-size in the original.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

// ---------------------------------------------------------------------------
// Placeholder defaults (honest empty bodies; real shared/primitive bodies are
// ported in a follow-up). These make TStream concrete so the typed accessors
// below — and the concrete stream subclasses — can be instantiated.
// ---------------------------------------------------------------------------
TStream::~TStream() {}

// FUNCTION: IMPERIALISM 0x00488a80
char TStream::streamSlot38() {
  return streamSlot28() >= streamSlot30();
}

// FUNCTION: IMPERIALISM 0x00488ab0
void TStream::Free() {} // slot 0x1c override
int TStream::streamSlot28() {
  return 0;
} // TODO
void TStream::streamSlot2c() {} // TODO
int TStream::streamSlot30() {
  return 0;
} // TODO
void TStream::streamSlot34() {}        // TODO
void TStream::ReadBytes(void*, int) {} // TODO: primitive (subclass overrides)

// FUNCTION: IMPERIALISM 0x00488b60
int TStream::ReadInteger() {
  return 0;
} // TODO: 0x00488b60

// FUNCTION: IMPERIALISM 0x00488b90
void TStream::streamSlot44() {} // TODO: 0x00488b90

// FUNCTION: IMPERIALISM 0x00488bc0
void TStream::streamSlot48(void* out) {
  *reinterpret_cast<short*>(out) = 0;
  ReadBytes(reinterpret_cast<char*>(out) + 1, 1);
}

// FUNCTION: IMPERIALISM 0x00488bf0
short TStream::ReadShort() {
  return 0;
} // TODO: 0x00488bf0

// FUNCTION: IMPERIALISM 0x00488c20
int TStream::streamSlot50() {
  int value;
  ReadBytes(&value, 4);
  return value;
}

// FUNCTION: IMPERIALISM 0x00488ca0
void TStream::streamSlot6c() {} // TODO: 0x00488ca0
void TStream::streamSlot70() {} // TODO: 0x00489360

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

// FUNCTION: IMPERIALISM 0x00488dd0
void TStream::streamSlot74() {}               // TODO: 0x00488dd0
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
void TStream::streamSlotA8() {} // TODO
void TStream::streamSlotAc(void* sharedString) {
  (void)sharedString;
} // TODO: writes a CString/shared-string ref to the stream
char TStream::ReadByte(void*) {
  return 0;
} // TODO: primitive 0x004892f0

void TStream::WriteObjectSlotB4(void*, int) {} // TODO: primitive (subclass overrides)

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
