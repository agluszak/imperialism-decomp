#include "game/THandleStream.h"

extern "C" {
char g_pClassDescTHandleStream = 0;
}
// SYNTHETIC: IMPERIALISM 0x00489580
// THandleStream::CreateObject

IMPLEMENT_DYNCREATE(THandleStream, TStream)

// FUNCTION: IMPERIALISM 0x004895e0
THandleStream::THandleStream() {
  this->position = 1;
  this->currentExtent = 0;
  this->highWatermark = 0;
  this->ownsHandleOrDirty = 0;
  this->handleOrBuffer = 0;
}

// SYNTHETIC: IMPERIALISM 0x00489610
// THandleStream::`scalar deleting destructor'
THandleStream::~THandleStream() {}

// SYNTHETIC: IMPERIALISM 0x00489640
// THandleStream::~THandleStream

// FUNCTION: IMPERIALISM 0x004896a0
void THandleStream::Free() {}

// FUNCTION: IMPERIALISM 0x004896e0
int THandleStream::streamSlot28() {
  return highWatermark;
}

// FUNCTION: IMPERIALISM 0x00489700
int THandleStream::streamSlot30() {
  return handleOrBuffer;
}

// FUNCTION: IMPERIALISM 0x00489720
undefined THandleStream::OrphanLeaf_NoCall_Ins06_00489720() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00489740
void THandleStream::streamSlot2c() {}

// FUNCTION: IMPERIALISM 0x00489760
void THandleStream::streamSlot34() {}

// FUNCTION: IMPERIALISM 0x004897a0
void THandleStream::ReadBytes(void* buffer, int sizeBytes) {
  (void)buffer;
  (void)sizeBytes;
}

// FUNCTION: IMPERIALISM 0x00489810
void THandleStream::WriteBytesSlot78(void* data, int length) {
  (void)data;
  (void)length;
}
