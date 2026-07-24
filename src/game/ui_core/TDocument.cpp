#include "game/ui_core/TDocument.h"

// SYNTHETIC: IMPERIALISM 0x00486350
// TDocument::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00486380
TDocument::~TDocument() {}
// SYNTHETIC: IMPERIALISM 0x00486320
// TDocument::CreateObject

// SYNTHETIC: IMPERIALISM 0x004863a0
// TDocument::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDocument, TObject)

// NOOP: verified empty in original 0x00486322 (no standalone TDocument::TDocument body exists: construction is fully inlined into CreateObject 0x00486320; that address is its operator-new call site)
TDocument::TDocument() {}

// FUNCTION: IMPERIALISM 0x00486530
void TDocument::DoRead(ArchiveStreamAdapter*, unsigned char) {}

// FUNCTION: IMPERIALISM 0x00486550
void TDocument::DoWrite(ArchiveStreamAdapter*, unsigned char) {}
