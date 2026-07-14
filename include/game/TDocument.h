#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class ArchiveStreamAdapter;

// VTABLE: IMPERIALISM 0x00648a60
class TDocument : public TObject {
public:
// === BEGIN GENERATED DECLS (TDocument) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TDocument)
  virtual ~TDocument() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanRetStub_00486530(ArchiveStreamAdapter* stream); // slot 0x0a 0x486530
  virtual undefined OrphanRetStub_00486550(ArchiveStreamAdapter* stream); // slot 0x0b 0x486550
// === END GENERATED DECLS (TDocument) ===

  TDocument();
};

