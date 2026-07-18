#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class ArchiveStreamAdapter;

// VTABLE: IMPERIALISM 0x00648a60
class TDocument : public TObject {
public:
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
  // Both base slots are 3-byte `RET 0x8` no-ops: 2 stack dwords, not 1. The caller
  // (CAmbitDocument::Serialize) pushes (adapter, 0), so the second dword is a constant
  // flag the base ignores. Arity corrected against RET-imm evidence.
  virtual undefined OrphanRetStub_00486530(ArchiveStreamAdapter* stream,
                                           int flag); // slot 0x0a 0x486530
  virtual undefined OrphanRetStub_00486550(ArchiveStreamAdapter* stream,
                                           int flag); // slot 0x0b 0x486550

  TDocument();
};
