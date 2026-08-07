#pragma once

#include "compat.h"

#include "game/ui_core/TDocument.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00648aa0
class TFileBasedDocument : public TDocument {
public:
  DECLARE_DYNCREATE(TFileBasedDocument)
  // FUNCTION: IMPERIALISM 0x00486420
  virtual ~TFileBasedDocument() override {} // slot 0x01 (scalar deleting destructor)

  // NOOP: verified empty in original 0x004863c2 (no standalone TFileBasedDocument::TFileBasedDocument body exists: construction is fully inlined into CreateObject 0x004863c0; that address is its operator-new call site)
  TFileBasedDocument() {}
};
ASSERT_SIZE(TFileBasedDocument, 0x4);
