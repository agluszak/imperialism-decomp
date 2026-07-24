#pragma once

#include "compat.h"

#include "game/ui_core/TDocument.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00648aa0
class TFileBasedDocument : public TDocument {
public:
  DECLARE_DYNCREATE(TFileBasedDocument)
  virtual ~TFileBasedDocument() override; // slot 0x01 (scalar deleting destructor)

  TFileBasedDocument();
};
ASSERT_SIZE(TFileBasedDocument, 0x4);
