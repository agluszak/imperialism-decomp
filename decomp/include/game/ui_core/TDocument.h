#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

class ArchiveStreamAdapter;

// VTABLE: IMPERIALISM 0x00648a60
class TDocument : public TObject {
public:
  DECLARE_DYNCREATE(TDocument)
  // FUNCTION: IMPERIALISM 0x00486380
  virtual ~TDocument() override {}
  virtual void DoRead(ArchiveStreamAdapter* file, unsigned char flags);
  virtual void DoWrite(ArchiveStreamAdapter* file, unsigned char flags);

  // NOOP: verified empty in original 0x00486322
  TDocument() {}
};
ASSERT_SIZE(TDocument, 0x4);
