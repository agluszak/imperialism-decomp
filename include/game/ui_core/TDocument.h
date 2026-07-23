#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

class ArchiveStreamAdapter;

// VTABLE: IMPERIALISM 0x00648a60
class TDocument : public TObject {
public:
  DECLARE_DYNCREATE(TDocument)
  virtual ~TDocument() override; // slot 0x01 (scalar deleting destructor)
  // Mac oracle: TFileBasedDocument::DoRead / DoWrite. The TDocument defaults are
  // genuine no-ops; concrete file-based documents override both slots.
  virtual void DoRead(ArchiveStreamAdapter* file, unsigned char flags);  // slot 0x0a 0x486530
  virtual void DoWrite(ArchiveStreamAdapter* file, unsigned char flags); // slot 0x0b 0x486550

  TDocument();
};
