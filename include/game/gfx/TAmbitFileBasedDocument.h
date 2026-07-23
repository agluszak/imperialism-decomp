#pragma once

#include "game/TFileBasedDocument.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c170
class TAmbitFileBasedDocument : public TFileBasedDocument {
public:
  DECLARE_DYNCREATE(TAmbitFileBasedDocument)
  virtual ~TAmbitFileBasedDocument() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoRead(ArchiveStreamAdapter* file,
                      unsigned char flags) override; // slot 0x0a 0x49e6a0
  virtual void DoWrite(ArchiveStreamAdapter* file,
                       unsigned char flags) override; // slot 0x0b 0x49eb30
  // Mac oracle identities for the three TAmbitFileBasedDocument-specific slots.
  virtual void IAmbitDocument(ArchiveStreamAdapter* file,
                              unsigned long documentKind); // slot 0x0c 0x49e660
  virtual void DoMakeViews(unsigned char flags);           // slot 0x0d 0x49e680
  virtual void SaveDocument(long saveMode);                // slot 0x0e 0x49ee70

  TAmbitFileBasedDocument();
};
