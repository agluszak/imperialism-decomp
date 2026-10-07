#pragma once

#include "compat.h"

#include "game/TFileBasedDocument.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c170
class TAmbitFileBasedDocument : public TFileBasedDocument {
public:
  DECLARE_DYNCREATE(TAmbitFileBasedDocument)
  virtual ~TAmbitFileBasedDocument() override;
  virtual void DoRead(ArchiveStreamAdapter* file, unsigned char flags) override;
  virtual void DoWrite(ArchiveStreamAdapter* file, unsigned char flags) override;
  virtual void IAmbitDocument(ArchiveStreamAdapter* file, unsigned long documentKind);
  virtual void DoMakeViews(unsigned char flags);
  virtual void SaveDocument(long saveMode);

  TAmbitFileBasedDocument();
};
ASSERT_SIZE(TAmbitFileBasedDocument, 0x4);
