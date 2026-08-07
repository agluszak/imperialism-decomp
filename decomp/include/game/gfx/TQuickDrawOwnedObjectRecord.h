#pragma once

#include "game/mfc.h"

// ABI model for the dead out-of-line destructor at 0x00498f10. The listing proves
// one nullable polymorphic CObject owner at +0x1c; no constructor, callers, or additional
// fields survive in the retail image, so the unknown prefix remains explicitly opaque.
class TQuickDrawOwnedObjectRecord {
public:
  ~TQuickDrawOwnedObjectRecord();

  unsigned char m_unknown00[0x1c];
  CObject* m_ownedObject1c;
};

ASSERT_SIZE(TQuickDrawOwnedObjectRecord, 0x20);
