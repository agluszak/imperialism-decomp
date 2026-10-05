#pragma once

#include "game/mfc.h"

class TQuickDrawOwnedObjectRecord {
public:
  ~TQuickDrawOwnedObjectRecord();

  unsigned char m_unknown[0x1c];
  CObject* m_ownedObject;
};

ASSERT_SIZE(TQuickDrawOwnedObjectRecord, 0x20);
