#pragma once

#include "game/mfc.h"

class TQuickDrawOwnedObjectRecord {
public:
  ~TQuickDrawOwnedObjectRecord();

  unsigned char m_unknown[28];
  CObject* m_ownedObject;
};

ASSERT_SIZE(TQuickDrawOwnedObjectRecord, 0x20);
