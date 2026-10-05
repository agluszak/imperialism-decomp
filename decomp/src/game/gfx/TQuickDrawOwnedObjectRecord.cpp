#include "game/gfx/TQuickDrawOwnedObjectRecord.h"

TQuickDrawOwnedObjectRecord::~TQuickDrawOwnedObjectRecord() {
  delete m_ownedObject;
}
