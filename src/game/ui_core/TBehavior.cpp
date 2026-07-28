#include "game/ui_core/TBehavior.h"
#include "game/ui_tags_common.h"

#include "game/ui_core/TEventHandler.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x00487180
// TBehavior::CreateObject

// SYNTHETIC: IMPERIALISM 0x004871c0
// TBehavior::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBehavior, TObject)

// FUNCTION: IMPERIALISM 0x004871e0
TBehavior::TBehavior() : TObject(), behaviorTag(kControlTagSpSpSpSp), owner(0), enabled(1) {}

// SYNTHETIC: IMPERIALISM 0x00487210
// TBehavior::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00487240
TBehavior::~TBehavior() {}

// FUNCTION: IMPERIALISM 0x00487260
void TBehavior::SetBehaviorTag(unsigned long tag) {
  behaviorTag = tag;
}

// FUNCTION: IMPERIALISM 0x00487280
void TBehavior::SetOwner(TEventHandler* newOwner) {
  owner = newOwner;
}

// FUNCTION: IMPERIALISM 0x004872a0
unsigned char TBehavior::IsEnabled() {
  return enabled;
}

// FUNCTION: IMPERIALISM 0x004872c0
void TBehavior::SetEnabled(unsigned char isEnabled) {
  enabled = isEnabled;
}

// FUNCTION: IMPERIALISM 0x004872e0
void TBehavior::Draw(RECT* bounds) {
  (void)bounds;
}
