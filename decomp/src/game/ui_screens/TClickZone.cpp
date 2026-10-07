#include "game/ui_screens/TClickZone.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x005723d0
void TClickZone::Hilite() {}

IMPLEMENT_DYNCREATE(TClickZone, TControl)

// FUNCTION: IMPERIALISM 0x00572410
TClickZone::TClickZone() : TControl(), clickSoundId(0x1b58) {}

// FUNCTION: IMPERIALISM 0x00572470
TClickZone::~TClickZone() {}

// FUNCTION: IMPERIALISM 0x00572490
void TClickZone::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  g_pSfxPlaybackSystem->PlaySoundEffect(clickSoundId, 0, 1);
  TControl::DoMouseCommand(point, event, origin);
}
