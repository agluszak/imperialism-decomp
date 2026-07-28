#include "game/ui_screens/TClickZone.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x005723d0
void TClickZone::Hilite() {}
// SYNTHETIC: IMPERIALISM 0x00572350
// TClickZone::CreateObject

// SYNTHETIC: IMPERIALISM 0x005723f0
// TClickZone::GetRuntimeClass

IMPLEMENT_DYNCREATE(TClickZone, TControl)

// FUNCTION: IMPERIALISM 0x00572410
TClickZone::TClickZone() : TControl(), clickSoundId84(0x1b58) {}

// SYNTHETIC: IMPERIALISM 0x00572440
// TClickZone::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00572470
TClickZone::~TClickZone() {}

// FUNCTION: IMPERIALISM 0x00572490
void TClickZone::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  g_pSfxPlaybackSystem->PlaySoundEffect(clickSoundId84, 0, 1);
  TControl::DoMouseCommand(point, event, origin);
}
