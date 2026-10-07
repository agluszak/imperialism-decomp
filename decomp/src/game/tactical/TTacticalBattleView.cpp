#include "game/tactical/TTacticalBattleView.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/quickdraw_guards.h"
#include "game/tactical_ui/TTacticalToolbar.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_core/TWindow.h"

#include "game/app/TCivAnimation2.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/app/TOneTimeAnimation.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/ui_message_pump.h"

#include "game/app/TAnimation.h"
#include "game/app/TAnimator.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/map/TTacticalPlayer.h"
#include "game/tactical/TTacticalUnit.h"
#include "game/tactical/TArmyTacUnit.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TUiEvent.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/TAmbitApplication.h"

// No-op bracket hooks around the modal one-time-animation wait (retail build leaves these empty).
// FUNCTION: IMPERIALISM 0x00498c60
void BeginModalAnimationWait(void) {}

// FUNCTION: IMPERIALISM 0x00498c80
void EndModalAnimationWait(void) {}

// FUNCTION: IMPERIALISM 0x005a6940
BOOL __cdecl ClipSrcRectToBoundsAndOffsetDstRect(RECT* bounds, RECT* dstRect, RECT* srcRect) {
  if (srcRect->top < bounds->top) {
    dstRect->top += bounds->top - srcRect->top;
    srcRect->top = bounds->top;
  }
  if (bounds->bottom < srcRect->bottom) {
    dstRect->bottom += bounds->bottom - srcRect->bottom;
    srcRect->bottom = bounds->bottom;
  }
  if (srcRect->left < bounds->left) {
    dstRect->left += bounds->left - srcRect->left;
    srcRect->left = bounds->left;
  }
  if (bounds->right < srcRect->right) {
    dstRect->right += bounds->right - srcRect->right;
    srcRect->right = bounds->right;
  }
  return srcRect->left < srcRect->right && srcRect->top < srcRect->bottom;
}

// ORACLE: The retail CRT initializer table at 0x693134 invokes this table setup.
// FUNCTION: IMPERIALISM 0x005a6a20
void InitializeTacticalUnitFacingOffsetTable() {
  g_aTacticalUnitFacingOffsetTable[0][2][0].x = 2;
  g_aTacticalUnitFacingOffsetTable[0][2][1].x = 2;
  g_aTacticalUnitFacingOffsetTable[0][3][0].x = -1;
  g_aTacticalUnitFacingOffsetTable[0][3][1].x = -1;
  g_aTacticalUnitFacingOffsetTable[0][5][0].x = 6;
  g_aTacticalUnitFacingOffsetTable[0][5][1].x = 6;
  g_aTacticalUnitFacingOffsetTable[0][6][0].x = 6;
  g_aTacticalUnitFacingOffsetTable[0][6][1].x = 6;
  g_aTacticalUnitFacingOffsetTable[1][1][0].x = 6;
  g_aTacticalUnitFacingOffsetTable[0][0][0].x = 7;
  g_aTacticalUnitFacingOffsetTable[0][0][1].x = 7;
  g_aTacticalUnitFacingOffsetTable[0][4][0].x = 7;
  g_aTacticalUnitFacingOffsetTable[0][4][1].x = 7;
  g_aTacticalUnitFacingOffsetTable[1][2][0].x = 5;
  g_aTacticalUnitFacingOffsetTable[1][4][0].x = 7;
  g_aTacticalUnitFacingOffsetTable[1][5][0].x = 5;
  g_aTacticalUnitFacingOffsetTable[0][0][0].y = 18;
  g_aTacticalUnitFacingOffsetTable[0][0][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[0][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[0][1][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[0][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[0][1][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[0][2][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[0][2][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[0][3][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[0][3][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[0][4][0].y = 18;
  g_aTacticalUnitFacingOffsetTable[0][4][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[0][5][0].y = 18;
  g_aTacticalUnitFacingOffsetTable[0][5][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[0][6][0].y = 13;
  g_aTacticalUnitFacingOffsetTable[0][6][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[1][0][0].x = 5;
  g_aTacticalUnitFacingOffsetTable[1][0][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[1][0][1].x = -4;
  g_aTacticalUnitFacingOffsetTable[1][0][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[1][1][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[1][1][1].x = -9;
  g_aTacticalUnitFacingOffsetTable[1][1][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[1][2][0].y = 13;
  g_aTacticalUnitFacingOffsetTable[1][2][1].x = -11;
  g_aTacticalUnitFacingOffsetTable[1][2][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[1][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[1][3][0].y = 18;
  g_aTacticalUnitFacingOffsetTable[1][3][1].x = -12;
  g_aTacticalUnitFacingOffsetTable[1][3][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[1][4][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[1][4][1].x = -4;
  g_aTacticalUnitFacingOffsetTable[1][4][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[1][5][0].y = 10;
  g_aTacticalUnitFacingOffsetTable[1][5][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[1][5][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[1][6][0].x = 9;
  g_aTacticalUnitFacingOffsetTable[1][6][0].y = 13;
  g_aTacticalUnitFacingOffsetTable[1][6][1].x = -6;
  g_aTacticalUnitFacingOffsetTable[1][6][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[2][0][0].x = 4;
  g_aTacticalUnitFacingOffsetTable[2][0][0].y = 18;
  g_aTacticalUnitFacingOffsetTable[2][0][1].x = -2;
  g_aTacticalUnitFacingOffsetTable[2][0][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[2][1][0].x = 2;
  g_aTacticalUnitFacingOffsetTable[2][1][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[2][1][1].x = -5;
  g_aTacticalUnitFacingOffsetTable[2][1][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[2][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[2][3][0].x = -5;
  g_aTacticalUnitFacingOffsetTable[2][2][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[2][2][1].x = -7;
  g_aTacticalUnitFacingOffsetTable[2][2][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[2][3][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[2][3][1].x = -10;
  g_aTacticalUnitFacingOffsetTable[2][3][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[2][4][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[2][4][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[2][4][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[2][4][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[2][5][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[2][5][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[2][5][1].x = -4;
  g_aTacticalUnitFacingOffsetTable[2][5][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[2][6][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[2][6][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[2][6][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[2][6][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[3][0][0].x = 11;
  g_aTacticalUnitFacingOffsetTable[3][0][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[3][0][1].x = -7;
  g_aTacticalUnitFacingOffsetTable[3][0][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[3][1][0].x = 7;
  g_aTacticalUnitFacingOffsetTable[3][1][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[3][1][1].x = -9;
  g_aTacticalUnitFacingOffsetTable[3][1][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[3][2][0].x = 5;
  g_aTacticalUnitFacingOffsetTable[3][2][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[3][2][1].x = -15;
  g_aTacticalUnitFacingOffsetTable[3][2][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[3][3][0].x = 1;
  g_aTacticalUnitFacingOffsetTable[3][3][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[3][3][1].x = -15;
  g_aTacticalUnitFacingOffsetTable[3][3][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[3][4][0].x = 8;
  g_aTacticalUnitFacingOffsetTable[3][4][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[3][4][1].x = -7;
  g_aTacticalUnitFacingOffsetTable[3][4][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[3][5][0].x = 9;
  g_aTacticalUnitFacingOffsetTable[3][5][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[3][5][1].x = -8;
  g_aTacticalUnitFacingOffsetTable[3][5][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[3][6][0].x = 10;
  g_aTacticalUnitFacingOffsetTable[3][6][0].y = 11;
  g_aTacticalUnitFacingOffsetTable[3][6][1].x = -10;
  g_aTacticalUnitFacingOffsetTable[3][6][1].y = 11;
  g_aTacticalUnitFacingOffsetTable[4][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[4][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[4][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[5][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[5][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[6][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[6][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[7][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[7][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[8][0][0].x = 6;
  g_aTacticalUnitFacingOffsetTable[8][0][0].y = 19;
  g_aTacticalUnitFacingOffsetTable[8][0][1].x = 6;
  g_aTacticalUnitFacingOffsetTable[8][0][1].y = 19;
  g_aTacticalUnitFacingOffsetTable[8][1][0].x = 2;
  g_aTacticalUnitFacingOffsetTable[8][1][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[8][1][1].x = 2;
  g_aTacticalUnitFacingOffsetTable[8][1][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[8][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[8][2][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[8][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[8][2][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[8][3][0].x = -6;
  g_aTacticalUnitFacingOffsetTable[8][3][0].y = 20;
  g_aTacticalUnitFacingOffsetTable[8][3][1].x = -6;
  g_aTacticalUnitFacingOffsetTable[8][3][1].y = 20;
  g_aTacticalUnitFacingOffsetTable[8][4][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[8][4][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[8][4][1].x = 3;
  g_aTacticalUnitFacingOffsetTable[8][4][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[8][5][0].x = 5;
  g_aTacticalUnitFacingOffsetTable[8][5][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[8][5][1].x = 5;
  g_aTacticalUnitFacingOffsetTable[8][5][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[8][6][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[8][6][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[8][6][1].x = 3;
  g_aTacticalUnitFacingOffsetTable[8][6][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[9][0][0].x = 9;
  g_aTacticalUnitFacingOffsetTable[9][0][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[9][0][1].x = -2;
  g_aTacticalUnitFacingOffsetTable[9][0][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[9][1][0].x = 5;
  g_aTacticalUnitFacingOffsetTable[9][1][0].y = 14;
  g_aTacticalUnitFacingOffsetTable[9][1][1].x = -5;
  g_aTacticalUnitFacingOffsetTable[9][1][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[9][2][0].x = 6;
  g_aTacticalUnitFacingOffsetTable[9][2][0].y = 13;
  g_aTacticalUnitFacingOffsetTable[9][2][1].x = -6;
  g_aTacticalUnitFacingOffsetTable[9][2][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[9][3][0].x = 1;
  g_aTacticalUnitFacingOffsetTable[9][3][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[9][3][1].x = -8;
  g_aTacticalUnitFacingOffsetTable[9][3][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[9][4][0].x = 10;
  g_aTacticalUnitFacingOffsetTable[9][4][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[9][4][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[9][4][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[9][5][0].x = 10;
  g_aTacticalUnitFacingOffsetTable[9][5][0].y = 13;
  g_aTacticalUnitFacingOffsetTable[9][5][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[9][5][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[9][6][0].x = 9;
  g_aTacticalUnitFacingOffsetTable[9][6][0].y = 14;
  g_aTacticalUnitFacingOffsetTable[9][6][1].x = -4;
  g_aTacticalUnitFacingOffsetTable[9][6][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[10][0][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[10][0][0].y = 18;
  g_aTacticalUnitFacingOffsetTable[10][0][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[10][0][1].y = 19;
  g_aTacticalUnitFacingOffsetTable[10][1][0].x = 1;
  g_aTacticalUnitFacingOffsetTable[10][1][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[10][1][1].x = -5;
  g_aTacticalUnitFacingOffsetTable[10][1][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[10][2][0].x = -1;
  g_aTacticalUnitFacingOffsetTable[10][2][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[10][2][1].x = -8;
  g_aTacticalUnitFacingOffsetTable[10][2][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[10][3][0].x = -4;
  g_aTacticalUnitFacingOffsetTable[10][3][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[10][3][1].x = -10;
  g_aTacticalUnitFacingOffsetTable[10][3][1].y = 19;
  g_aTacticalUnitFacingOffsetTable[10][4][0].x = 4;
  g_aTacticalUnitFacingOffsetTable[10][4][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[10][4][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[10][4][1].y = 20;
  g_aTacticalUnitFacingOffsetTable[10][5][0].x = 5;
  g_aTacticalUnitFacingOffsetTable[10][5][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[10][5][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[10][5][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[10][6][0].x = 4;
  g_aTacticalUnitFacingOffsetTable[10][6][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[10][6][1].x = -4;
  g_aTacticalUnitFacingOffsetTable[10][6][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[11][0][0].x = 11;
  g_aTacticalUnitFacingOffsetTable[11][0][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[11][0][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[11][0][1].y = 19;
  g_aTacticalUnitFacingOffsetTable[11][1][0].x = 8;
  g_aTacticalUnitFacingOffsetTable[11][1][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[11][1][1].x = -7;
  g_aTacticalUnitFacingOffsetTable[11][1][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[11][2][0].x = 5;
  g_aTacticalUnitFacingOffsetTable[11][2][0].y = 14;
  g_aTacticalUnitFacingOffsetTable[11][2][1].x = -8;
  g_aTacticalUnitFacingOffsetTable[11][2][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[11][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[11][3][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[11][3][1].x = -9;
  g_aTacticalUnitFacingOffsetTable[11][3][1].y = 19;
  g_aTacticalUnitFacingOffsetTable[11][4][0].x = 7;
  g_aTacticalUnitFacingOffsetTable[11][4][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[11][4][1].x = -2;
  g_aTacticalUnitFacingOffsetTable[11][4][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[11][5][0].x = 12;
  g_aTacticalUnitFacingOffsetTable[11][5][0].y = 14;
  g_aTacticalUnitFacingOffsetTable[11][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[11][5][1].y = 14;
  g_aTacticalUnitFacingOffsetTable[11][6][0].x = 8;
  g_aTacticalUnitFacingOffsetTable[11][6][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[11][6][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[11][6][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[12][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[12][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[12][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[13][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[13][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[14][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[14][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[15][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[15][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[16][0][0].x = 4;
  g_aTacticalUnitFacingOffsetTable[16][0][0].y = 18;
  g_aTacticalUnitFacingOffsetTable[16][0][1].x = 1;
  g_aTacticalUnitFacingOffsetTable[16][0][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[16][1][0].x = 2;
  g_aTacticalUnitFacingOffsetTable[16][1][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[16][1][1].x = -2;
  g_aTacticalUnitFacingOffsetTable[16][1][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[16][2][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[16][2][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[16][2][1].x = -5;
  g_aTacticalUnitFacingOffsetTable[16][2][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[16][3][0].x = -6;
  g_aTacticalUnitFacingOffsetTable[16][3][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[16][3][1].x = -7;
  g_aTacticalUnitFacingOffsetTable[16][3][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[16][4][0].x = 6;
  g_aTacticalUnitFacingOffsetTable[16][4][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[16][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[16][4][1].y = 17;
  g_aTacticalUnitFacingOffsetTable[16][5][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[16][5][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[16][5][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[16][6][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[17][0][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[17][0][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[17][3][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[18][0][1].y = 16;
  g_aTacticalUnitFacingOffsetTable[18][1][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[18][3][0].y = 18;
  g_aTacticalUnitFacingOffsetTable[18][3][1].y = 18;
  g_aTacticalUnitFacingOffsetTable[18][4][0].y = 17;
  g_aTacticalUnitFacingOffsetTable[18][5][0].y = 16;
  g_aTacticalUnitFacingOffsetTable[16][5][1].x = 2;
  g_aTacticalUnitFacingOffsetTable[16][6][0].x = 4;
  g_aTacticalUnitFacingOffsetTable[16][6][0].y = 12;
  g_aTacticalUnitFacingOffsetTable[16][6][1].x = -1;
  g_aTacticalUnitFacingOffsetTable[17][0][0].x = 4;
  g_aTacticalUnitFacingOffsetTable[17][0][1].x = 2;
  g_aTacticalUnitFacingOffsetTable[17][1][0].x = -1;
  g_aTacticalUnitFacingOffsetTable[17][1][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[17][1][1].x = -3;
  g_aTacticalUnitFacingOffsetTable[17][1][1].y = 12;
  g_aTacticalUnitFacingOffsetTable[17][2][0].x = -4;
  g_aTacticalUnitFacingOffsetTable[17][2][0].y = 14;
  g_aTacticalUnitFacingOffsetTable[17][2][1].x = -6;
  g_aTacticalUnitFacingOffsetTable[17][2][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[17][3][0].x = -8;
  g_aTacticalUnitFacingOffsetTable[17][3][1].x = -8;
  g_aTacticalUnitFacingOffsetTable[17][3][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[17][4][0].x = 2;
  g_aTacticalUnitFacingOffsetTable[17][4][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[17][4][1].x = 3;
  g_aTacticalUnitFacingOffsetTable[17][4][1].y = 14;
  g_aTacticalUnitFacingOffsetTable[17][5][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[17][5][0].y = 14;
  g_aTacticalUnitFacingOffsetTable[17][5][1].x = -2;
  g_aTacticalUnitFacingOffsetTable[17][5][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[17][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[17][6][0].y = 13;
  g_aTacticalUnitFacingOffsetTable[17][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[17][6][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[18][0][0].x = 4;
  g_aTacticalUnitFacingOffsetTable[18][0][0].y = 19;
  g_aTacticalUnitFacingOffsetTable[18][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[18][1][0].x = 2;
  g_aTacticalUnitFacingOffsetTable[18][1][1].x = -1;
  g_aTacticalUnitFacingOffsetTable[18][1][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[18][2][0].x = 1;
  g_aTacticalUnitFacingOffsetTable[18][2][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[18][2][1].x = -5;
  g_aTacticalUnitFacingOffsetTable[18][2][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[18][3][0].x = -6;
  g_aTacticalUnitFacingOffsetTable[18][3][1].x = -5;
  g_aTacticalUnitFacingOffsetTable[18][4][0].x = 5;
  g_aTacticalUnitFacingOffsetTable[18][4][1].x = 3;
  g_aTacticalUnitFacingOffsetTable[18][4][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[18][5][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[18][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[18][5][1].y = 15;
  g_aTacticalUnitFacingOffsetTable[18][6][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[18][6][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[18][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[18][6][1].y = 14;
  g_aTacticalUnitFacingOffsetTable[19][0][0].x = 8;
  g_aTacticalUnitFacingOffsetTable[19][0][0].y = 14;
  g_aTacticalUnitFacingOffsetTable[19][0][1].x = -6;
  g_aTacticalUnitFacingOffsetTable[19][0][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[19][1][0].x = 3;
  g_aTacticalUnitFacingOffsetTable[19][1][0].y = 13;
  g_aTacticalUnitFacingOffsetTable[19][1][1].x = -6;
  g_aTacticalUnitFacingOffsetTable[19][1][1].y = 12;
  g_aTacticalUnitFacingOffsetTable[19][2][0].x = 4;
  g_aTacticalUnitFacingOffsetTable[19][2][0].y = 13;
  g_aTacticalUnitFacingOffsetTable[19][2][1].x = -9;
  g_aTacticalUnitFacingOffsetTable[19][2][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[19][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[19][3][0].y = 15;
  g_aTacticalUnitFacingOffsetTable[19][3][1].x = -8;
  g_aTacticalUnitFacingOffsetTable[19][3][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[19][4][0].x = 7;
  g_aTacticalUnitFacingOffsetTable[19][4][0].y = 14;
  g_aTacticalUnitFacingOffsetTable[19][4][1].x = -5;
  g_aTacticalUnitFacingOffsetTable[19][4][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[19][5][0].x = 6;
  g_aTacticalUnitFacingOffsetTable[19][5][0].y = 13;
  g_aTacticalUnitFacingOffsetTable[19][5][1].x = -7;
  g_aTacticalUnitFacingOffsetTable[19][5][1].y = 13;
  g_aTacticalUnitFacingOffsetTable[19][6][0].x = 7;
  g_aTacticalUnitFacingOffsetTable[19][6][0].y = 9;
  g_aTacticalUnitFacingOffsetTable[19][6][1].x = -6;
  g_aTacticalUnitFacingOffsetTable[19][6][1].y = 8;
  g_aTacticalUnitFacingOffsetTable[20][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[20][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[20][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[21][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[21][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[22][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[22][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[23][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[23][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[24][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[24][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[25][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[25][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[26][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[26][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[27][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[27][6][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][0][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][0][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][0][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][0][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][1][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][1][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][1][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][1][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][2][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][2][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][2][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][2][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][3][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][3][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][3][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][3][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][4][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][4][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][4][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][4][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][5][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][5][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][5][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][5][1].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][6][0].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][6][0].y = 0;
  g_aTacticalUnitFacingOffsetTable[28][6][1].x = 0;
  g_aTacticalUnitFacingOffsetTable[28][6][1].y = 0;
}

IMPLEMENT_DYNCREATE(TTacticalBattleView, TView)

// FUNCTION: IMPERIALISM 0x005a8350
TTacticalBattleView::TTacticalBattleView() : TView() {
  tacticalBattle = 0;
  battlefieldSurface = 0;
  viewOriginX = 0;
  toolbar = 0;
  unitSpriteAtlasSurface = 0;
  fortLevelAtlasSurface = 0;
  tileScratchSurface = 0;
  effectAtlasSurface = 0;
  unitSpriteScratchSurface = 0;
  modalAnimWaitDoneFlag = true;
  moveAnimUnitOffsetX = -1;
}

// FUNCTION: IMPERIALISM 0x005a83c0
void TTacticalBattleView::DrawTile(TacticalTileIndex tileIndex, RECT* clipRect) {}

// FUNCTION: IMPERIALISM 0x005a8410
TTacticalBattleView::~TTacticalBattleView() {}

// FUNCTION: IMPERIALISM 0x005a8430
void TTacticalBattleView::Free() {
  g_pDisplayMgr->RemoveGWorld(battlefieldSurface);
  g_pDisplayMgr->RemoveGWorld(unitSpriteAtlasSurface);
  g_pDisplayMgr->RemoveGWorld(unitSpriteScratchSurface);
  g_pDisplayMgr->RemoveGWorld(fortLevelAtlasSurface);
  g_pDisplayMgr->RemoveGWorld(tileScratchSurface);
  g_pDisplayMgr->RemoveGWorld(effectAtlasSurface);
  g_pUiAnimator->FreeAllAnis();
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x005a84d0
void TTacticalBattleView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  TInfoBarText* cursorPanel = static_cast<TInfoBarText*>(GetWindow()->FindSubView(kControlTagCurs));
  cursorPanel->AssertValid();
  g_pCursorControlPanel = cursorPanel;
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  GetWindow()->activeViewTag = controlTag;
  BecomeTarget();
}

// FUNCTION: IMPERIALISM 0x005a8550
void TTacticalBattleView::DoKeyEvent(TToolboxEvent* event) {
  int commandCode = event->commandCode;
  switch (commandCode) {
  case 0x20:
    tacticalBattle->CycleTarget();
    break;
  case 0x44:
  case 0x64:
    tacticalBattle->HandleTacticalBattleCommandTag(kControlTagDone); // 'done'
    break;
  case 0x48:
  case 0x68:
    g_pHelpMgr->ShowLatestHelp();
    break;
  case 0x53:
  case 0x73:
    tacticalBattle->HandleTacticalBattleCommandTag(kControlTagSkip); // 'skip'
    break;
  }
}

// FUNCTION: IMPERIALISM 0x005a8660
void TTacticalBattleView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (modalAnimWaitDoneFlag) {
    int row;
    int column;
    ConvertPoint(&point, &row, &column);
    tacticalBattle->DispatchTacticalActionByHoverStateIndex(row * tileColumnsPerRow + column);
  }
}

// FUNCTION: IMPERIALISM 0x005a86d0
void TTacticalBattleView::ConvertPoint(POINT* screenPoint, int* outRow, int* outCol) {
  int row = screenPoint->y / tileRowHeightPx;
  *outRow = row;
  if (row < 0) {
    *outRow = 0;
  }
  int maxRow = frameHeight / tileRowHeightPx - 1;
  if (*outRow >= maxRow) {
    *outRow = maxRow;
  }
  int col = viewOriginX + screenPoint->x;
  *outCol = col;
  if ((*outRow & 1) != 0) {
    *outCol = col - tileWidthPx / 2;
  }
  col = *outCol / tileWidthPx;
  *outCol = col;
  if (col < 0) {
    *outCol = 0;
  }
  int maxCol = tacticalBattle->battlefieldColumnCount;
  if (*outCol >= maxCol) {
    *outCol = maxCol - 1;
  }
}

// FUNCTION: IMPERIALISM 0x005a8790
void TTacticalBattleView::SyncStatusPanelBounds() {
  RECT bounds = {0, 0, frameWidth, frameHeight};
  ValidateVRect(&bounds);
}

// FUNCTION: IMPERIALISM 0x005a87d0
void TTacticalBattleView::Tile2Rect(RECT* rectOut, TacticalTileIndex tileIndex) {
  int row = tileIndex / tileColumnsPerRow;
  int x = (tileIndex % tileColumnsPerRow) * tileWidthPx - viewOriginX;
  rectOut->left = x;
  if (row & 1) {
    // Odd hex rows are staggered right by half a tile.
    rectOut->left = x + tileWidthPx / 2;
  }
  rectOut->top = row * tileRowHeightPx;
  rectOut->right = rectOut->left + tileWidthPx;
  rectOut->bottom = rectOut->top + tileRowHeightPx;
}

// FUNCTION: IMPERIALISM 0x005a8860
void TTacticalBattleView::InvalidateTile(TacticalTileIndex tileIndex) {
  RECT tileRect;
  int row = tileIndex / tileColumnsPerRow;
  int tileWidth = tileWidthPx;
  int x = (tileIndex % tileColumnsPerRow) * tileWidth - viewOriginX;
  tileRect.left = x;
  if (row & 1) {
    // Odd hex rows are staggered right by half a tile.
    x += tileWidth / 2;
    tileRect.left = x;
  }
  int rowHeight = tileRowHeightPx;
  tileRect.top = row * rowHeight;
  tileRect.right = x + tileWidth;
  tileRect.bottom = tileRect.top + rowHeight;
  InvalidateCityDialogRectRegion(&tileRect, 1);
}

// FUNCTION: IMPERIALISM 0x005a8900
void TTacticalBattleView::UpdateTile(TacticalTileIndex tileIndex) {
  int row = tileIndex / tileColumnsPerRow;
  int x = (tileIndex % tileColumnsPerRow) * tileWidthPx - viewOriginX;
  RECT tileRect;
  tileRect.left = x;
  if (row & 1) {
    x += tileWidthPx / 2;
    tileRect.left = x;
  }
  tileRect.top = row * tileRowHeightPx;
  tileRect.right = x + tileWidthPx;
  tileRect.bottom = tileRect.top + tileRowHeightPx;
  InvalidateCityDialogRectRegion(&tileRect, 1);
}

// FUNCTION: IMPERIALISM 0x005a89a0
void TTacticalBattleView::InvalidateUnit(TTacticalUnit* unit) {
  RECT unitRect;
  if (unit->tileIndex != -1) {
    UnitRect(unit, &unitRect);
    InvalidateCityDialogRectRegion(&unitRect, 1);
  }
}

// FUNCTION: IMPERIALISM 0x005a89f0
void TTacticalBattleView::UnitRect(TTacticalUnit* unit, RECT* rectOut) {
  TacticalTileIndex tileIndex = unit->tileIndex;
  if (tileIndex == -1) {
    rectOut->left = 0;
    rectOut->top = 0;
    rectOut->right = 0;
    rectOut->bottom = 0;
    return;
  }
  int row = tileIndex / tileColumnsPerRow;
  int x = (tileIndex % tileColumnsPerRow) * tileWidthPx - viewOriginX;
  rectOut->left = x;
  if (row & 1) {
    // Odd hex rows are staggered right by half a tile.
    rectOut->left = x + tileWidthPx / 2;
  }
  int top = row * tileRowHeightPx;
  rectOut->top = top;
  rectOut->right = rectOut->left + tileWidthPx;
  int bottom = top + tileRowHeightPx;
  rectOut->top = top - 0x18;
  rectOut->bottom = bottom;
  rectOut->bottom = bottom - 4;
}

// FUNCTION: IMPERIALISM 0x005a8ac0
void TTacticalBattleView::MakeTileVisible(TacticalTileIndex tileIndex) {
  int firstVisibleColumn = viewOriginX / tileWidthPx;
  int visibleColumnCount = frameWidth / tileWidthPx;
  int lastVisibleColumn = firstVisibleColumn + visibleColumnCount;
  int screenColumn = ((tileIndex % 0x1d) * 2 + ((tileIndex / 0x1d) & 1)) / 2;
  if (screenColumn >= firstVisibleColumn + 2 && screenColumn <= lastVisibleColumn - 2) {
    return;
  }
  short tileWidth =
      static_cast<short>(tileWidthPx); // original loads the low word once and reuses it
  viewOriginX = static_cast<short>(screenColumn * tileWidth - frameWidth / 2);
  if (viewOriginX < 0) {
    viewOriginX = 0;
  } else if (viewOriginX > scrollableContentWidth - frameWidth) {
    viewOriginX = static_cast<short>(scrollableContentWidth - frameWidth);
  }
  // Snap the origin back to a whole-tile boundary.
  if (viewOriginX % tileWidthPx != 0) {
    viewOriginX = static_cast<short>((viewOriginX / tileWidthPx) * tileWidth);
  }
  RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005a8be0
void TTacticalBattleView::Scroll(MapScrollEdgeMaskStorage scrollDirection) {
  if (modalAnimWaitDoneFlag) {
    if (scrollDirection == kMapScrollEdgeLeft) {
      if (viewOriginX > 0) {
        viewOriginX = viewOriginX - static_cast<short>(tileWidthPx);
        RefreshControl();
        UpdateSelectionBlink();
        return;
      }
    } else if (scrollDirection == kMapScrollEdgeRight &&
               static_cast<int>(viewOriginX) <
                   (static_cast<int>(scrollableContentWidth) - frameWidth) - tileWidthPx) {
      viewOriginX = static_cast<short>(tileWidthPx) + viewOriginX;
      RefreshControl();
    }
    UpdateSelectionBlink();
  }
}

// FUNCTION: IMPERIALISM 0x005a8ca0
void TTacticalBattleView::DoSetCursor(CPoint* point, RgnHandle hitArg) {
  short cursorId = static_cast<short>(GetCursorID());
  if (cursorId != -1) {
    CPoint mappedPoint = ViewToQDPt(point);
    if (PtInRgn(&mappedPoint, hitArg) != 0) {
      SetCursor(g_pViewMgr->turnEventCursors[cursorId - TViewMgr::kCursorResourceIdBase]);
      return;
    }
  }
  SetCursor(LoadCursorA(0, IDC_ARROW));
}

// FUNCTION: IMPERIALISM 0x005a8d40
void TTacticalBattleView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                              RgnHandle hitArg) {
  int gridRow = 0;
  int gridCol = 0;
  ConvertPoint(point, &gridRow, &gridCol);
  int tileIndex = static_cast<short>(gridRow * tileColumnsPerRow + gridCol);
  unsigned short cursorToken = static_cast<unsigned short>(
      tacticalBattle->ResolveTacticalHoverCursorResourceId(static_cast<short>(tileIndex)));
  if (cursorToken == 999 || cursorToken == 0) {
    cursorToken = 0xffff;
  }
  cursorId = cursorToken;
  HCURSOR cursor;
  if (cursorToken == 0xffff) {
    cursor = LoadCursorA(0, IDC_ARROW);
  } else {
    cursor =
        g_pViewMgr
            ->turnEventCursors[static_cast<short>(cursorToken) - TViewMgr::kCursorResourceIdBase];
  }
  SetCursor(cursor);
  if (tileIndex == hoveredTileIndex) {
    return;
  }
  ScopedMapQuickDrawContext guard(this);
  CTemporaryRegion savedClip;
  GetClip(savedClip.tempRgn);
  int previousTile = hoveredTileIndex;
  hoveredTileIndex = tileIndex;
  ResetQuickDrawStrokeState();
  if (previousTile != -1) {
    int row = previousTile / tileColumnsPerRow;
    int x = (previousTile % tileColumnsPerRow) * tileWidthPx - viewOriginX;
    RECT tileRect;
    tileRect.left = x;
    if (row & 1) {
      x += tileWidthPx / 2;
      tileRect.left = x;
    }
    tileRect.top = row * tileRowHeightPx;
    tileRect.right = x + tileWidthPx;
    tileRect.bottom = tileRect.top + tileRowHeightPx;
    SetQuickDrawStrokeColor(0xffffff);
    SetQuickDrawFillColor(0);
    BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &tileRect,
                                     &tileRect, 0, 0);
  }
  if (static_cast<short>(tileIndex) != -1) {
    int row = tileIndex / tileColumnsPerRow;
    int x = (tileIndex % tileColumnsPerRow) * tileWidthPx - viewOriginX;
    RECT tileRect;
    tileRect.left = x;
    if (row & 1) {
      x += tileWidthPx / 2;
      tileRect.left = x;
    }
    tileRect.top = row * tileRowHeightPx;
    tileRect.right = x + tileWidthPx;
    tileRect.bottom = tileRect.top + tileRowHeightPx;
    SetQuickDrawStrokeColor(0xffffff);
    SetQuickDrawFillColorFromPaletteIndex(0);
    DrawHexSelectionOutlineSegments(&tileRect);
    DrawTile(static_cast<short>(tileIndex), &tileRect);
  }
  SetClip(savedClip.tempRgn);
  if (toolbar != 0 && tacticalBattle->battleOutcome == kTacticalBattleInProgress) {
    toolbar->UpdateTacticalOtherSideUnitControl(
        static_cast<TArmyTacUnit*>(tacticalBattle->tileGrid[tileIndex].occupant));
  }
}

// FUNCTION: IMPERIALISM 0x005a9090
void TTacticalBattleView::PlayAni(TacticalTileIndex tileIndex, int effectId, int frameCount) {
  RECT effectRect;
  TTacticalUnit* occupant = tacticalBattle->tileGrid[tileIndex].occupant;
  if (occupant != 0) {
    UnitRect(occupant, &effectRect);
  } else {
    int row = tileIndex / tileColumnsPerRow;
    int tileWidth = tileWidthPx;
    int x = (tileIndex % tileColumnsPerRow) * tileWidth - viewOriginX;
    effectRect.left = x;
    if (row & 1) {
      x += tileWidth / 2;
      effectRect.left = x;
    }
    int rowHeight = tileRowHeightPx;
    effectRect.top = row * rowHeight;
    effectRect.right = x + tileWidth;
    effectRect.bottom = effectRect.top + rowHeight;
  }
  PlayAni(&effectRect, effectId, frameCount, tileIndex, 2);
}

// Plays a one-shot animation over `rect` and pumps UI messages until it completes.

// FUNCTION: IMPERIALISM 0x005a9170
void TTacticalBattleView::PlayAni(RECT* rect, int effectId, int frameCount,
                                  TacticalTileIndex tileIndex, int mode) {
  TOneTimeAnimation* animation = new TOneTimeAnimation;
  // The original calls the init body unconditionally on the new-result (no null guard).
  animation->InitializeOneTimeAnimation(this, rect, static_cast<short>(frameCount),
                                        static_cast<short>(effectId), mode, tileIndex);
  g_pUiAnimator->AddAnimation(static_cast<TAnimation*>(static_cast<void*>(animation)));
  BeginModalAnimationWait();
  modalAnimWaitDoneFlag = false;
  while (!animation->completeFlag) {
    PumpUiMessagesAndBackgroundTasks(1);
  }
  modalAnimWaitDoneFlag = true;
  EndModalAnimationWait();
  InvalidateCityDialogRectRegion(rect, 1);
  g_pUiAnimator->FreeAni(tileIndex);
}

// FUNCTION: IMPERIALISM 0x005a9240
void TTacticalBattleView::GlideUnit(TTacticalUnit* unit, TacticalTileIndex fromTileIndex,
                                    TacticalTileIndex toTileIndex) {
  if (g_pSimMgr->preferenceValues[5] == 0) {
    return;
  }

  int fromRow = fromTileIndex / tileColumnsPerRow;
  int fromX = (fromTileIndex % tileColumnsPerRow) * tileWidthPx - viewOriginX;
  if (fromRow & 1) {
    fromX += tileWidthPx / 2;
  }
  int fromY = fromRow * tileRowHeightPx;
  int fromBottom = fromY + tileRowHeightPx;

  int toRow = toTileIndex / tileColumnsPerRow;
  int toX = (toTileIndex % tileColumnsPerRow) * tileWidthPx - viewOriginX;
  if (toRow & 1) {
    toX += tileWidthPx / 2;
  }
  int toY = toRow * tileRowHeightPx;
  int toBottom = toY + tileRowHeightPx;

  RECT animRect;
  animRect.left = (fromX < toX) ? fromX : toX;
  int maxBottom = (fromBottom > toBottom) ? fromBottom : toBottom;
  animRect.top = maxBottom - 3 * tileRowHeightPx;
  animRect.right = animRect.left + 2 * tileWidthPx;
  animRect.bottom = maxBottom;

  moveAnimUnitOffsetY = fromBottom - animRect.top - 4;
  moveAnimScreenRect.left = animRect.left;
  moveAnimScreenRect.top = animRect.top;
  moveAnimScreenRect.right = animRect.right;
  moveAnimScreenRect.bottom = animRect.bottom;
  moveAnimStepX = (toX - fromX) / 3;
  moveAnimStepY = (toY - fromY) / 3;
  moveAnimUnitOffsetX = fromX - animRect.left;

  int spriteLeft = unit->unitType * unitSpriteCellWidth;
  int fromHalfColumn = (fromTileIndex % 0x1d) * 2 + ((fromTileIndex / 0x1d) & 1);
  int toHalfColumn = (toTileIndex % 0x1d) * 2 + ((toTileIndex / 0x1d) & 1);
  int spriteTop = (fromHalfColumn < toHalfColumn) ? 0 : unitSpriteCellHeight;
  moveAnimSpriteSrcRect.left = spriteLeft;
  moveAnimSpriteSrcRect.top = spriteTop;
  moveAnimSpriteSrcRect.right = spriteLeft + unitSpriteCellWidth;
  moveAnimSpriteSrcRect.bottom = spriteTop + unitSpriteCellHeight;

  InvalidateCityDialogRectRegion(&animRect, 1);

  RECT fromTileRect;
  int row2 = fromTileIndex / tileColumnsPerRow;
  int tileWidth2 = tileWidthPx;
  int x2 = (fromTileIndex % tileColumnsPerRow) * tileWidth2 - viewOriginX;
  fromTileRect.left = x2;
  if (row2 & 1) {
    x2 += tileWidth2 / 2;
    fromTileRect.left = x2;
  }
  int rowHeight2 = tileRowHeightPx;
  fromTileRect.top = row2 * rowHeight2;
  fromTileRect.right = x2 + tileWidth2;
  fromTileRect.bottom = fromTileRect.top + rowHeight2;
  InvalidateCityDialogRectRegion(&fromTileRect, 1);

  ForceRedraw();
  moveAnimUnitOffsetX = -1;
}

// FUNCTION: IMPERIALISM 0x005a9550
void TTacticalBattleView::DoGlideAni() {
  if (moveAnimUnitOffsetX == -1) {
    return;
  }
  SetQuickDrawFillColor(0);
  for (int slotIndex = 0; slotIndex < 4; ++slotIndex) {
    unsigned int frameStartTick = GetTickCountDiv16();
    int rowOffsetPx = slotIndex * moveAnimStepY;
    int colOffsetPx = slotIndex * moveAnimStepX;

    // Save the current on-screen animation-rect background into the scratch surface.
    RECT screenRect = moveAnimScreenRect;
    RECT scratchRect;
    scratchRect.left = 0;
    scratchRect.top = 0;
    scratchRect.right = tileWidthPx << 1;
    scratchRect.bottom = tileRowHeightPx * 3;
    RECT primaryClipRect;
    CopyRect(&primaryClipRect, &g_pPrimaryRenderSurfaceContext->blitSurface.clipRect);
    if (ClipSrcRectToBoundsAndOffsetDstRect(&primaryClipRect, &scratchRect, &screenRect)) {
      if (unitSpriteScratchSurface->blitSurface.surfaceDib != 0) {
        int scratchDibHeight =
            unitSpriteScratchSurface->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (scratchDibHeight < 1) {
          scratchDibHeight = -scratchDibHeight;
        }
        OffsetRect(&scratchRect, 0, (scratchDibHeight - scratchRect.top) - scratchRect.bottom);
      }
      if (g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib != 0) {
        int primaryDibHeight = g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib->m_pInfoHeader
                                   ->bmiHeader.biHeight;
        if (primaryDibHeight < 1) {
          primaryDibHeight = -primaryDibHeight;
        }
        OffsetRect(&screenRect, 0, (primaryDibHeight - screenRect.top) - screenRect.bottom);
      }
      BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                       unitSpriteScratchSurface->GetBlitSurface(), &screenRect,
                                       &scratchRect, 0);
    }

    RECT tileRect;
    tileRect.left = colOffsetPx + moveAnimUnitOffsetX;
    tileRect.top = (rowOffsetPx - unitSpriteCellHeight) + moveAnimUnitOffsetY;
    tileRect.bottom = moveAnimUnitOffsetY + rowOffsetPx;
    tileRect.right = colOffsetPx + unitSpriteCellWidth + moveAnimUnitOffsetX;

    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);

    RECT spriteSrcRect = moveAnimSpriteSrcRect;
    RECT atlasClipRect;
    CopyRect(&atlasClipRect, &unitSpriteAtlasSurface->blitSurface.clipRect);
    if (ClipSrcRectToBoundsAndOffsetDstRect(&atlasClipRect, &tileRect, &spriteSrcRect)) {
      if (unitSpriteAtlasSurface->blitSurface.surfaceDib != 0) {
        int atlasDibHeight =
            unitSpriteAtlasSurface->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (atlasDibHeight < 1) {
          atlasDibHeight = -atlasDibHeight;
        }
        OffsetRect(&spriteSrcRect, 0, (atlasDibHeight - spriteSrcRect.top) - spriteSrcRect.bottom);
      }
      if (unitSpriteScratchSurface->blitSurface.surfaceDib != 0) {
        int scratchDibHeight2 =
            unitSpriteScratchSurface->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (scratchDibHeight2 < 1) {
          scratchDibHeight2 = -scratchDibHeight2;
        }
        OffsetRect(&tileRect, 0, (scratchDibHeight2 - tileRect.top) - tileRect.bottom);
      }
      BlitRectWithOptionalTransparency(unitSpriteAtlasSurface->GetBlitSurface(),
                                       unitSpriteScratchSurface->GetBlitSurface(), &spriteSrcRect,
                                       &tileRect, 0x24);
    }

    SetQuickDrawStrokeColor(0xffffff);
    RECT compositeSrcRect = moveAnimScreenRect;
    RECT compositeDstRect = {0, 0, tileWidthPx << 1, tileRowHeightPx * 3};
    RECT frameBoundsRect = {g_nUiFrameClipOriginX, g_nUiFrameClipOriginY, frameWidth, frameHeight};
    if (ClipSrcRectToBoundsAndOffsetDstRect(&frameBoundsRect, &compositeDstRect,
                                            &compositeSrcRect)) {
      if (g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib != 0) {
        int activeDibHeight = g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib
                                  ->m_pInfoHeader->bmiHeader.biHeight;
        if (activeDibHeight < 1) {
          activeDibHeight = -activeDibHeight;
        }
        OffsetRect(&compositeSrcRect, 0,
                   (activeDibHeight - compositeSrcRect.top) - compositeSrcRect.bottom);
      }
      BlitRectWithOptionalTransparency(unitSpriteScratchSurface->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &compositeDstRect, &compositeSrcRect, 0);
    }

    unsigned int nowTick;
    do {
      nowTick = GetTickCountDiv16();
      if (frameStartTick + 2 <= nowTick) {
        break;
      }
    } while (frameStartTick <= nowTick);
  }

  InvalidateCityDialogRectRegion(&moveAnimScreenRect, 1);
  moveAnimUnitOffsetX = -1;
}

// FUNCTION: IMPERIALISM 0x005a99e0
void __stdcall DrawHexSelectionOutlineSegments(RECT* rect) {
  rect->right -= 1;
  rect->bottom -= 1;
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(rect->left),
                                          static_cast<short>(rect->top + 6));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(rect->left), static_cast<short>(rect->top));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(rect->left + 6), static_cast<short>(rect->top));
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(rect->right - 6),
                                          static_cast<short>(rect->top));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(rect->right), static_cast<short>(rect->top));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(rect->right), static_cast<short>(rect->top + 6));
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(rect->right),
                                          static_cast<short>(rect->bottom - 6));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(rect->right), static_cast<short>(rect->bottom));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(rect->right - 6),
                               static_cast<short>(rect->bottom));
  SetQuickDrawTextOriginWithContextOffset(static_cast<short>(rect->left + 6),
                                          static_cast<short>(rect->bottom));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(rect->left), static_cast<short>(rect->bottom));
  DrawCenteredGuideLineOnMapDc(static_cast<short>(rect->left),
                               static_cast<short>(rect->bottom - 6));
}

// FUNCTION: IMPERIALISM 0x005a9b40
void TTacticalBattleView::SetCurrentPlayer(unsigned char side) {
  (void)side; // parameter is dead in the original: the side is read from the battle state
  TPicture* coatControl = static_cast<TPicture*>(ownerContext->FindSubView(kControlTagCoat));
  coatControl->AssertValid();
  TTacticalBattle* battle = tacticalBattle;
  TTacticalPlayer* currentPlayer = battle->players[battle->currentSide];
  coatControl->SetPictureRsrcID(static_cast<short>(currentPlayer->nationIndex + 0xea6), 1);
}

// FUNCTION: IMPERIALISM 0x005a9bb0
void TTacticalBattleView::UpdateSelectionBlink() {
  g_pUiAnimator->FreeAni(0x2711);
  TTacticalUnit* selectedUnit = tacticalBattle->selectedUnit;
  if (selectedUnit == 0) {
    return;
  }
  TacticalTileIndex tileIndex = selectedUnit->tileIndex;
  if (tileIndex < 0) {
    return;
  }
  RECT tileRect;
  int row = tileIndex / tileColumnsPerRow;
  int tileWidth = tileWidthPx;
  int x = (tileIndex % tileColumnsPerRow) * tileWidth - viewOriginX;
  tileRect.left = x;
  if (row & 1) {
    x += tileWidth / 2;
    tileRect.left = x;
  }
  int rowHeight = tileRowHeightPx;
  tileRect.top = row * rowHeight;
  tileRect.right = x + tileWidth;
  tileRect.bottom = tileRect.top + rowHeight;
  TAnimation* marker = new TAnimation;
  // Original calls the init body unconditionally on the new-result (no null guard).
  marker->IAnimation(this, &tileRect, 2, 0, 0xa, 0x2711);
  g_pUiAnimator->AddAnimation(marker);
}

// FUNCTION: IMPERIALISM 0x005a9cc0
void TTacticalBattleView::KillSelectionBlink() {
  g_pUiAnimator->FreeAni(0x2711);
}

// FUNCTION: IMPERIALISM 0x005aa670
short TTacticalBattleView::ComputeTacticalUnitSpriteOrientationIndexByAdjacentType1Occupancy(
    TacticalTileIndex tileIndex) {
  int orientationTable[8] = {6, 3, 5, 1, 6, 0, 2, 4};
  TacticalTileIndex neighbors[6];
  tacticalBattle->GetNeighborList(tileIndex, neighbors);
  int code;
  if ((tileIndex / 29 & 1) != 0) {
    code = 0;
    if (neighbors[5] != -1 && tacticalBattle->tileGrid[neighbors[5]].deployMark == 1) {
      code = 2;
    }
    if (neighbors[3] != -1 && tacticalBattle->tileGrid[neighbors[3]].deployMark == 1) {
      code++;
    }
  } else {
    code = 4;
    if (neighbors[0] != -1 && tacticalBattle->tileGrid[neighbors[0]].deployMark == 1) {
      code = 6;
    }
    if (neighbors[2] != -1 && tacticalBattle->tileGrid[neighbors[2]].deployMark == 1) {
      code++;
    }
  }
  return static_cast<short>(orientationTable[code]);
}

// FUNCTION: IMPERIALISM 0x005aa7d0
void TTacticalBattleView::ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(TTacticalUnit* unit,
                                                                                RECT* rectOut) {
  TacticalTileIndex tileIndex = unit->tileIndex;
  int row = tileIndex / tileColumnsPerRow;
  int x = (tileIndex % tileColumnsPerRow) * tileWidthPx - viewOriginX;
  rectOut->left = x;
  if (row & 1) {
    rectOut->left = tileWidthPx / 2 + x;
  }
  int y = row * tileRowHeightPx;
  rectOut->top = y;
  rectOut->right = rectOut->left + tileWidthPx;
  rectOut->bottom = tileRowHeightPx + y;
  rectOut->top = y - 0x14;

  TacticalTileRecord* tile = &tacticalBattle->tileGrid[tileIndex];
  if (tile->deployMark == 1) {
    int unitType = unit->unitType;
    short orient = ComputeTacticalUnitSpriteOrientationIndexByAdjacentType1Occupancy(tileIndex);
    POINT* delta = &g_aTacticalUnitFacingOffsetTable[unitType][orient][unit->side];
    ::OffsetRect(rectOut, delta->x, delta->y);
    return;
  }
  if (tile->trenchMask != 0 && g_awTacticalUnitCategoryCodeBySlot[unit->unitType] ==
                                   EncodeArmyUnitCategory(kArmyUnitCategoryDemolitionist)) {
    rectOut->right = -200;
  }
}

// FUNCTION: IMPERIALISM 0x005ad9e0
void ResetUiFrameClipOrigin() {
  g_nUiFrameClipOriginX = 0;
  g_nUiFrameClipOriginY = 0;
}
