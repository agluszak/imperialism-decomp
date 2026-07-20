#include "game/TTacticalBattleView.h"

#include "game/TCivAnimation2.h"
#include "game/TControl.h"
#include "game/TInfoBarText.h"
#include "game/TOneTimeAnimation.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"

#include "game/TAnimation.h"
#include "game/TAnimator.h"
#include "game/TPicture.h"
#include "game/TSimMgr.h"
#include "game/TTacticalBattle.h"
#include "game/TTacticalPlayer.h"
#include "game/TTacticalUnit.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/TAmbitApplication.h"
#include "game/ui_control_tags.h"

// No-op bracket hooks around the modal one-time-animation wait (retail build leaves these empty).
// FUNCTION: IMPERIALISM 0x00498c60
void NoOpModalAnimWaitBracketHookA_00498c60(void) {}

// FUNCTION: IMPERIALISM 0x00498c80
void NoOpModalAnimWaitBracketHookB_00498c80(void) {}

// FUNCTION: IMPERIALISM 0x005a6940
BOOL __stdcall ClipSrcRectToBoundsAndOffsetDstRect(RECT* bounds, RECT* dstRect, RECT* srcRect) {
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

// Fills the tactical unit sprite facing-offset table ([unit type][orientation][side] pixel
// deltas applied by ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset for units on a
// fresh trench-deploy tile). In the original this runs as a file-scope static initializer
// (its address sits in the CRT init-pointer table at 0x693134); the assignment order below
// is the original store order, which the compiler value-groups into cached registers.
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

// SYNTHETIC: IMPERIALISM 0x005a82b0
// TTacticalBattleView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a8330
// TTacticalBattleView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalBattleView, TView)

// The original zeroes the offscreen-surface slots and anim state with body assignments in
// this exact order (all POD), so mirror that rather than a member-init list.
// FUNCTION: IMPERIALISM 0x005a8350
TTacticalBattleView::TTacticalBattleView() : TView() {
  tacticalBattle60 = 0;
  battlefieldSurface64 = 0;
  viewOriginX78 = 0;
  toolbarD0 = 0;
  unitSpriteAtlasSurface68 = 0;
  fortLevelAtlasSurface6C = 0;
  tileScratchSurface70 = 0;
  effectAtlasSurface74 = 0;
  unitSpriteScratchSurfaceBC = 0;
  modalAnimWaitDoneFlag98 = 1;
  moveAnimUnitOffsetXA4 = -1;
}

// FUNCTION: IMPERIALISM 0x005a83c0
undefined TTacticalBattleView::DrawTacticalTileInClipRect(int tileIndex, RECT* clipRect) {
  (void)tileIndex;
  (void)clipRect;
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005a83e0
// TTacticalBattleView::`scalar deleting destructor'
TTacticalBattleView::~TTacticalBattleView() {}

// FUNCTION: IMPERIALISM 0x005a8430
void TTacticalBattleView::Free() {}

// FUNCTION: IMPERIALISM 0x005a84d0
void TTacticalBattleView::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);

  TInfoBarText* cursorPanel = static_cast<TInfoBarText*>(OwnerPanel()->ResolveControlByTag(kControlTagCurs));
  cursorPanel->QueryStepValue();
  g_pCursorControlPanel = cursorPanel;
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  static_cast<TControl*>(OwnerPanel())->contentInsets68.left = controlTag;
  ActivateCityProductionViewIfAllowed();
}

// FUNCTION: IMPERIALISM 0x005a8550
void TTacticalBattleView::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x005a8660
void TTacticalBattleView::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                               int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
}

// Converts a screen point to a clamped hex grid (row, col) for this battle: row from the
// point's Y over the tile row height, column from viewOriginX + point X (shifted half a
// tile on odd rows) over the tile width, each clamped into the battle's playable range.
// FUNCTION: IMPERIALISM 0x005A86D0
void TTacticalBattleView::ConvertScreenPointToHexGridCoordClamped(POINT* screenPoint, int* outRow,
                                                                  int* outCol) {
  int row = screenPoint->y / tileRowHeightPx8C;
  *outRow = row;
  if (row < 0) {
    *outRow = 0;
  }
  int maxRow = frameHeight38 / tileRowHeightPx8C + -1;
  if (*outRow >= maxRow) {
    *outRow = maxRow;
  }
  int col = viewOriginX78 + screenPoint->x;
  *outCol = col;
  if ((*outRow & 1) != 0) {
    *outCol = col - tileWidthPx88 / 2;
  }
  col = *outCol / tileWidthPx88;
  *outCol = col;
  if (col < 0) {
    *outCol = 0;
  }
  int maxCol = tacticalBattle60->battlefieldColumnCount34;
  if (*outCol >= maxCol) {
    *outCol = maxCol + -1;
  }
}

// FUNCTION: IMPERIALISM 0x005a87d0
void TTacticalBattleView::ComputeTacticalHexTileScreenRect(RECT* rectOut, int tileIndex) {
  int row = tileIndex / tileColumnsPerRow80;
  int x = (tileIndex % tileColumnsPerRow80) * tileWidthPx88 - viewOriginX78;
  rectOut->left = x;
  if (row & 1) {
    // Odd hex rows are staggered right by half a tile.
    rectOut->left = x + tileWidthPx88 / 2;
  }
  rectOut->top = row * tileRowHeightPx8C;
  rectOut->right = rectOut->left + tileWidthPx88;
  rectOut->bottom = rectOut->top + tileRowHeightPx8C;
}

// FUNCTION: IMPERIALISM 0x005a8860
void TTacticalBattleView::InvalidateTacticalHexTileRect(int tileIndex) {
  RECT tileRect;
  int row = tileIndex / tileColumnsPerRow80;
  int tileWidth = tileWidthPx88;
  int x = (tileIndex % tileColumnsPerRow80) * tileWidth - viewOriginX78;
  tileRect.left = x;
  if (row & 1) {
    // Odd hex rows are staggered right by half a tile.
    x += tileWidth / 2;
    tileRect.left = x;
  }
  int rowHeight = tileRowHeightPx8C;
  tileRect.top = row * rowHeight;
  tileRect.right = x + tileWidth;
  tileRect.bottom = tileRect.top + rowHeight;
  InvalidateCityDialogRectRegion(&tileRect, 1);
}

// FUNCTION: IMPERIALISM 0x005a8900
undefined TTacticalBattleView::TacticalBattleViewSlot68(int param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a89a0
void TTacticalBattleView::InvalidateTacticalUnitTileRect(TTacticalUnit* unit) {
  RECT unitRect;
  if (unit->tileIndex8 != -1) {
    ComputeTacticalUnitTileScreenRect(unit, &unitRect);
    InvalidateCityDialogRectRegion(&unitRect, 1);
  }
}

// FUNCTION: IMPERIALISM 0x005a89f0
undefined TTacticalBattleView::ComputeTacticalUnitTileScreenRect(TTacticalUnit* unit,
                                                                 RECT* rectOut) {
  int tileIndex = unit->tileIndex8;
  if (tileIndex == -1) {
    rectOut->left = 0;
    rectOut->top = 0;
    rectOut->right = 0;
    rectOut->bottom = 0;
    return 0;
  }
  int row = tileIndex / tileColumnsPerRow80;
  int x = (tileIndex % tileColumnsPerRow80) * tileWidthPx88 - viewOriginX78;
  rectOut->left = x;
  if (row & 1) {
    // Odd hex rows are staggered right by half a tile.
    rectOut->left = x + tileWidthPx88 / 2;
  }
  int top = row * tileRowHeightPx8C;
  rectOut->top = top;
  rectOut->right = rectOut->left + tileWidthPx88;
  int bottom = top + tileRowHeightPx8C;
  // Grow the plain tile rect 0x18 px upward and pull the bottom in by 4 for the unit
  // sprite box; the original stores the plain values first, then the adjusted ones
  // (double writes kept per the original store order).
  rectOut->top = top - 0x18;
  rectOut->bottom = bottom;
  rectOut->bottom = bottom - 4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a8ac0
void TTacticalBattleView::CenterViewportAroundGridIndexAndSnap(int tileIndex) {
  int firstVisibleColumn = viewOriginX78 / tileWidthPx88;
  int visibleColumnCount = frameWidth34 / tileWidthPx88;
  int lastVisibleColumn = firstVisibleColumn + visibleColumnCount;
  // Screen column in whole tiles; odd rows contribute a half-column stagger
  // (tile grid is 0x1d columns wide, matching TTacticalBattle::tacticalTileStride40).
  int screenColumn = ((tileIndex % 0x1d) * 2 + ((tileIndex / 0x1d) & 1)) / 2;
  if (screenColumn >= firstVisibleColumn + 2 && screenColumn <= lastVisibleColumn - 2) {
    return;
  }
  short tileWidth = (short)tileWidthPx88; // original loads the low word once and reuses it
  viewOriginX78 = (short)(screenColumn * tileWidth - frameWidth34 / 2);
  if (viewOriginX78 < 0) {
    viewOriginX78 = 0;
  } else if (viewOriginX78 > scrollableContentWidth7A - frameWidth34) {
    viewOriginX78 = (short)(scrollableContentWidth7A - frameWidth34);
  }
  // Snap the origin back to a whole-tile boundary.
  if (viewOriginX78 % tileWidthPx88 != 0) {
    viewOriginX78 = (short)((viewOriginX78 / tileWidthPx88) * tileWidth);
  }
  RefreshControl();
}

// Horizontal battlefield scroll: on direction 8 pans left by one tile while origin > 0,
// on direction 4 pans right by one tile while within the scrollable content width, then
// repaints and refreshes the unit marker. Gated on the modal-wait-done flag.
// FUNCTION: IMPERIALISM 0x005a8be0
void TTacticalBattleView::AdjustTacticalUnitVerticalOffsetAndRefreshMarker(short scrollDirection) {
  if (modalAnimWaitDoneFlag98 != 0) {
    if (scrollDirection == 8) {
      if (viewOriginX78 > 0) {
        viewOriginX78 = viewOriginX78 - static_cast<short>(tileWidthPx88);
        RefreshControl();
        SpawnTacticalUiMarkerAtUnitTile();
        return;
      }
    } else if (scrollDirection == 4 &&
               static_cast<int>(viewOriginX78) <
                   (static_cast<int>(scrollableContentWidth7A) - frameWidth34) - tileWidthPx88) {
      viewOriginX78 = static_cast<short>(tileWidthPx88) + viewOriginX78;
      RefreshControl();
    }
    SpawnTacticalUiMarkerAtUnitTile();
  }
}

// FUNCTION: IMPERIALISM 0x005a8ca0
void TTacticalBattleView::HandleCursorHoverFallback(CPoint* point, RgnHandle hitArg) {}

// FUNCTION: IMPERIALISM 0x005a8d40
void TTacticalBattleView::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                              RgnHandle hitArg) {
  (void)point;
  (void)hitArg;
}

// FUNCTION: IMPERIALISM 0x005a9090
undefined TTacticalBattleView::PlayTacticalTileEffect(int tileIndex, int effectId, int frameCount) {
  RECT effectRect;
  TTacticalUnit* occupant = tacticalBattle60->tileGrid4[tileIndex].occupant4;
  if (occupant != 0) {
    ComputeTacticalUnitTileScreenRect(occupant, &effectRect);
  } else {
    int row = tileIndex / tileColumnsPerRow80;
    int tileWidth = tileWidthPx88;
    int x = (tileIndex % tileColumnsPerRow80) * tileWidth - viewOriginX78;
    effectRect.left = x;
    if (row & 1) {
      x += tileWidth / 2;
      effectRect.left = x;
    }
    int rowHeight = tileRowHeightPx8C;
    effectRect.top = row * rowHeight;
    effectRect.right = x + tileWidth;
    effectRect.bottom = effectRect.top + rowHeight;
  }
  return RunOneTimeAnimationModalWaitAndInvalidateCityDialog(&effectRect, effectId, frameCount,
                                                             tileIndex, 2);
}

// 1-byte no-op pair bracketing the modal animation wait (possible Mac
// HideCursor/ShowCursor shims, like QDLoadResource); autogen-stub-owned.

// Spawns a TOneTimeAnimation over `rect` (effect sprite `effectId`, `frameCount`
// frames, `mode` ticks per frame, registry tag = tileIndex), registers it with the
// UI animator, then pumps UI messages modally until the animation completes; finally
// invalidates the rect and drops the registry entry.

// FUNCTION: IMPERIALISM 0x005a9170
undefined TTacticalBattleView::RunOneTimeAnimationModalWaitAndInvalidateCityDialog(
    RECT* rect, int effectId, int frameCount, int tileIndex, int mode) {
  TOneTimeAnimation* animation = new TOneTimeAnimation;
  // The original calls the init body unconditionally on the new-result (no null guard).
  animation->ConstructTOneTimeAnimationBaseState(this, rect, static_cast<short>(frameCount),
                                                 static_cast<short>(effectId), mode, tileIndex);
  // The registry stores heterogeneous animation objects; TOneTimeAnimation is
  // CObject-rooted, not TAnimation-derived, so this is a genuine pun confined here.
  g_pUiAnimator->AddObjectToUiTransientRegistry(
      static_cast<TAnimation*>(static_cast<void*>(animation)));
  NoOpModalAnimWaitBracketHookA_00498c60();
  modalAnimWaitDoneFlag98 = 0;
  while (animation->completeFlag == 0) {
    PumpUiMessagesAndBackgroundTasks(1);
  }
  modalAnimWaitDoneFlag98 = 1;
  NoOpModalAnimWaitBracketHookB_00498c80();
  InvalidateCityDialogRectRegion(rect, 1);
  g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(tileIndex);
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a9240
undefined TTacticalBattleView::AnimateTacticalUnitMoveBetweenTiles(TTacticalUnit* unit,
                                                                   int fromTileIndex,
                                                                   int toTileIndex) {
  // VERIFIED: 0x5a9248 reads word [g_pSimMgr + 0x52] = preferenceValues[5]
  // (preferenceValues[0] is at +0x48), the animation-enable preference gate.
  if (g_pSimMgr->preferenceValues[5] == 0) {
    return 0;
  }

  int fromRow = fromTileIndex / tileColumnsPerRow80;
  int fromX = (fromTileIndex % tileColumnsPerRow80) * tileWidthPx88 - viewOriginX78;
  if (fromRow & 1) {
    fromX += tileWidthPx88 / 2;
  }
  int fromY = fromRow * tileRowHeightPx8C;
  int fromBottom = fromY + tileRowHeightPx8C;

  int toRow = toTileIndex / tileColumnsPerRow80;
  int toX = (toTileIndex % tileColumnsPerRow80) * tileWidthPx88 - viewOriginX78;
  if (toRow & 1) {
    toX += tileWidthPx88 / 2;
  }
  int toY = toRow * tileRowHeightPx8C;
  int toBottom = toY + tileRowHeightPx8C;

  RECT animRect;
  animRect.left = (fromX < toX) ? fromX : toX;
  int maxBottom = (fromBottom > toBottom) ? fromBottom : toBottom;
  animRect.top = maxBottom - 3 * tileRowHeightPx8C;
  animRect.right = animRect.left + 2 * tileWidthPx88;
  animRect.bottom = maxBottom;

  moveAnimUnitOffsetYA8 = fromBottom - animRect.top - 4;
  moveAnimScreenRectC0.left = animRect.left;
  moveAnimScreenRectC0.top = animRect.top;
  moveAnimScreenRectC0.right = animRect.right;
  moveAnimScreenRectC0.bottom = animRect.bottom;
  moveAnimStepX9C = (toX - fromX) / 3;
  moveAnimStepYA0 = (toY - fromY) / 3;
  moveAnimUnitOffsetXA4 = fromX - animRect.left;

  int spriteLeft = unit->unitTypeC * unitSpriteCellWidth90;
  // Half-column positions decide the facing: moving toward a higher half-column uses
  // sprite-sheet row 0, otherwise the second row (offset by one cell height).
  int fromHalfColumn = (fromTileIndex % 0x1d) * 2 + ((fromTileIndex / 0x1d) & 1);
  int toHalfColumn = (toTileIndex % 0x1d) * 2 + ((toTileIndex / 0x1d) & 1);
  int spriteTop = (fromHalfColumn < toHalfColumn) ? 0 : unitSpriteCellHeight94;
  moveAnimSpriteSrcRectAC.left = spriteLeft;
  moveAnimSpriteSrcRectAC.top = spriteTop;
  moveAnimSpriteSrcRectAC.right = spriteLeft + unitSpriteCellWidth90;
  moveAnimSpriteSrcRectAC.bottom = spriteTop + unitSpriteCellHeight94;

  InvalidateCityDialogRectRegion(&animRect, 1);

  RECT fromTileRect;
  int row2 = fromTileIndex / tileColumnsPerRow80;
  int tileWidth2 = tileWidthPx88;
  int x2 = (fromTileIndex % tileColumnsPerRow80) * tileWidth2 - viewOriginX78;
  fromTileRect.left = x2;
  if (row2 & 1) {
    x2 += tileWidth2 / 2;
    fromTileRect.left = x2;
  }
  int rowHeight2 = tileRowHeightPx8C;
  fromTileRect.top = row2 * rowHeight2;
  fromTileRect.right = x2 + tileWidth2;
  fromTileRect.bottom = fromTileRect.top + rowHeight2;
  InvalidateCityDialogRectRegion(&fromTileRect, 1);

  InvokeSlot13C();
  moveAnimUnitOffsetXA4 = -1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a9550
void TTacticalBattleView::DrawUiTilesAndOverlay() {
  if (moveAnimUnitOffsetXA4 == -1) {
    return;
  }
  SetQuickDrawFillColor(0);
  int slotIndex = 0;
  do {
    unsigned int frameStartTick = GetTickCountDiv16();
    int rowOffsetPx = slotIndex * moveAnimStepYA0;
    int colOffsetPx = slotIndex * moveAnimStepX9C;

    // Save the current on-screen animation-rect background into the scratch surface.
    RECT screenRect = moveAnimScreenRectC0;
    RECT scratchRect;
    scratchRect.left = 0;
    scratchRect.top = 0;
    scratchRect.right = tileWidthPx88 << 1;
    scratchRect.bottom = tileRowHeightPx8C * 3;
    RECT primaryClipRect;
    CopyRect(&primaryClipRect, &g_pPrimaryRenderSurfaceContext->clipRect);
    if (ClipSrcRectToBoundsAndOffsetDstRect(&primaryClipRect, &scratchRect, &screenRect)) {
      if (unitSpriteScratchSurfaceBC->surfaceDib != 0) {
        int scratchDibHeight =
            unitSpriteScratchSurfaceBC->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (scratchDibHeight < 1) {
          scratchDibHeight = -scratchDibHeight;
        }
        OffsetRect(&scratchRect, 0, (scratchDibHeight - scratchRect.top) - scratchRect.bottom);
      }
      if (g_pPrimaryRenderSurfaceContext->surfaceDib != 0) {
        int primaryDibHeight =
            g_pPrimaryRenderSurfaceContext->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (primaryDibHeight < 1) {
          primaryDibHeight = -primaryDibHeight;
        }
        OffsetRect(&screenRect, 0, (primaryDibHeight - screenRect.top) - screenRect.bottom);
      }
      BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                            unitSpriteScratchSurfaceBC->GetBlitSurface(), &screenRect, &scratchRect,
                            0);
    }

    // Draw the unit sprite for this animation frame onto the scratch surface
    // (transparent-color blit) at its per-frame offset within the anim rect.
    RECT tileRect;
    tileRect.left = colOffsetPx + moveAnimUnitOffsetXA4;
    tileRect.top = (rowOffsetPx - unitSpriteCellHeight94) + moveAnimUnitOffsetYA8;
    tileRect.bottom = moveAnimUnitOffsetYA8 + rowOffsetPx;
    tileRect.right = colOffsetPx + unitSpriteCellWidth90 + moveAnimUnitOffsetXA4;

    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);

    RECT spriteSrcRect = moveAnimSpriteSrcRectAC;
    RECT atlasClipRect;
    CopyRect(&atlasClipRect, &unitSpriteAtlasSurface68->clipRect);
    if (ClipSrcRectToBoundsAndOffsetDstRect(&atlasClipRect, &tileRect, &spriteSrcRect)) {
      if (unitSpriteAtlasSurface68->surfaceDib != 0) {
        int atlasDibHeight =
            unitSpriteAtlasSurface68->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (atlasDibHeight < 1) {
          atlasDibHeight = -atlasDibHeight;
        }
        OffsetRect(&spriteSrcRect, 0, (atlasDibHeight - spriteSrcRect.top) - spriteSrcRect.bottom);
      }
      if (unitSpriteScratchSurfaceBC->surfaceDib != 0) {
        int scratchDibHeight2 =
            unitSpriteScratchSurfaceBC->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (scratchDibHeight2 < 1) {
          scratchDibHeight2 = -scratchDibHeight2;
        }
        OffsetRect(&tileRect, 0, (scratchDibHeight2 - tileRect.top) - tileRect.bottom);
      }
      BlitQuickDrawSurfaces(unitSpriteAtlasSurface68->GetBlitSurface(),
                            unitSpriteScratchSurfaceBC->GetBlitSurface(), &spriteSrcRect, &tileRect,
                            0x24);
    }

    // Composite the finished scratch tile back onto the active surface, clipped to
    // the view's own frame bounds.
    SetQuickDrawStrokeColor(0xffffff);
    RECT compositeSrcRect = moveAnimScreenRectC0;
    RECT compositeDstRect = {0, 0, tileWidthPx88 << 1, tileRowHeightPx8C * 3};
    RECT frameBoundsRect = {g_nUiFrameClipOriginX, g_nUiFrameClipOriginY, frameWidth34,
                            frameHeight38};
    if (ClipSrcRectToBoundsAndOffsetDstRect(&frameBoundsRect, &compositeDstRect,
                                            &compositeSrcRect)) {
      if (g_pActiveQuickDrawSurfaceContext->surfaceDib != 0) {
        int activeDibHeight =
            g_pActiveQuickDrawSurfaceContext->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
        if (activeDibHeight < 1) {
          activeDibHeight = -activeDibHeight;
        }
        OffsetRect(&compositeSrcRect, 0,
                   (activeDibHeight - compositeSrcRect.top) - compositeSrcRect.bottom);
      }
      BlitQuickDrawSurfaces(unitSpriteScratchSurfaceBC->GetBlitSurface(),
                            g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &compositeDstRect,
                            &compositeSrcRect, 0);
    }

    unsigned int nowTick;
    do {
      nowTick = GetTickCountDiv16();
      if (frameStartTick + 2 <= nowTick) {
        break;
      }
    } while (frameStartTick <= nowTick);

    ++slotIndex;
  } while (slotIndex < 4);

  InvalidateCityDialogRectRegion(&moveAnimScreenRectC0, 1);
  moveAnimUnitOffsetXA4 = -1;
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

// Promoted tactical-UI helpers (called from the TTacticalBattle command handlers).

// FUNCTION: IMPERIALISM 0x005a9b40
void TTacticalBattleView::UpdateTacticalActionControlBitmapForCurrentUnit(char side) {
  (void)side; // parameter is dead in the original: the side is read from the battle state
  TPicture* coatControl =
      static_cast<TPicture*>(ownerContext->ResolveControlByTag(kControlTagCoat));
  coatControl->AssertValid();
  TTacticalBattle* battle = tacticalBattle60;
  // tacticalPlayer14/18 are indexed as a two-slot array by the current side.
  TTacticalPlayer* currentPlayer = (&battle->tacticalPlayer14)[battle->currentSideC];
  coatControl->SetPictureResourceIdAndRefresh(
      static_cast<short>(currentPlayer->nationIndex1C + 0xea6), 1);
}

// FUNCTION: IMPERIALISM 0x005a9bb0
void TTacticalBattleView::SpawnTacticalUiMarkerAtUnitTile() {
  g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(0x2711);
  TTacticalUnit* selectedUnit = tacticalBattle60->selectedUnit1c;
  if (selectedUnit == 0) {
    return;
  }
  int tileIndex = selectedUnit->tileIndex8;
  if (tileIndex < 0) {
    return;
  }
  RECT tileRect;
  int row = tileIndex / tileColumnsPerRow80;
  int tileWidth = tileWidthPx88;
  int x = (tileIndex % tileColumnsPerRow80) * tileWidth - viewOriginX78;
  tileRect.left = x;
  if (row & 1) {
    x += tileWidth / 2;
    tileRect.left = x;
  }
  int rowHeight = tileRowHeightPx8C;
  tileRect.top = row * rowHeight;
  tileRect.right = x + tileWidth;
  tileRect.bottom = tileRect.top + rowHeight;
  TAnimation* marker = new TAnimation;
  // Original calls the init body unconditionally on the new-result (no null guard).
  marker->ConstructTAnimationBaseState(this, &tileRect, 2, 0, 0xa, 0x2711);
  g_pUiAnimator->AddObjectToUiTransientRegistry(marker);
}

// FUNCTION: IMPERIALISM 0x005a9cc0
void TTacticalBattleView::TriggerTacticalUiUpdate2711() {
  g_pUiAnimator->RemoveUiTransientRegistryObjectByTag(0x2711);
}

// FUNCTION: IMPERIALISM 0x005aa670
short TTacticalBattleView::ComputeTacticalUnitSpriteOrientationIndexByAdjacentType1Occupancy(
    int tileIndex) {
  // Orientation-code -> sprite-facing lookup (built on the stack as 8 dwords, returned
  // as a short). The code is derived from which of two parity-selected opposite hex
  // neighbors are trench-deploy tiles (TacticalTileRecord::deployMark8 == 1): even rows
  // consult neighbors[0]/[2], odd rows consult neighbors[5]/[3].
  int orientationTable[8] = {6, 3, 5, 1, 6, 0, 2, 4};
  int neighbors[6];
  tacticalBattle60->ComputeHexNeighborTileIndices_005A0420(tileIndex, neighbors);
  int code;
  if ((tileIndex / 29 & 1) != 0) {
    code = 0;
    if (neighbors[5] != -1 && tacticalBattle60->tileGrid4[neighbors[5]].deployMark8 == 1) {
      code = 2;
    }
    if (neighbors[3] != -1 && tacticalBattle60->tileGrid4[neighbors[3]].deployMark8 == 1) {
      code++;
    }
  } else {
    code = 4;
    if (neighbors[0] != -1 && tacticalBattle60->tileGrid4[neighbors[0]].deployMark8 == 1) {
      code = 6;
    }
    if (neighbors[2] != -1 && tacticalBattle60->tileGrid4[neighbors[2]].deployMark8 == 1) {
      code++;
    }
  }
  return static_cast<short>(orientationTable[code]);
}

// FUNCTION: IMPERIALISM 0x005aa7d0
void TTacticalBattleView::ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(TTacticalUnit* unit,
                                                                                RECT* rectOut) {
  int tileIndex = unit->tileIndex8;
  int row = tileIndex / tileColumnsPerRow80;
  int x = (tileIndex % tileColumnsPerRow80) * tileWidthPx88 - viewOriginX78;
  rectOut->left = x;
  if (row & 1) {
    rectOut->left = tileWidthPx88 / 2 + x;
  }
  int y = row * tileRowHeightPx8C;
  rectOut->top = y;
  rectOut->right = rectOut->left + tileWidthPx88;
  rectOut->bottom = tileRowHeightPx8C + y;
  rectOut->top = y - 0x14;

  TacticalTileRecord* tile = &tacticalBattle60->tileGrid4[tileIndex];
  if (tile->deployMark8 == 1) {
    // Shift the sprite rect by the unit's facing offset: table indexed by
    // [unit type][orientation][side] (see g_aTacticalUnitFacingOffsetTable). The unit
    // type is read before the orientation call (callee-saved register in the original).
    int unitType = unit->unitTypeC;
    short orient = ComputeTacticalUnitSpriteOrientationIndexByAdjacentType1Occupancy(tileIndex);
    POINT* delta = &g_aTacticalUnitFacingOffsetTable[unitType][orient][unit->side20];
    ::OffsetRect(rectOut, delta->x, delta->y);
    return;
  }
  // The else path reads word table 0x695528[unit->unitTypeC] (VERIFIED a repeating
  // identity-mod-8 table {0..7} x N) and tests "== 8", which can never hold against a
  // mod-8 read -- the branch is structurally preserved but dead for every table region.
  // Modeled here as unitTypeC % 8 == 8 (equivalently always-false) pending the same
  // table-global modeling pass noted above.
  if (tile->trenchMask10 != 0 && unit->unitTypeC % 8 == 8) {
    rectOut->right = -200;
  }
}

// FUNCTION: IMPERIALISM 0x005ad9e0
void ResetUiFrameClipOrigin() {
  g_nUiFrameClipOriginX = 0;
  g_nUiFrameClipOriginY = 0;
}
