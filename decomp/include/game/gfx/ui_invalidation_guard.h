#pragma once

#include "decomp_types.h"
#include "game/GameAssert.h"
#include "game/globals/ui_widgets_globals.h"

int TemporarilyClearAndRestoreUiInvalidationFlag(...);

#define FailNilPointerWithAssert(sourcePath, line)                                                 \
  do {                                                                                             \
    GAME_FAIL_NIL_POINTER();                                                                       \
    TemporarilyClearAndRestoreUiInvalidationFlag(sourcePath, line);                                \
  } while (0)

#define FailNilPointerInUSmallViews(line)                                                          \
  FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, line)
