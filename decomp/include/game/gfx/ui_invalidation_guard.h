#pragma once

#include "decomp_types.h"
#include "game/GameAssert.h"
#include "game/globals/ui_widgets_globals.h"

int ReportAssertionFailure(...);

#define FailNilPointerWithAssert(sourcePath, line)                                                 \
  do {                                                                                             \
    GAME_FAIL_NIL_POINTER();                                                                       \
    ReportAssertionFailure(sourcePath, line);                                                      \
  } while (0)

#define FailNilPointerInUSmallViews(line) FailNilPointerWithAssert(s_SourcePathUSmallViews, line)
