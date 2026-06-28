#pragma once

#include "game/mfc.h"

// Game-specific CObject extension at 0x00622778 (command-line ParseParam tail).
struct CObjectWithGameParseParam : public CObject {
  void ParseParam(const char* pszParam, int bFlag, int bLast);
};
