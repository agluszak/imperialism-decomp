#ifndef IMPERIALISM_NATIVE_CASES_H
#define IMPERIALISM_NATIVE_CASES_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error NativeCases is test-only and must not be included in the production build
#endif

#include "NativeTransition.h"

class TGreatPower;

struct NativeCase {
  const char* name;
  RuntimeActionResult (*run)(NativeTransition&);
};

const NativeCase* FindNativeCase(const char* name);

// Trusted beginning_of_game.imp helpers. Null is a fixture bug, not a recoverable failure.
TGreatPower* ActiveNation();
short ActiveNationSlot();

void RunTradeWithoutUi();
JSON_Value* CombatMovesWithoutBattleUi();

class JsonArray;
RuntimeActionResult LoadNewsStoryIds(JsonArray* ids);

#endif
