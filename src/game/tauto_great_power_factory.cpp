#include "game/TAutoGreatPower.h"

#include <new>

// FUNCTION: IMPERIALISM 0x004e6a70
TGreatPower* CreateAutoGreatPowerNationState(void) {
  void* buffer = operator new(0xb70);
  if (buffer == 0) {
    return 0;
  }
  static_cast<TAutoGreatPower*>(buffer)->ConstructTAutoGreatPowerBaseState();
  return static_cast<TGreatPower*>(buffer);
}
