#include "game/UiRuntimeContext.h"

// GLOBAL: IMPERIALISM 0x6a21bc
extern "C" UiRuntimeContext* g_pUiRuntimeContext = 0;

short UiRuntimeContext::GetActiveNationId(void) {
  return activeNationIdAt2E;
}

// FUNCTION: IMPERIALISM 0x00403b16
unsigned int __cdecl thunk_GetActiveNationId(void) {
  return static_cast<unsigned int>(g_pUiRuntimeContext->GetActiveNationId());
}
