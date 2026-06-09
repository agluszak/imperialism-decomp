#include "game/UiRuntimeContext.h"

// GLOBAL: IMPERIALISM 0x6a21bc
extern "C" UiRuntimeContext* g_pUiRuntimeContext = 0;

// FUNCTION: IMPERIALISM 0x00403b16
short UiRuntimeContext::GetActiveNationId(void) {
  return activeNationIdAt2E;
}

unsigned int __cdecl thunk_GetActiveNationId(void) {
  return g_pUiRuntimeContext->GetActiveNationId();
}
