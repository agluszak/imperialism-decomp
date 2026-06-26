#include "game/startup_helpers.h"
#include "game/ImperialismApp.h"

// Define the global callback pointer
// GLOBAL: IMPERIALISM 0x006a7fac
extern "C" void* g_pGlobalCallback_006a7fac = nullptr;

// Define DAT_006a2018
// GLOBAL: IMPERIALISM 0x006a2018
extern "C" int DAT_006a2018 = 0;

// FUNCTION: IMPERIALISM 0x004149a0
bool __fastcall LoadLanguageResourcesFromIrgFiles(void* app, int dummyEdx) {
  ImperialismApp* pApp = static_cast<ImperialismApp*>(app);
  pApp->field_CC = "English";
  pApp->field_D0 = "Data/English.gob";
  pApp->field_D4 = "Data/EngSetup.gob";
  pApp->field_D8 = "Data/Pallette.gob";
  pApp->field_DC = "Data/EngUniv.gob";
  pApp->field_E0 = "ENG";
  pApp->field_E4 = 0x474e45; // 'E' | ('N' << 8) | ('G' << 16)
  return true;
}

// FUNCTION: IMPERIALISM 0x00415760
BOOL WarnLowDiskSpaceAndConfirmContinue() {
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x00483340
void __fastcall SetUiRuntimeContextAndActivateMain(void* mainFrame, int dummyEdx,
                                                   void* activeDialog) {
  // stub
}

// FUNCTION: IMPERIALISM 0x0049cc40
void SetGlobalDword6A2018(int value) {
  DAT_006a2018 = value;
}

// FUNCTION: IMPERIALISM 0x0049ded0
void __fastcall InitializeGlobalRuntimeSystemsFromConfig(void* app, int dummyEdx) {
  // stub
}

// FUNCTION: IMPERIALISM 0x005e7a80
void* SetGlobalCallback6A7FACAndReturnPrevious(void* callback) {
  extern undefined4 EnterIndexedCriticalSectionWithLazyInit();
  extern undefined4 LeaveIndexedCriticalSection();
  reinterpret_cast<void(__cdecl*)(int)>(EnterIndexedCriticalSectionWithLazyInit)(9);
  void* prev = g_pGlobalCallback_006a7fac;
  g_pGlobalCallback_006a7fac = callback;
  reinterpret_cast<void(__cdecl*)(int)>(LeaveIndexedCriticalSection)(9);
  return prev;
}
