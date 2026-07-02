#include "game/CAmbitDocument.h"

#include "game/TAmbitFileBasedDocument.h"
#include "game/TView.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x00479440
// CAmbitDocument::GetRuntimeClass

IMPLEMENT_DYNCREATE(CAmbitDocument, CDocument)

// FUNCTION: IMPERIALISM 0x00479480
CAmbitDocument::CAmbitDocument() : CDocument() {
  fileBasedDocument50 = new TAmbitFileBasedDocument();
  g_pTurnEventDialogFactoryRegistry = new TTurnEventDialogFactoryRegistry();
  RegisterStartupDialogFactoryCallbacks(g_pTurnEventDialogFactoryRegistry);
}

// FUNCTION: IMPERIALISM 0x00479710
CAmbitDocument::~CAmbitDocument() {
  if (g_pTurnEventDialogFactoryRegistry != 0) {
    delete g_pTurnEventDialogFactoryRegistry;
  }
  g_pTurnEventDialogFactoryRegistry = 0;
  fileBasedDocument50->Free();
}
