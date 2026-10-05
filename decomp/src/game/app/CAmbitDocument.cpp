#include "game/menu_commands.h"
#include "game/app/CAmbitDocument.h"

#include "game/ArchiveStreamAdapter.h"
#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitFileBasedDocument.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_core/TView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

#ifndef IMPERIALISM_LINT
BEGIN_MESSAGE_MAP(CAmbitDocument, CDocument)
ON_COMMAND(kCmdStartNextPhase, OnStartNextPhase)
END_MESSAGE_MAP()
#endif

IMPLEMENT_DYNCREATE(CAmbitDocument, CDocument)

// FUNCTION: IMPERIALISM 0x00479480
CAmbitDocument::CAmbitDocument() : CDocument() {
  fileBasedDocument = new TAmbitFileBasedDocument();
  g_pTurnEventDialogFactoryRegistry = new TTurnEventDialogFactoryRegistry();
  RegisterStartupDialogFactoryCallbacks(g_pTurnEventDialogFactoryRegistry);
}

// FUNCTION: IMPERIALISM 0x004796a0
BOOL CAmbitDocument::IsModified() {
  return m_bModified;
}

// FUNCTION: IMPERIALISM 0x004796c0
void CAmbitDocument::SetModifiedFlag(BOOL bModified) {
  m_bModified = bModified;
}


// FUNCTION: IMPERIALISM 0x00479710
CAmbitDocument::~CAmbitDocument() {
  if (g_pTurnEventDialogFactoryRegistry != 0) {
    delete g_pTurnEventDialogFactoryRegistry;
  }
  g_pTurnEventDialogFactoryRegistry = 0;
  fileBasedDocument->Free();
}

// FUNCTION: IMPERIALISM 0x004797a0
BOOL CAmbitDocument::OnNewDocument() {
  g_bMultiplayerScenarioSetupActive = false;
  return CDocument::OnNewDocument() != 0;
}

// FUNCTION: IMPERIALISM 0x004797d0
void CAmbitDocument::Serialize(CArchive& ar) {
  CWaitCursor wait;
  ArchiveStreamAdapter* adapter = new ArchiveStreamAdapter(&ar);
  if (ar.IsStoring()) {
    fileBasedDocument->DoWrite(adapter, 0);
  } else {
    fileBasedDocument->DoRead(adapter, 0);
  }
  adapter->Free();
  SetModifiedFlag(TRUE);
}

// FUNCTION: IMPERIALISM 0x00479940
void CAmbitDocument::OnStartNextPhase() {
  g_pImperialismApp->HandleStartupCommand100();
}

// FUNCTION: IMPERIALISM 0x00479960
BOOL CAmbitDocument::OnOpenDocument(LPCTSTR lpszPathName) {
  g_bMultiplayerScenarioSetupActive = true;
  return CDocument::OnOpenDocument(lpszPathName) != 0;
}

// FUNCTION: IMPERIALISM 0x00479990
BOOL CAmbitDocument::OnSaveDocument(LPCTSTR lpszPathName) {
  CString dir(lpszPathName);
  int i = dir.GetLength() - 1;
  if (i > 0) {
    while (i > 0) {
      if (dir[i] == '/' || dir[i] == '\\') {
        break;
      }
      i--;
    }
    if (i > 0) {
      dir = dir.Left(i + 1);
      CreateDirectory(dir, NULL);
    }
  }
  return CDocument::OnSaveDocument(lpszPathName);
}
