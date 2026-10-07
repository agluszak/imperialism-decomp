#pragma once

#include "compat.h"

#include "game/mfc.h"

class TAmbitFileBasedDocument;

// VTABLE: IMPERIALISM 0x00645eb8
class CAmbitDocument : public CDocument {
public:
  DECLARE_DYNCREATE(CAmbitDocument)

  CAmbitDocument();
  virtual ~CAmbitDocument() override;

  virtual void Serialize(CArchive& ar) override;
  virtual BOOL IsModified() override;
  virtual void SetModifiedFlag(BOOL bModified = TRUE) override;
  virtual BOOL OnNewDocument() override;
  virtual BOOL OnOpenDocument(LPCTSTR lpszPathName) override;
  virtual BOOL OnSaveDocument(LPCTSTR lpszPathName) override;

  afx_msg void OnStartNextPhase();

  TAmbitFileBasedDocument* fileBasedDocument; // +0x50 (4-byte T-tree document adapter)

  DECLARE_MESSAGE_MAP()
};
ASSERT_SIZE(CAmbitDocument, 0x54);
