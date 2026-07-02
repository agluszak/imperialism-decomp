#pragma once

#include "game/mfc.h"

class TAmbitFileBasedDocument;

// MFC document class for the SDI doc template (CRuntimeClass @ 0x0063e7f8, m_lpszClassName
// CAmbitDocument, m_nObjectSize 0x54, vtable 0x00645eb8). The ctor also owns creating the
// global turn-event dialog-factory registry and registering the startup factories.
class CAmbitDocument : public CDocument {
public:
  DECLARE_DYNCREATE(CAmbitDocument)

  CAmbitDocument();          // 0x479480
  virtual ~CAmbitDocument(); // 0x479710

  TAmbitFileBasedDocument* fileBasedDocument50; // +0x50 (4-byte T-tree document adapter)
};
