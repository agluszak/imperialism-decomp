#pragma once

#include "game/app/TObject.h"

// VTABLE: IMPERIALISM 0x00645f98
class ArchiveStreamAdapter : public TObject {
public:
  CArchive* archive;

  ArchiveStreamAdapter(CArchive* pArchive) : archive(pArchive) {}
  ~ArchiveStreamAdapter() override;
};

ASSERT_SIZE(ArchiveStreamAdapter, 0x8);
