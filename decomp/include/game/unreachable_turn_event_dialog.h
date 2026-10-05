#pragma once

#include "game/ui_core/TView.h"

namespace turn_event_dialog {

struct TurnEventMapSelection {
  short unresolved0;
  short cityRecordIndex2;
};

struct UnreachableTacticalMapPictureControl : public TView {
  virtual void ApplySelection(TurnEventMapSelection* value); // slot 0x68 byte 0x1a0
};

} // namespace turn_event_dialog
