#pragma once

#include "game/ui_core/TView.h"

namespace turn_event_dialog {

struct TurnEventMapSelection {
  short unresolved0;
  short cityRecordIndex;
};

struct UnreachableTacticalMapPictureControl : public TView {
  virtual void ApplySelection(TurnEventMapSelection* value);
};

} // namespace turn_event_dialog
