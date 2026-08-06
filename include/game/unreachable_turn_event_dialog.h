#pragma once

#include "game/ui_core/TView.h"

namespace turn_event_dialog {

struct TurnEventMapSelection {
  short unresolved0;
  short cityRecordIndex2;
};

// ABI view used only by dead TViewMgr slot 0xe8 (0x005dd770). The body asks the factory
// for 0x0f0a, but that id is a tactical-map PICT and no Windows factory owns it; the
// slot has no code xrefs. Consequently no constructible retail receiver class exists
// to name here. This declaration preserves the unreachable original dispatch without
// pretending that it is a recovered resource class.
struct UnreachableTacticalMapPictureControl : public TView {
  virtual void ApplySelection(TurnEventMapSelection* value); // slot 0x68 byte 0x1a0
};

} // namespace turn_event_dialog
