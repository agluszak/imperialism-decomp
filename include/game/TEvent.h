#pragma once

// McApp UI command/event record passed through TEventHandler::DoEvent/HandleEvent.
// Layout is only partially recovered; callers treat it as an opaque pointer.
class TEvent {
public:
  unsigned char pad00[0x1c];
  int commandTag1c;
};
