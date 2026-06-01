#pragma once

// VTABLE: IMPERIALISM 0x0066FEC4
class TEventHandler {
public:
  int field04;
  unsigned char padding_08_to_0b[0x04];
  int field0c;

  TEventHandler() {}
  virtual void* GetTEventHandlerClassNamePointer() { return 0; }
  virtual ~TEventHandler() {}
};
