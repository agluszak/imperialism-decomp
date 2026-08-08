#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeTurnEventQueue is test-only and must not be included in the production build
#endif

class RuntimeTurnEventQueue {
public:
  enum { kCapacity = 32 };

  RuntimeTurnEventQueue();
  bool Push(int eventCode);
  bool Pop(int& eventCode);
  int Count() const;

private:
  int events[kCapacity];
  int head;
  int count;
};
