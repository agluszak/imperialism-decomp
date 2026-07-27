#include "RuntimeTurnEventQueue.h"

RuntimeTurnEventQueue::RuntimeTurnEventQueue() : head(0), count(0) {}

bool RuntimeTurnEventQueue::Push(int eventCode) {
  if (count == kCapacity) {
    return false;
  }
  int tail = (head + count) % kCapacity;
  events[tail] = eventCode;
  ++count;
  return true;
}

bool RuntimeTurnEventQueue::Pop(int& eventCode) {
  if (count == 0) {
    return false;
  }
  eventCode = events[head];
  head = (head + 1) % kCapacity;
  --count;
  return true;
}

int RuntimeTurnEventQueue::Count() const {
  return count;
}
