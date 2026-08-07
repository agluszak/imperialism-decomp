#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeObservation is test-only and must not be included in the production build
#endif

enum RuntimeObservationKind {
  kObserveNone = 0,
  kObserveApplicationIdle = 1 << 0,
  kObserveMainViewChanged = 1 << 1,
  kObserveModalPushed = 1 << 2,
  kObserveModalPopped = 1 << 3,
  kObserveAnimationAdded = 1 << 4,
  kObserveAnimationRemoved = 1 << 5,
  kObservePaintCompleted = 1 << 6,
  kObserveInvalidationRequested = 1 << 7,
  kObserveTurnEventActivated = 1 << 8,
  kObserveUiTreeBuilt = 1 << 9,
  kObserveGameStateChanged = 1 << 10,
  kObserveRuntimeBarrier = 1 << 11
};

const unsigned int kObserveUiStateChanged =
    kObserveMainViewChanged | kObserveModalPushed | kObserveModalPopped | kObserveAnimationAdded |
    kObserveAnimationRemoved | kObservePaintCompleted | kObserveInvalidationRequested |
    kObserveTurnEventActivated | kObserveUiTreeBuilt | kObserveGameStateChanged |
    kObserveRuntimeBarrier;
