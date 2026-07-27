#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeHarnessCore is test-only and must not be included in the production build
#endif

struct RuntimeTestDescriptor;

class RuntimeProgressState {
public:
  RuntimeProgressState();

  void Reset(unsigned long now);
  void EnterPhase(const char* phase, const char* action, unsigned long now);
  void Finish();
  void CountTick();
  void MarkProgress(const char* action, unsigned long now);
  void MarkFallbackProgress(unsigned long now);
  bool HeartbeatDue(unsigned long now, unsigned long interval) const;
  void ResetHeartbeat();
  void MarkHeartbeatWritten(unsigned long now);

  bool IsFinished() const;
  const char* PhaseName() const;
  const char* LastAction() const;
  unsigned long ElapsedMs(unsigned long now) const;
  unsigned long PhaseElapsedMs(unsigned long now) const;
  unsigned long IdleTicks() const;
  unsigned long PhaseTicks() const;
  unsigned long ProgressCounter() const;
  unsigned long LastProgressMs() const;
  unsigned long LastHeartbeatMs() const;

private:
  bool finished;
  unsigned long idleTicks;
  unsigned long phaseTicks;
  unsigned long phaseStartMs;
  unsigned long startMs;
  unsigned long progressCounter;
  unsigned long lastProgressMs;
  unsigned long lastHeartbeatMs;
  char phaseName[64];
  char lastAction[64];
};

class RuntimeResultAggregate {
public:
  RuntimeResultAggregate();

  void Reset();
  void RecordAssertion(const char* assertionId, const char* failure, bool fatal);
  bool HasFailures() const;
  int FailureCount() const;
  const char* FirstAssertionId() const;
  const char* FirstFailure() const;

private:
  int failureCount;
  char firstAssertionId[96];
  char firstFailure[256];
};

int FindRuntimeDescriptorIndex(const char* name, const RuntimeTestDescriptor* descriptors,
                               int count);
bool EscapeRuntimeJsonString(const char* value, char* escaped, unsigned long capacity);
bool WriteRuntimeBytesAtomically(const char* path, const char* bytes, unsigned long size);
