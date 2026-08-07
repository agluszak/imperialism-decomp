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

// What a scenario is currently waiting for. Before this existed, `Await` took a failure
// description and dropped it, so a stalled run reported only its phase and last action --
// the reader could see that nothing was happening but not what the scenario expected to
// happen. Armed on every wait, cleared when the wait is satisfied, and published in both
// the heartbeat and the result file.
class RuntimeAwaitState {
public:
  RuntimeAwaitState();

  void Clear();
  void Arm(unsigned int observationKinds, const char* expression, const char* file, int line);

  bool IsArmed() const;
  unsigned int ObservationKinds() const;
  const char* Expression() const;
  // "EndTurnTest.cpp:76" -- basename only, because __FILE__ is an absolute Wine path.
  const char* Source() const;

private:
  unsigned int observationKinds;
  bool armed;
  char expression[192];
  char source[96];
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

// Render an observation mask as a stable pipe-separated name list, e.g.
// "paint_completed|game_state_changed". The full composite collapses to
// "ui_state_changed" so the common case stays readable. Needs 256 bytes for the widest
// mask; returns false (and writes "?") when the buffer is too small.
bool DescribeRuntimeObservationMask(unsigned int observationKinds, char* text,
                                    unsigned long capacity);
// The file-name component of a path, for turning __FILE__ into a short source location.
const char* RuntimeSourceBasename(const char* path);
