#pragma once

#include "RuntimeTestCase.h"

class RuntimeContext;

enum RuntimeScenarioCompletion {
  kCompleteOnManagers,
  kCompleteOnEasyMap,
  kCompleteAfterTurns,
  kCompleteOnCityScreen,
  kCompleteAfterNormalJourney,
  kCompleteAfterLoadedMap
};

struct RuntimeScenarioConfig {
  const char* name;
  RuntimeScenarioCompletion completion;
  bool randomGame;
  bool easyDifficulty;
  bool recordGameFlow;
};

class RuntimeScenario : public RuntimeTestCase {
public:
  explicit RuntimeScenario(const RuntimeScenarioConfig& config);

  void Start(RuntimeContext& context) override;
  void Tick(RuntimeContext& context) override;
  void ObserveTurnEvent(RuntimeContext& context, int eventCode) override;
  void ObserveBuiltUiTree(RuntimeContext& context, int eventCode, TView* root) override;
  unsigned int RandomSeed(RuntimeContext& context) override;

private:
  const RuntimeScenarioConfig& config;
};
