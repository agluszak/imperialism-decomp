#pragma once

class TView;

class StrategicMapDriver {
public:
  explicit StrategicMapDriver(TView* root);

  bool EndTurnThroughNativeMessages();
  bool ActivateCitySemantically();
  bool ActivateDiplomacySemantically();
  bool ActivateTradeSemantically();

private:
  TView* root;
};
