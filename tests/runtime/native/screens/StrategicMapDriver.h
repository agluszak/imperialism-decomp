#pragma once

class TView;

class StrategicMapDriver {
public:
  explicit StrategicMapDriver(TView* root);

  bool EndTurn();
  bool ActivateCity();
  bool ActivateDiplomacy();
  bool ActivateTrade();

private:
  TView* root;
};
