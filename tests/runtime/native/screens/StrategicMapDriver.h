#pragma once

class TView;

class StrategicMapDriver {
public:
  explicit StrategicMapDriver(TView* root);

  bool EndTurn();
  bool ActivateCity();
  bool ActivateTransport();
  bool ActivateDiplomacy();
  bool ActivateTrade();

private:
  TView* root;
};
