#pragma once

class TView;

class StrategicMapDriver {
public:
  explicit StrategicMapDriver(TView* root);

  bool EndTurn();
  bool OpenCity();
  bool ActivateTransport();
  bool OpenDiplomacy();
  bool OpenTrade();

private:
  TView* root;
};
