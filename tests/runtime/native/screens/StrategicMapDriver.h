#pragma once

class TView;

class StrategicMapDriver {
public:
  explicit StrategicMapDriver(TView* root);

  bool EndTurn();
  bool ActivateCity();

private:
  TView* root;
};
