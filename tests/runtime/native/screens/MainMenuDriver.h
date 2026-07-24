#pragma once

class TView;

class MainMenuDriver {
public:
  explicit MainMenuDriver(TView* root);
  bool StartRandomGame();

private:
  TView* root;
};
