#pragma once

class TView;

class MainMenuDriver {
public:
  explicit MainMenuDriver(TView* root);
  bool StartRandomGameSemantically();

private:
  TView* root;
};
