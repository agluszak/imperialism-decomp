#pragma once

class TView;
class CString;

class MainMenuDriver {
public:
  explicit MainMenuDriver(TView* root);
  bool StartRandomGame(CString* failure = 0);

private:
  TView* root;
};
