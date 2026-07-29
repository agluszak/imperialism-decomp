#pragma once

class TView;

class RandomSetupDriver {
public:
  explicit RandomSetupDriver(TView* root);

  short SelectedNationSlot() const;
  bool SetCountryName(const char* name);
  bool SelectDifficulty(unsigned long tag);
  bool Accept();

private:
  TView* root;
};
