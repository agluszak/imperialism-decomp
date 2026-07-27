#pragma once

class TView;

class RandomSetupDriver {
public:
  explicit RandomSetupDriver(TView* root);

  short SelectedNationSlot() const;
  bool SetCountryName(const char* name);
  bool SelectDifficultySemantically(unsigned long tag);
  bool AcceptSemantically();

private:
  TView* root;
};
