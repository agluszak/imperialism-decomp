#pragma once

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006621e0
class TSetupRandomMapPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TSetupRandomMapPicture)
  virtual ~TSetupRandomMapPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void StartGame();
  virtual void ExitScreen();

  TSetupRandomMapPicture();

  void RecheckCountryName();
  void PickCountry(short nationSlot);
  void GroundControlToMajorTom(unsigned char mode);
  void MajorTomToGroundControl(unsigned char mode);
  void SpinYourGlobe();

  CString planetSeed;             // random-map seed text
  unsigned char wrapHorizontally; // copied to TMapMgr+0x20
  unsigned char pad99;
  short selectedNationSlot;   // selected great-power slot
  unsigned int lastGlobeTick; // spinner timestamp
  int globeFrame;             // 0..23 spinner frame
  bool countryControlReady;   // ctor zeroes it
};
ASSERT_SIZE(TSetupRandomMapPicture, 0xa8);
