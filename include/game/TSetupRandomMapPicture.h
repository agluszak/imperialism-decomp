#pragma once

#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006621e0
class TSetupRandomMapPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TSetupRandomMapPicture)
  virtual ~TSetupRandomMapPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;           // slot 0x0f 0x005779c0
  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x5782f0
  virtual void DoPostCreate(int arg) override;            // slot 0x37 0x577030
  virtual void StartGame();                               // slot 0x74 0x577e40
  virtual void ExitScreen();                              // slot 0x75 0x5781f0

  TSetupRandomMapPicture();

  void RecheckCountryName();                        // 0x576fe0
  void GroundControlToMajorTom(unsigned char mode); // 0x578230
  void MajorTomToGroundControl(unsigned char mode); // 0x578330
  void SpinYourGlobe();                             // 0x578680

  CString planetSeed94;                // 0x94 — random-map seed text
  unsigned char wrapHorizontally98;    // 0x98 — copied to TMapMgr+0x20
  unsigned char pad99;                 // 0x99
  short selectedNationSlot9A;          // 0x9a — selected great-power slot
  unsigned int lastGlobeTick9C;        // 0x9c — spinner timestamp
  int globeFrameA0;                    // 0xa0 — 0..23 spinner frame
  unsigned char countryControlReadyA4; // 0xa4 — ctor zeroes it
  unsigned char padA5[3];              // 0xa5
};
ASSERT_SIZE(TSetupRandomMapPicture, 0xa8);
