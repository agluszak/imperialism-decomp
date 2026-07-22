#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

struct MciMovieWindowState;

// VTABLE: IMPERIALISM 0x0066f708
class TMovieView : public TPicture {
public:
  DECLARE_DYNCREATE(TMovieView)
  virtual ~TMovieView() override;               // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5e23f0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5e2490
  virtual char HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                               CPoint origin) override; // slot 0x46 0x5e2520
  MciMovieWindowState* movieWindowState;                // +0x90

  TMovieView();
  bool OpenMoviePathAndDetachOnSuccess(LPCSTR moviePath); // 0x5e24b0
  void PlayMovieIfActive();                               // 0x5e24e0 (MCI_PLAY)
  void StopMovieIfActive();                               // 0x5e2500 (MCI_STOP / skip)
};

ASSERT_SIZE(TMovieView, 0x94);
