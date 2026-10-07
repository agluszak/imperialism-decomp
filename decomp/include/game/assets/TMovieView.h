#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

struct MciMovieWindowState;

// VTABLE: IMPERIALISM 0x0066f708
class TMovieView : public TPicture {
public:
  DECLARE_DYNCREATE(TMovieView)
  virtual ~TMovieView() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual bool HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  MciMovieWindowState* movieWindowState;

  TMovieView();
  bool OpenMoviePathAndDetachOnSuccess(LPCSTR moviePath);
  void PlayTheMovie(); // (MCI_PLAY)
  void StopMovie();    // (MCI_STOP / skip)
};

ASSERT_SIZE(TMovieView, 0x94);
