#pragma once

class TCivilianOrderState {
public:
  void* vftable;          // 0x00
  short civilianClassId;  // 0x04
  short currentTileIndex; // 0x06
  int pad_08;
  int pad_0c;
  int pad_10;
  TCivilianOrderState* nextOnTile; // 0x14 — per-tile civilian-order chain
  short ownerNationSlot18;         // 0x18 — recruit-tile scan (0x00514cd0)
  short pad1a;

  int IsInIdleSelectionState();
};
