#pragma once

// TEMP: ABI view over NationState metric slots used by trade amount bars.
// Replace with real NationState virtual methods once that vtable is recovered.
struct TradeNationMetricView {
  virtual void Slot00(void) = 0;
  virtual void Slot04(void) = 0;
  virtual void Slot08(void) = 0;
  virtual void Slot0C(void) = 0;
  virtual void Slot10(void) = 0;
  virtual void Slot14(void) = 0;
  virtual void Slot18(void) = 0;
  virtual void Slot1C(void) = 0;
  virtual void Slot20(void) = 0;
  virtual void Slot24(void) = 0;
  virtual void Slot28(void) = 0;
  virtual void Slot2C(void) = 0;
  virtual void Slot30(void) = 0;
  virtual void Slot34(void) = 0;
  virtual void Slot38(void) = 0;
  virtual void Slot3C(void) = 0;
  virtual void Slot40(void) = 0;
  virtual void Slot44(void) = 0;
  virtual void Slot48(void) = 0;
  virtual void Slot4C(void) = 0;
  virtual void Slot50(void) = 0;
  virtual void Slot54(void) = 0;
  virtual void Slot58(void) = 0;
  virtual void Slot5C(void) = 0;
  virtual void Slot60(void) = 0;
  virtual void Slot64(void) = 0;
  virtual void Slot68(void) = 0;
  virtual void Slot6C(void) = 0;
  virtual void Slot70(void) = 0;
  virtual void Slot74(void) = 0;
  virtual short QueryNationMetricBySlot78(short metricSlot) = 0;
  virtual short QueryNationMetricBySlot7C(short metricSlot) = 0;
};
