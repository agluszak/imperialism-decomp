#include "game/UiDialogHandlerPrefix.h"

#include "game/ApplicationUiRootController.h"
#include "game/TView.h"

extern "C" char PTR_s_TApplication_00648af8;

UiDialogHandlerPrefix::UiDialogHandlerPrefix()
    : field04(0), field08(0), field0c(0), field10(0x7fffffff), field14(0), field18(0), field1c(0) {}

// Prefix slot 0x00 (0x00486740 via ILT): return the TApplication RTTI name pointer.
// FUNCTION: IMPERIALISM 0x00486740
void* UiDialogHandlerPrefix::GetClassNamePointer() {
  return &PTR_s_TApplication_00648af8;
}

UiDialogHandlerPrefix::~UiDialogHandlerPrefix() {}

void UiDialogHandlerPrefix::vmethod_0002() {}
void UiDialogHandlerPrefix::vmethod_0003() {}
void UiDialogHandlerPrefix::vmethod_0004() {}
void UiDialogHandlerPrefix::vmethod_0005() {}
void UiDialogHandlerPrefix::vmethod_0006() {}
void UiDialogHandlerPrefix::CallVoidSlot1C() {}
void UiDialogHandlerPrefix::vmethod_0008() {}
void UiDialogHandlerPrefix::vmethod_0009() {}
char UiDialogHandlerPrefix::GetBoolSlot28() {
  return (char)field04;
}
void UiDialogHandlerPrefix::SetControlValue(int value) {
  field04 = (signed char)value;
}
int UiDialogHandlerPrefix::QueryStepValue() {
  return field0c;
}
void UiDialogHandlerPrefix::vmethod_0013() {}
void UiDialogHandlerPrefix::vmethod_0014() {}
void UiDialogHandlerPrefix::vmethod_0015() {}
void UiDialogHandlerPrefix::DispatchEvent(int arg1, void* arg2, int arg3) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
}
void UiDialogHandlerPrefix::vmethod_0017() {}
void UiDialogHandlerPrefix::ForwardParam(int param) {
  (void)param;
}
char UiDialogHandlerPrefix::vmethod_0019() {
  return 0;
}
void UiDialogHandlerPrefix::vmethod_0020() {}
void UiDialogHandlerPrefix::vmethod_0021() {}
TView* UiDialogHandlerPrefix::OwnerPanel() {
  return 0;
}
char UiDialogHandlerPrefix::vmethod_0023() {
  return 0;
}
char UiDialogHandlerPrefix::vmethod_0024() {
  return 0;
}
void UiDialogHandlerPrefix::vmethod_0025() {}
void UiDialogHandlerPrefix::vmethod_0026(int gate) {
  (void)gate;
}
void UiDialogHandlerPrefix::vmethod_0027() {}
void UiDialogHandlerPrefix::vmethod_0028() {}
void UiDialogHandlerPrefix::vmethod_0029() {}
void UiDialogHandlerPrefix::vmethod_0030() {}
char UiDialogHandlerPrefix::vmethod_0031() {
  return 0;
}
char UiDialogHandlerPrefix::vmethod_0080() {
  return 0;
}
void UiDialogHandlerPrefix::vmethod_0081() {}
void UiDialogHandlerPrefix::vmethod_0032() {}
void UiDialogHandlerPrefix::vmethod_0033(int arg) {
  (void)arg;
}
void UiDialogHandlerPrefix::vmethod_0034() {}
void UiDialogHandlerPrefix::vmethod_0035() {}
