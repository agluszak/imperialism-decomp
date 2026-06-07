#include "game/TStatusButton.h"

int g_pClassDescTStatusButton;

// FUNCTION: IMPERIALISM 0x00586330
TStatusButton::TStatusButton() : TButton() {}

int TStatusButton::ControlTag() const {
  return *reinterpret_cast<const int*>(reinterpret_cast<const char*>(this) + 0x1c);
}

void* TStatusButton::OwnerPanel() const {
  return *reinterpret_cast<void* const*>(reinterpret_cast<const char*>(this) + 0x20);
}
