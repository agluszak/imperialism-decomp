#pragma once

#include "game/core/CString.h"
#include "game/mfc.h"

class TDropShadowText;
class TDropShadowNumberText;
class TStaticText;
class TView;
struct TextStyle;

// Text-style and control-theme helpers (ui_text_label_helpers.cpp).

void ResolveUiThemeColor(short themeCode, COLORREF* outColor);
void BuildUiTextStyleDescriptor(TextStyle* styleDescriptor, int unused, int fontSize,
                                int themeCode);
void InitializeUiTextStyleDescriptor(TextStyle* styleDescriptor, short face, short pointSize,
                                     int themeCode, short font);

TStaticText* ApplyControlTheme(TStaticText* control, int unused2, int pointSize, int themeCode,
                               int themeCode2, const char* caption);

TStaticText* ConfigureControlFromStrings(TStaticText* control, int unused2, int pointSize,
                                         int themeCode, int themeCode2, int stringResourceGroup,
                                         short stringResourceIndex);

void ApplyTextStyle(int unused, int styleWidth, int themeCode);
void SetTextStyleAndApply(short face, short pointSize, int themeCode, short font);

void SetControlHoverHelpText(CString sharedString, TView* control);
void SetControlHoverHelpTextAltEntry(CString sharedString, TView* control);

void SendStringCommand(short group, short index, TView* control);

void __cdecl DispatchToSelectableTextOptionEntries(TView* view, TextStyle* state, int flag);

TStaticText* __cdecl RefreshAndTheme(unsigned int controlTag, int unused2, int pointSize,
                                     int themeCode, int themeCode2, const char* caption);

void __cdecl ApplyUiTextStyleAndThemeFlags(TDropShadowText* control, int unused, int pointSize,
                                           int shadowThemeCode, int textThemeCode);

void __cdecl ApplyUiNumberTextStyleAndThemeColor(TDropShadowNumberText* control, int unused,
                                                 int pointSize, int shadowThemeCode,
                                                 int textThemeCode);

void SetTaggedStringAndApply(short group, short index, unsigned int controlTag);

void SetTaggedString(short group, short index, unsigned int controlTag);

class TView;

TView* __cdecl ApplySharedStringToGlobalControlTag(CString sharedString, unsigned int controlTag);

void SetControlString(short group, short index, TView* control);

TView* __cdecl SetTaggedControlText(const char* text, unsigned int controlTag);
