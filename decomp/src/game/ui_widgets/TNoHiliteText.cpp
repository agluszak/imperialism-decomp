#include "game/ui_widgets/TNoHiliteText.h"

IMPLEMENT_DYNCREATE(TNoHiliteText, TStaticText)

// FUNCTION: IMPERIALISM 0x005b6a00
TNoHiliteText::TNoHiliteText() {}

// No own destructor: the original's 0x005b6a60 is an ILT thunk to the base's
// ~TStaticText (0x0048fc30), so this class inherits it. The scalar deleting destructor above is what
// the vtable slot holds.
