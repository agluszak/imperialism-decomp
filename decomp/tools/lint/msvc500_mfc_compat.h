#pragma once

#ifndef IMPERIALISM_LINT
#error "MSVC500 MFC compatibility header is lint-only"
#endif

// MFC 4.2 enables optional inline bodies for non-debug builds. Two CMenu
// definitions in afxwin1.inl rely on VC5's implicit-int extension, which
// modern Clang rejects. The lint target is compile-only, so load the core MFC
// declarations once and suppress the remaining optional library bodies.
#include <afx.h>

#ifdef _AFX_ENABLE_INLINES
#undef _AFX_ENABLE_INLINES
#endif
