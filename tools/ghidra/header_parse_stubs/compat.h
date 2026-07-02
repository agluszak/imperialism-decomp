#ifndef COMPAT_H
#define COMPAT_H

/* Minimal compat.h for header parsing (pcpp cannot handle MSVC #pragma warning). */

#if __cplusplus < 201103L
#define override
#define nullptr 0
#endif

/* MFC RTTI/message-map macros expand from afx*.h in the real build; afx*.h is
 * not stubbed for parsing, so expand them to nothing here (they contribute no
 * instance fields, which is all the header-parse pipeline extracts). */
#define DECLARE_DYNAMIC(class_name)
#define DECLARE_DYNCREATE(class_name)
#define DECLARE_SERIAL(class_name)
#define DECLARE_MESSAGE_MAP()
#define afx_msg

#endif
