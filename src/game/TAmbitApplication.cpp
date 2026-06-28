#include "game/TAmbitApplication.h"
#include "game/global_data_tables.h"
#include "game/TDisplayMgr.h"
#include "game/TViewMgr.h"
#include "game/TSimMgr.h"
#include "game/TAssetMgr.h"
#include "game/TView.h"
#include "game/TStream.h"
#include "game/TLanguageMgr.h"
#include "game/TMacViewMgr.h"
#include "game/THelpMgr.h"
#include "game/ui_invalidation_guard.h"

// GLOBAL: IMPERIALISM 0x0064c0b8
extern "C" CRuntimeClass TAmbitApplication_classRuntimeClass_0064c0b8 = {
    "TAmbitApplication", sizeof(TAmbitApplication), 0xffff, nullptr, nullptr, nullptr};

// SYNTHETIC: IMPERIALISM 0x004135f0
// TAmbitApplication::`scalar deleting destructor'
TAmbitApplication::~TAmbitApplication() {}

// FUNCTION: IMPERIALISM 0x00414770
void TAmbitApplication::VTableSlot2C() {
  // OrphanRetStub
}

TAmbitApplication::TAmbitApplication() : TApplication() {
  field_48 = 0;
  field_4c = 0;
  field_50 = 0;
}
IMPLEMENT_DYNCREATE(TAmbitApplication, TApplication)

// FUNCTION: IMPERIALISM 0x0049e1a0
void TAmbitApplication::Free() {
  if (g_pLanguageMgr != nullptr) {
    g_pLanguageMgr->Free();
    g_pLanguageMgr = nullptr;
  }
  if (g_pStrategicMapViewSystem != nullptr) {
    g_pStrategicMapViewSystem->Free();
    g_pStrategicMapViewSystem = nullptr;
  }
  if (g_pHelpMgr != nullptr) {
    g_pHelpMgr->Free();
    g_pHelpMgr = nullptr;
  }
  g_pLocalizationTable->Free();

  if (g_pUiViewManager != nullptr) {
    g_pUiViewManager->Free();
    g_pUiViewManager = nullptr;
  }
  if (g_pUiRuntimeContext != nullptr) {
    g_pUiRuntimeContext->Free();
    g_pUiRuntimeContext = nullptr;
  }
  if (g_pDisplayMgr != nullptr) {
    g_pDisplayMgr->Free();
    g_pDisplayMgr = nullptr;
  }
  if (g_pGameFlowState != nullptr) {
    reinterpret_cast<TObject*>(g_pGameFlowState)->Free();
    g_pGameFlowState = nullptr;
  }
  TApplication::Free();
}

extern "C" int __cdecl InvokeAfxThreadAndCallSecondaryRefresh();
unsigned int __cdecl GetTickCountDiv16();
extern "C" int DAT_006a21c0;

// FUNCTION: IMPERIALISM 0x0049e280
void TAmbitApplication::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  static const unsigned int kAddrSaveFormatVersion = 0x00695278;
  if (*reinterpret_cast<const int*>(kAddrSaveFormatVersion) < 0x2a) {
    stream->ReadBytes(&field_50, 2);
    field_50 = 0x00657573;
  } else {
    stream->ReadBytes(&field_50, 4);
  }
}

// FUNCTION: IMPERIALISM 0x0049e2f0
void TAmbitApplication::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&field_50, 4);
}

// FUNCTION: IMPERIALISM 0x0049e320
void TAmbitApplication::VTableSlot2B(int arg1, int arg2, int arg3) {
  int iVar3 = TemporarilyClearAndRestoreUiInvalidationFlag();
  if (iVar3 == 0 && activeView != nullptr) {
    extern TViewMgr* g_pUiRuntimeContext;
    short sVar1 = *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pUiRuntimeContext) + 0x4);
    if (sVar1 == 0x7dd || sVar1 == 0x3b8 || sVar1 == 0xed8 || sVar1 == 0xf3c || sVar1 == 0x3c0) {
      iVar3 = TemporarilyClearAndRestoreUiInvalidationFlag();
      if (iVar3 == 0) {
        POINT pt;
        pt.x = arg1;
        pt.y = arg2;

        TView* activeDialog = g_pDisplayMgr->activeDialog;
        activeDialog->UpdateAfterBitmapChange(reinterpret_cast<int>(&pt));

        if (pt.x > -200 && pt.y > -200) {
          int width = *reinterpret_cast<int*>(reinterpret_cast<char*>(activeDialog) + 0x34);
          int height = *reinterpret_cast<int*>(reinterpret_cast<char*>(activeDialog) + 0x38);
          if (pt.x < width + 200 && pt.y < height + 200) {
            byte bVar4 = 0;
            if (pt.x < 5) {
              bVar4 = 8;
            } else if (width - 4 <= pt.x) {
              bVar4 = 4;
            }
            if (pt.y < 5) {
              bVar4 |= 1;
            } else if (height - 4 <= pt.y) {
              bVar4 |= 2;
            }
            if (bVar4 != 0) {
              int ticks = GetTickCountDiv16();
              if (ticks < DAT_006a21c0 || DAT_006a21c0 + 3 < ticks) {
                DAT_006a21c0 = ticks;
                // (**(code **)((this[3].vftable)->GetTEventClassNamePointer + 0x1d0))(bVar4);
                // Wait! this[3] is activeView? No, this is TAmbitApplication.
                // In TApplication, CList<void*, void*> trackedEntries is at 0x2c (which is offset
                // 44). So this + 0x2c is trackedEntries. In the decompile: this[3].vftable is at
                // offset 0x30 (since sizeof(TSoundPlayer) or whatever? No, it's pointer arithmetic
                // on TNewGameCommand* which has size 16? Wait! pointer arithmetic on
                // TNewGameCommand*: this[3] is at offset 3 * sizeof(TNewGameCommand) = 3 * 0x10 =
                // 0x30? Yes! So it is at offset 0x30 from this, which is activeView! (activeView is
                // at 0x20, wait, activeView at 0x20, screenModeAt24 at 0x24, field28 at 0x28,
                // trackedEntries at 0x2c. Wait! What is at offset 0x30? Ah! in_ECX + 0x30 is inside
                // trackedEntries? Let's check TApplication layout: activeView is at +0x20. In the
                // decompile of HandleTurnEventViewportEdgeAutoScroll: this[3].vftable -> wait!
                // TNewGameCommand has some size. But this is TAmbitApplication. Let's check who is
                // this[3]. In the decompile: "this[3].vftable" is checked. Wait, this is
                // TAmbitApplication*. Let's check: activeView is at +0x20. Let's check the offset
                // of activeView! Yes, activeView is at +0x20. What is at +0x30? In TApplication,
                // CList trackedEntries is at +0x2c. CList has size 28 bytes? Or 24 bytes? Wait,
                // CList has: +0x00: vtable (4 bytes) +0x04: m_pNodeHead +0x08: m_pNodeTail
                // ...
                // So trackedEntries.vtable is at +0x2c.
                // What is at +0x30? It's trackedEntries.m_pNodeHead!
                // Wait! In the decompile:
                // "this[3].vftable != (TNewGameCommandVtbl *)0x0"
                // Wait, if this is TNewGameCommand* (with some size), this[3] means:
                // this + 3 * sizeof(TNewGameCommand).
                // But in TAmbitApplication:
                // What was in_ECX?
                // In the decompile:
                // "this" was typed TNewGameCommand*.
                // If it is actually TAmbitApplication*, then in_ECX + 0x30 is
                // trackedEntries.m_pNodeHead! But wait! Is it trackedEntries.m_pNodeHead? Or is it
                // activeView? Let's look at the assembly for 0x0049e320: 0049e32a  CMP dword ptr
                // [ESI + 0x30], 0 Ah! [ESI + 0x30]! What is at [ESI + 0x30]? Wait! If [ESI + 0x30]
                // is checked, and ESI is this (TAmbitApplication*). Wait! TApplication size is
                // 0x48. CList trackedEntries is at +0x2c. In MFC, CList has: +0x00 (0x2c):
                // m_pNodeHead +0x04 (0x30): m_pNodeTail +0x08 (0x34): m_nCount wait, does MFC CList
                // have a vtable? No, MFC CList is a template class, it does NOT have a vtable! But
                // wait, the comment in TApplication.h says: CList<void*, void*> trackedEntries; //
                // 0x2c, vtable 0x00648ca8 Wait! If it has a vtable 0x00648ca8, then it does have a
                // vtable! Why does it have a vtable? Because it inherits from CObject? Yes, MFC
                // templated collections like CList do not inherit from CObject, but wait, did the
                // game developers inherit from CObject or use a custom list? Ah! The comment says
                // "vtable 0x00648ca8". So it has a vtable at +0x2c, and m_pNodeHead is at +0x30!
                // Yes! [ESI + 0x30] is indeed m_pNodeHead!
                // And what does it do?
                // (**(code **)((this[3].vftable)->GetTEventClassNamePointer + 0x1d0))(bVar4);
                // Wait!
                // "this[3].vftable" is actually [this + 0x30], which is m_pNodeHead!
                // So it gets the first node of the list: node = trackedEntries.m_pNodeHead.
                // Then: (node->vftable)->GetTEventClassNamePointer?
                // No! node is a CNode.
                // In MFC CList:
                // struct CNode {
                //   CNode* pNext;
                //   CNode* pPrev;
                //   void* data;
                // };
                // So node->data is at offset +0x08 from node!
                // In the decompile:
                // "(this[3].vftable)->GetTEventClassNamePointer" is node + 0x08?
                // Wait! In the decompile:
                // "(this[3].vftable)->GetTEventClassNamePointer"
                // Let's check the assembly for this part:
                // 0049e3d9  MOV EAX,dword ptr [ESI + 0x30] ; EAX = m_pNodeHead (CNode*)
                // ...
                // 0049e3f4  MOV ECX,dword ptr [EAX + 0x8]  ; ECX = CNode->data
                // 0049e3fa  MOV EAX,dword ptr [ECX]        ; EAX = CNode->data->vtable
                // 0049e3fc  CALL dword ptr [EAX + 0x1d0]   ; Call virtual method at slot 0x1d0 of
                // CNode->data! YES! This is exactly calling virtual method at slot 0x1d0 of the
                // first element in trackedEntries! Let's write this in clean C++:
                if (!trackedEntries.IsEmpty()) {
                  void* data = trackedEntries.GetHead();
                  union {
                    void* p;
                    void (TView::*fn)(byte);
                  } u;
                  void** vtbl = *reinterpret_cast<void***>(data);
                  u.p = vtbl[116];
                  (reinterpret_cast<TView*>(data)->*u.fn)(bVar4);
                }
                return;
              }
            }
          }
        }
      }
    }
  }
  TApplication::HandleTurnEventViewportEdgeAutoScroll(arg1, arg2, arg3);
}

// FUNCTION: IMPERIALISM 0x0049e4b0
void TAmbitApplication::ForwardParam(int param) {
  if (g_pDisplayMgr != nullptr && g_pDisplayMgr->activeDialog != nullptr) {
    g_pDisplayMgr->activeDialog->ForwardParam(param);
  }
}

// FUNCTION: IMPERIALISM 0x0049e4e0
void TAmbitApplication::VTableSlot2D(void* param_1) {
  if (param_1 != nullptr) {
    union {
      void* p;
      void (TView::*fn)();
    } u;
    void** vtbl = *reinterpret_cast<void***>(param_1);
    u.p = vtbl[116];
    (reinterpret_cast<TView*>(param_1)->*u.fn)();
  }
}
