// Annotation-only carrier. Scanned by source_model and reccmp for LIBRARY/SYNTHETIC
// identity markers; excluded from the product compile TU list in CMakeLists.txt.
// CRT/MFC library and synthetic identity claims. Ownership plus reccmp
// name/symbol/prototype overlays live here as // LIBRARY or // SYNTHETIC markers.
// Accepting an object-matcher oracle hit means adding a block below.

// LIBRARY: IMPERIALISM 0x00412600 SYMBOL
// ??_H@YGXPAXIHP6EX0@Z@Z
// name: `vector constructor iterator'
// prototype: void __stdcall `vector constructor iterator'(void * base,unsigned int elementSize,int count,void * (__thiscall * ctor)(void *))

// LIBRARY: IMPERIALISM 0x00412bd0
// CObject::Serialize

// LIBRARY: IMPERIALISM 0x00412bf0
// CObject::AssertValid

// LIBRARY: IMPERIALISM 0x00412c10
// CObject::Dump

// LIBRARY: IMPERIALISM 0x00413380
// CObject::operator delete

// LIBRARY: IMPERIALISM 0x004133a0
// MFC nafxcw registry helper: RegCloseKey on the handle at [ecx], then
// clears it. Part of the CWinApp registry-key cluster around AfxGetAppRegistryKey.

// LIBRARY: IMPERIALISM 0x00415000
// MFC/CRT file-find close: if [ecx] holds a find handle (!= -1), calls
// _findclose and resets it. CFileFind::Close shape.

// LIBRARY: IMPERIALISM 0x00415030 SYMBOL
// ?DoDataExchange@CWnd@@MAEXPAVCDataExchange@@@Z
// name: CWnd::DoDataExchange
// prototype: protected: virtual void __thiscall CWnd::DoDataExchange(class CDataExchange *)

// LIBRARY: IMPERIALISM 0x00415050 SYMBOL
// ?BeginModalState@CWnd@@UAEXXZ
// name: CWnd::BeginModalState
// prototype: public: virtual void __thiscall CWnd::BeginModalState(void)

// LIBRARY: IMPERIALISM 0x00415070 SYMBOL
// ?EndModalState@CWnd@@UAEXXZ
// name: CWnd::EndModalState
// prototype: public: virtual void __thiscall CWnd::EndModalState(void)

// LIBRARY: IMPERIALISM 0x00415c00 SYMBOL
// ??1CWaitCursor@@QAE@XZ
// name: CWaitCursor::~CWaitCursor
// prototype: public: __thiscall CWaitCursor::~CWaitCursor(void)

// SYNTHETIC: IMPERIALISM 0x00415f00
// CObject::`scalar deleting destructor'

// LIBRARY: IMPERIALISM 0x00415f30 SYMBOL
// ??1CObject@@UAE@XZ
// name: CObject::~CObject
// prototype: public: virtual __thiscall CObject::~CObject(void)

// LIBRARY: IMPERIALISM 0x0041b1c0
// CObject::operator new

// LIBRARY: IMPERIALISM 0x0041b1e0 SYMBOL
// ??0CRect@@QAE@HHHH@Z
// name: CRect::CRect
// prototype: public: __thiscall CRect::CRect(int,int,int,int)

// SYNTHETIC: IMPERIALISM 0x0041b6b0
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00427310
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00429580
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00430c30
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00435790
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0043dba0
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0044a7f0
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0044af70
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0044fba0
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00453880
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0045b0e0
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0045d500
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0045e090
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00460190
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0046fcf0
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00474980
// ownership-only

// SYNTHETIC: IMPERIALISM 0x004793a0
// ownership-only

// LIBRARY: IMPERIALISM 0x00479ba0 SYMBOL
// ?GetFirstDocTemplatePosition@CDocManager@@UBEPAU__POSITION@@XZ
// name: CDocManager::GetFirstDocTemplatePosition
// prototype: public: virtual struct __POSITION * __thiscall CDocManager::GetFirstDocTemplatePosition(void) const

// SYNTHETIC: IMPERIALISM 0x0047ca90 SYMBOL
// ??_GCPalette@@UAEPAXI@Z
// name: CPalette::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CPalette::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0047cac0
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0047cb30 SYMBOL
// ??_GCGdiObject@@UAEPAXI@Z
// name: CGdiObject::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CGdiObject::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0047cb60
// ownership-only

// LIBRARY: IMPERIALISM 0x0047d960
// CGdiObject::~CGdiObject

// LIBRARY: IMPERIALISM 0x0047d9d0
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0047da40 SYMBOL
// ??_GCRgn@@UAEPAXI@Z
// name: CRgn::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CRgn::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0047da70
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0047e200 SYMBOL
// ??_GCButton@@UAEPAXI@Z
// name: CButton::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CButton::`scalar deleting destructor'(unsigned int)

// SYNTHETIC: IMPERIALISM 0x0047e230 SYMBOL
// ??_GCListBox@@UAEPAXI@Z
// name: CListBox::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CListBox::`scalar deleting destructor'(unsigned int)

// SYNTHETIC: IMPERIALISM 0x0047e260 SYMBOL
// ??_GCSliderCtrl@@UAEPAXI@Z
// name: CSliderCtrl::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CSliderCtrl::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0047e550 SYMBOL
// ?GetEntryCount@CPalette@@QAEHXZ
// name: CPalette::GetEntryCount
// prototype: public: int __thiscall CPalette::GetEntryCount(void)

// LIBRARY: IMPERIALISM 0x0047ec00 SYMBOL
// ??1CFileDialog@@UAE@XZ
// name: CFileDialog::~CFileDialog
// prototype: public: virtual __thiscall CFileDialog::~CFileDialog(void)

// LIBRARY: IMPERIALISM 0x0047f760
// MFC container teardown (one of three byte-identical bodies at
// 0x47f760/0x5e27c0/0x5e2870): for each of count slots, run the element
// cleanup thunk then operator_delete; then operator_delete the table and
// zero head/count globals. MFC template/library code, not game source.

// LIBRARY: IMPERIALISM 0x004845f0
// ownership-only

// LIBRARY: IMPERIALISM 0x0048d2c0
// MFC frame-modal window-list pop (winfrm.obj family): unlinks a node from
// the DAT_006a1ac4 disable-list head, returns it to the CPlex freelist, and
// re-enables the next tracked top-level window via CWnd::EnableWindow.
// Paired with the push body at 0x48d390 (CFrameWnd modal state machinery).

// LIBRARY: IMPERIALISM 0x0048d390
// MFC frame-modal window-list push (winfrm.obj family): disables the current
// top-level window via CWnd::EnableWindow(0), then links a new node onto the
// DAT_006a1ac4 list (CPlex freelist allocation at DAT_006a1ad0).
// CFrameWnd modal-state machinery -- MFC library code.

// LIBRARY: IMPERIALISM 0x004919e0 SYMBOL
// ?GetStream@COleStreamFile@@QBEPAUIStream@@XZ
// name: COleStreamFile::GetStream
// prototype: public: struct IStream * __thiscall COleStreamFile::GetStream(void) const

// LIBRARY: IMPERIALISM 0x00492420 SYMBOL
// ?GetFirstDocTemplatePosition@CDocManager@@UBEPAU__POSITION@@XZ
// name: CDocManager::GetFirstDocTemplatePosition
// prototype: public: virtual struct __POSITION * __thiscall CDocManager::GetFirstDocTemplatePosition(void) const

// LIBRARY: IMPERIALISM 0x004924c0
// ownership-only

// LIBRARY: IMPERIALISM 0x00494340 SYMBOL
// ??_GCPen@@UAEPAXI@Z
// name: CPen::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CPen::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00494370
// ownership-only

// LIBRARY: IMPERIALISM 0x004943e0
// WrapperFor_AppendPointerToGlobalVectorAsStatus_At004943e0

// LIBRARY: IMPERIALISM 0x00494430
// ReleaseQuickDrawCachedFontHandleIfPresent_At00494430

// LIBRARY: IMPERIALISM 0x00494460
// WrapperFor_AppendPointerToGlobalVectorAsStatus_At00494460

// LIBRARY: IMPERIALISM 0x004944b0
// ReleaseCachedGlobalFontObjectIfPresent_At004944b0

// LIBRARY: IMPERIALISM 0x00497400
// ownership-only

// LIBRARY: IMPERIALISM 0x00497470
// ownership-only

// LIBRARY: IMPERIALISM 0x00497b00 SYMBOL
// ??_GCBrush@@UAEPAXI@Z
// name: CBrush::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CBrush::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00497c20
// ownership-only

// LIBRARY: IMPERIALISM 0x00497c40
// ownership-only

// LIBRARY: IMPERIALISM 0x00497c60
// ownership-only

// LIBRARY: IMPERIALISM 0x004985b0 SYMBOL
// ??0CGdiObject@@QAE@XZ
// name: CGdiObject::CGdiObject
// prototype: public: __thiscall CGdiObject::CGdiObject(void)

// LIBRARY: IMPERIALISM 0x004985d0 SYMBOL
// ?CreatePen@CPen@@QAEHHHK@Z
// name: CPen::CreatePen
// prototype: public: int __thiscall CPen::CreatePen(int,int,unsigned long)

// SYNTHETIC: IMPERIALISM 0x004986a0
// TScopedQuickDrawPen::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall TScopedQuickDrawPen::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0049eb00
// ownership-only

// LIBRARY: IMPERIALISM 0x004ac370
// ownership-only

// LIBRARY: IMPERIALISM 0x004b0970
// ownership-only

// LIBRARY: IMPERIALISM 0x004bdcf0 SYMBOL
// ??0CRect@@QAE@HHHH@Z
// name: CRect::CRect
// prototype: public: __thiscall CRect::CRect(int,int,int,int)
// second emission of the 0x41b1e0 body (per-TU duplicate); 9 call sites.

// LIBRARY: IMPERIALISM 0x004d6b70
// CString::operator= forwarder: calls the shared-body assign then returns
// this. MFC strcore.obj family.

// LIBRARY: IMPERIALISM 0x004fe5c0
// CDC::SelectPalette wrapper: SelectPalette([ecx+4] DC, bForceBkgd=0).
// MFC afxwin/dc inline out-of-line copy.

// LIBRARY: IMPERIALISM 0x00525810
// CDC::SelectClipRgn wrapper: SelectClipRgn(*[ecx], NULL). MFC dc inline
// out-of-line copy.

// LIBRARY: IMPERIALISM 0x0054ae70
// CStringData release tail: InterlockedDecrement on the shared-data refcount
// at [ecx+0xc4]-0xc, operator_delete on zero -- MFC CString::FreeData shape.

// LIBRARY: IMPERIALISM 0x00556320
// CFrameWnd::GetActiveFrame (unique msvc500 oracle hit, winfrm.obj):
// 3-byte `mov eax,ecx; ret` -- returns this.

// LIBRARY: IMPERIALISM 0x005d5d10 SYMBOL
// ??BCString@@QBEPBDXZ
// name: CString::operator char const *
// prototype: public: __thiscall CString::operator char const *(void) const

// LIBRARY: IMPERIALISM 0x005db2f0
// CString::GetLength

// LIBRARY: IMPERIALISM 0x005df610 SYMBOL
// ??1CObject@@UAE@XZ
// name: CObject::~CObject
// prototype: public: virtual __thiscall CObject::~CObject(void)

// LIBRARY: IMPERIALISM 0x005df630 SYMBOL
// ??_GCResourceException@@UAEPAXI@Z
// name: CResourceException::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CResourceException::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005df660
// MFC exception-object destructor tail (CFileException/CException family):
// EH frame, exception-vftable store, CString member dtor, CObject vftable
// restore.

// LIBRARY: IMPERIALISM 0x005e27c0
// MFC container teardown -- see the triplicate note at 0x47f760.

// LIBRARY: IMPERIALISM 0x005e2870
// MFC container teardown -- see the triplicate note at 0x47f760.

// LIBRARY: IMPERIALISM 0x005e4a90
// CPtrArray::SetSize

// LIBRARY: IMPERIALISM 0x005e538c
// MFC nafxcw handler in the CDialog-derived message maps 0x66fb20/0x673208
// (ON_COMMAND id 2): `mov eax,[ecx]; jmp [eax+0xcc]` virtual-call forwarder.

// LIBRARY: IMPERIALISM 0x005e5394
// MFC nafxcw handler in the CDialog-derived message maps 0x66fb20/0x673208
// (ON_COMMAND id 1 / id 0x64): `mov eax,[ecx]; jmp [eax+0xcc]` virtual-call forwarder.

// LIBRARY: IMPERIALISM 0x005e539c SYMBOL
// ?AfxGetMainWnd@@YGPAVCWnd@@XZ
// name: AfxGetMainWnd
// prototype: class CWnd * __stdcall AfxGetMainWnd(void)

// LIBRARY: IMPERIALISM 0x005e53bc
// CNoTrackObject::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CNoTrackObject::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e53d8 SYMBOL
// ?CreateObject@?$CThreadLocal@VAFX_MODULE_THREAD_STATE@@@@SGPAVCNoTrackObject@@XZ
// name: CThreadLocal<class AFX_MODULE_THREAD_STATE>::CreateObject
// prototype: public: static class CNoTrackObject * __stdcall CThreadLocal<class AFX_MODULE_THREAD_STATE>::CreateObject(void)

// LIBRARY: IMPERIALISM 0x005e540c SYMBOL
// ?CreateObject@?$CThreadLocal@V_AFX_THREAD_STATE@@@@SGPAVCNoTrackObject@@XZ
// name: _AFX_THREAD_STATE>::CreateObject
// prototype: public: static class CNoTrackObject * __stdcall CThreadLocal<class _AFX_THREAD_STATE>::CreateObject(void)

// LIBRARY: IMPERIALISM 0x005e5440 SYMBOL
// ?CreateObject@?$CProcessLocal@V_AFX_CTL3D_STATE@@@@SGPAVCNoTrackObject@@XZ
// name: _AFX_CTL3D_STATE>::CreateObject
// prototype: public: static class CNoTrackObject * __stdcall CProcessLocal<class _AFX_CTL3D_STATE>::CreateObject(void)

// LIBRARY: IMPERIALISM 0x005e5455 SYMBOL
// ??_G_AFX_CTL3D_STATE@@UAEPAXI@Z
// name: _AFX_CTL3D_STATE::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall _AFX_CTL3D_STATE::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e5470 SYMBOL
// ?CreateObject@?$CThreadLocal@V_AFX_CTL3D_THREAD@@@@SGPAVCNoTrackObject@@XZ
// name: _AFX_CTL3D_THREAD>::CreateObject
// prototype: public: static class CNoTrackObject * __stdcall CThreadLocal<class _AFX_CTL3D_THREAD>::CreateObject(void)

// LIBRARY: IMPERIALISM 0x005e5485 SYMBOL
// ??_G_AFX_CTL3D_THREAD@@UAEPAXI@Z
// name: _AFX_CTL3D_THREAD::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall _AFX_CTL3D_THREAD::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e54a0 SYMBOL
// ?CreateObject@?$CProcessLocal@V_AFX_WIN_STATE@@@@SGPAVCNoTrackObject@@XZ
// name: _AFX_WIN_STATE>::CreateObject
// prototype: public: static class CNoTrackObject * __stdcall CProcessLocal<class _AFX_WIN_STATE>::CreateObject(void)

// LIBRARY: IMPERIALISM 0x005e54d1 SYMBOL
// ?GetOwner@CWnd@@QBEPAV1@XZ

// LIBRARY: IMPERIALISM 0x005e54e8 SYMBOL
// ??1CHandleMap@@QAE@XZ
// name: CHandleMap::~CHandleMap
// prototype: public: __thiscall CHandleMap::~CHandleMap(void)

// LIBRARY: IMPERIALISM 0x005e5529 SYMBOL
// ??1CDragListBox@@UAE@XZ
// name: CDragListBox::~CDragListBox
// prototype: public: virtual __thiscall CDragListBox::~CDragListBox(void)

// LIBRARY: IMPERIALISM 0x005e5561 SYMBOL
// ?PreSubclassWindow@CDragListBox@@UAEXXZ
// name: CDragListBox::PreSubclassWindow
// prototype: public: virtual void __thiscall CDragListBox::PreSubclassWindow(void)

// LIBRARY: IMPERIALISM 0x005e556b SYMBOL
// ?BeginDrag@CDragListBox@@UAEHVCPoint@@@Z
// name: CDragListBox::BeginDrag
// prototype: public: virtual int __thiscall CDragListBox::BeginDrag(class CPoint)

// LIBRARY: IMPERIALISM 0x005e5597 SYMBOL
// ?CancelDrag@CDragListBox@@UAEXVCPoint@@@Z
// name: CDragListBox::CancelDrag
// prototype: public: virtual void __thiscall CDragListBox::CancelDrag(class CPoint)

// LIBRARY: IMPERIALISM 0x005e55a4 SYMBOL
// ?Dragging@CDragListBox@@UAEIVCPoint@@@Z
// name: CDragListBox::Dragging
// prototype: public: virtual unsigned int __thiscall CDragListBox::Dragging(class CPoint)

// LIBRARY: IMPERIALISM 0x005e55ee SYMBOL
// ?Dropped@CDragListBox@@UAEXHVCPoint@@@Z
// name: CDragListBox::Dropped
// prototype: public: virtual void __thiscall CDragListBox::Dropped(int, class CPoint)

// LIBRARY: IMPERIALISM 0x005e56cd SYMBOL
// ?DrawInsert@CDragListBox@@UAEXH@Z
// name: CDragListBox::DrawInsert
// prototype: public: virtual void __thiscall CDragListBox::DrawInsert(int)

// LIBRARY: IMPERIALISM 0x005e56f2 SYMBOL
// ?DrawSingle@CDragListBox@@QAEXH@Z
// name: CDragListBox::DrawSingle
// prototype: public: void __thiscall CDragListBox::DrawSingle(int)

// LIBRARY: IMPERIALISM 0x005e57e9 SYMBOL
// ?OnChildNotify@CDragListBox@@MAEHIIJPAJ@Z
// name: CDragListBox::OnChildNotify
// prototype: protected: virtual int __thiscall CDragListBox::OnChildNotify(unsigned int, unsigned int, long, long *)

// LIBRARY: IMPERIALISM 0x005e58ab SYMBOL
// ?Create@CToolBarCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CToolBarCtrl::Create
// prototype: public: int __thiscall CToolBarCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e58e4 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e591c SYMBOL
// ?AddBitmap@CToolBarCtrl@@QAEHHPAVCBitmap@@@Z
// name: AddBitmap
// prototype: int __thiscall CToolBarCtrl::AddBitmap(int param_1, CBitmap * param_2)

// LIBRARY: IMPERIALISM 0x005e5950 SYMBOL
// ?AddBitmap@CToolBarCtrl@@QAEHHI@Z
// name: CToolBarCtrl::AddBitmap
// prototype: public: int __thiscall CToolBarCtrl::AddBitmap(int, unsigned int)

// LIBRARY: IMPERIALISM 0x005e5987 SYMBOL
// ?SaveState@CToolBarCtrl@@QAEXPAUHKEY__@@PBD1@Z
// name: SaveState
// prototype: void __thiscall CToolBarCtrl::SaveState(HKEY__ * param_1, char * param_2, char * param_3)

// LIBRARY: IMPERIALISM 0x005e59b7 SYMBOL
// ?RestoreState@CToolBarCtrl@@QAEXPAUHKEY__@@PBD1@Z
// name: RestoreState
// prototype: void __thiscall CToolBarCtrl::RestoreState(HKEY__ * param_1, char * param_2, char * param_3)

// LIBRARY: IMPERIALISM 0x005e59e7 SYMBOL
// ?AddString@CToolBarCtrl@@QAEHI@Z
// name: CToolBarCtrl::AddString
// prototype: public: int __thiscall CToolBarCtrl::AddString(unsigned int)

// LIBRARY: IMPERIALISM 0x005e5a0d SYMBOL
// ?OnCreate@CToolBarCtrl@@IAEHPAUtagCREATESTRUCTA@@@Z
// name: CToolBarCtrl::OnCreate
// prototype: protected: int __thiscall CToolBarCtrl::OnCreate(struct tagCREATESTRUCTA *)

// LIBRARY: IMPERIALISM 0x005e5a36 SYMBOL
// ?Create@CStatusBarCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CStatusBarCtrl::Create
// prototype: public: int __thiscall CStatusBarCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e5a6f SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e5ad2 SYMBOL
// ?GetText@CStatusBarCtrl@@QBE?AVCString@@HPAH@Z
// name: CStatusBarCtrl::GetText
// prototype: public: class CString __thiscall CStatusBarCtrl::GetText(int, int *) const

// LIBRARY: IMPERIALISM 0x005e5b9a SYMBOL
// ?GetBorders@CStatusBarCtrl@@QBEHAAH00@Z
// name: GetBorders
// prototype: int __thiscall CStatusBarCtrl::GetBorders(int * param_1, int * param_2, int * param_3)

// LIBRARY: IMPERIALISM 0x005e5bd7 SYMBOL
// ?OnChildNotify@CListCtrl@@MAEHIIJPAJ@Z

// LIBRARY: IMPERIALISM 0x005e5c0b SYMBOL
// ?Create@CListCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CListCtrl::Create
// prototype: public: int __thiscall CListCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e5c44 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e5c9c SYMBOL
// ?InsertColumn@CListCtrl@@QAEHHPBDHHH@Z
// name: CListCtrl::InsertColumn
// prototype: public: int __thiscall CListCtrl::InsertColumn(int, char const *, int, int, int)

// LIBRARY: IMPERIALISM 0x005e5cef SYMBOL
// ?InsertItem@CListCtrl@@QAEHIHPBDIIHJ@Z
// name: CListCtrl::InsertItem
// prototype: public: int __thiscall CListCtrl::InsertItem(unsigned int, int, char const *, unsigned int, unsigned int, int, long)

// LIBRARY: IMPERIALISM 0x005e5d3b SYMBOL
// ?HitTest@CListCtrl@@QBEHVCPoint@@PAI@Z
// name: HitTest
// prototype: int __thiscall CListCtrl::HitTest(CPoint param_1, uint * param_2)

// LIBRARY: IMPERIALISM 0x005e5d71 SYMBOL
// ?SetItem@CListCtrl@@QAEHHHIPBDHIIJ@Z
// name: SetItem
// prototype: public: int __thiscall CListCtrl::SetItem(int, int, unsigned int, char const *, int, unsigned int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x005e5dbf SYMBOL
// ?GetItemText@CListCtrl@@QBE?AVCString@@HH@Z
// name: CListCtrl::GetItemText
// prototype: public: class CString __thiscall CListCtrl::GetItemText(int, int) const

// LIBRARY: IMPERIALISM 0x005e5e64 SYMBOL
// ?GetItemText@CListCtrl@@QBEHHHPADH@Z
// name: CListCtrl::GetItemText
// prototype: public: int __thiscall CListCtrl::GetItemText(int, int, char *, int) const

// LIBRARY: IMPERIALISM 0x005e5ea9 SYMBOL
// ?GetItemData@CListCtrl@@QBEKH@Z
// name: CListCtrl::GetItemData
// prototype: public: unsigned long __thiscall CListCtrl::GetItemData(int) const

// LIBRARY: IMPERIALISM 0x005e5eee SYMBOL
// ?OnChildNotify@CListCtrl@@MAEHIIJPAJ@Z

// LIBRARY: IMPERIALISM 0x005e5f1c SYMBOL
// ?RemoveImageList@CListCtrl@@IAEXH@Z
// name: CListCtrl::RemoveImageList
// prototype: protected: void __thiscall CListCtrl::RemoveImageList(int)

// LIBRARY: IMPERIALISM 0x005e5f55 SYMBOL
// ?OnNcDestroy@CListCtrl@@IAEXXZ
// name: CListCtrl::OnNcDestroy
// prototype: protected: void __thiscall CListCtrl::OnNcDestroy(void)

// LIBRARY: IMPERIALISM 0x005e5fe5 SYMBOL
// ?Create@CTreeCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CTreeCtrl::Create
// prototype: public: int __thiscall CTreeCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e601e SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e6076 SYMBOL
// ?GetItemText@CTreeCtrl@@QBE?AVCString@@PAU_TREEITEM@@@Z
// name: CTreeCtrl::GetItemText
// prototype: public: class CString __thiscall CTreeCtrl::GetItemText(struct _TREEITEM *) const

// LIBRARY: IMPERIALISM 0x005e6116 SYMBOL
// ?GetItemImage@CTreeCtrl@@QBEHPAU_TREEITEM@@AAH1@Z
// name: CTreeCtrl::GetItemImage
// prototype: public: int __thiscall CTreeCtrl::GetItemImage(struct _TREEITEM *, int &, int &) const

// LIBRARY: IMPERIALISM 0x005e6155 SYMBOL
// ?GetItemState@CTreeCtrl@@QBEIPAU_TREEITEM@@I@Z
// name: CTreeCtrl::GetItemState
// prototype: public: unsigned int __thiscall CTreeCtrl::GetItemState(struct _TREEITEM *, unsigned int) const

// LIBRARY: IMPERIALISM 0x005e618d SYMBOL
// ?GetItemData@CTreeCtrl@@QBEKPAU_TREEITEM@@@Z
// name: CTreeCtrl::GetItemData
// prototype: public: unsigned long __thiscall CTreeCtrl::GetItemData(struct _TREEITEM *) const

// LIBRARY: IMPERIALISM 0x005e61bb SYMBOL
// ?ItemHasChildren@CTreeCtrl@@QBEHPAU_TREEITEM@@@Z
// name: CTreeCtrl::ItemHasChildren
// prototype: public: int __thiscall CTreeCtrl::ItemHasChildren(struct _TREEITEM *) const

// LIBRARY: IMPERIALISM 0x005e61e9 SYMBOL
// ?SetItem@CTreeCtrl@@QAEHPAU_TREEITEM@@IPBDHHIIJ@Z

// LIBRARY: IMPERIALISM 0x005e6237 SYMBOL
// ?InsertItem@CTreeCtrl@@QAEPAU_TREEITEM@@IPBDHHIIJPAU2@1@Z
// name: CTreeCtrl::InsertItem
// prototype: public: struct _TREEITEM * __thiscall CTreeCtrl::InsertItem(unsigned int, char const *, int, int, unsigned int, unsigned int, long, struct _TREEITEM *, struct _TREEITEM *)

// LIBRARY: IMPERIALISM 0x005e628b SYMBOL
// ?HitTest@CTreeCtrl@@QBEPAU_TREEITEM@@VCPoint@@PAI@Z
// name: CTreeCtrl::HitTest

// LIBRARY: IMPERIALISM 0x005e62c1 SYMBOL
// ?RemoveImageList@CTreeCtrl@@IAEXH@Z
// name: CTreeCtrl::RemoveImageList
// prototype: protected: void __thiscall CTreeCtrl::RemoveImageList(int)

// LIBRARY: IMPERIALISM 0x005e62fa SYMBOL
// ?OnDestroy@CTreeCtrl@@QAEXXZ
// name: CTreeCtrl::OnDestroy
// prototype: public: void __thiscall CTreeCtrl::OnDestroy(void)

// LIBRARY: IMPERIALISM 0x005e6379 SYMBOL
// ?Create@CSpinButtonCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CSpinButtonCtrl::Create
// prototype: public: int __thiscall CSpinButtonCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e63b2 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e6416 SYMBOL
// ?Create@CSliderCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CSliderCtrl::Create
// prototype: public: int __thiscall CSliderCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e644f
// CProgressCtrl::~CHotKeyCtrl

// LIBRARY: IMPERIALISM 0x005e64be SYMBOL
// ?SetRange@CSliderCtrl@@QAEXHHH@Z
// name: CSliderCtrl::SetRange
// prototype: public: void __thiscall CSliderCtrl::SetRange(int, int, int)

// LIBRARY: IMPERIALISM 0x005e6557 SYMBOL
// ?Create@CProgressCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CProgressCtrl::Create
// prototype: public: int __thiscall CProgressCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e6590 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e65c8 SYMBOL
// ?Create@CHeaderCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CHeaderCtrl::Create
// prototype: public: int __thiscall CHeaderCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e6601 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e663c SYMBOL
// ?OnChildNotify@CListCtrl@@MAEHIIJPAJ@Z

// LIBRARY: IMPERIALISM 0x005e666a SYMBOL
// ?Create@CHotKeyCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CHotKeyCtrl::Create
// prototype: public: int __thiscall CHotKeyCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e66a3 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e6710 SYMBOL
// ?Create@CTabCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CTabCtrl::Create
// prototype: public: int __thiscall CTabCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e6749 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e6784 SYMBOL
// ?OnChildNotify@CListCtrl@@MAEHIIJPAJ@Z

// LIBRARY: IMPERIALISM 0x005e67b2
// MFC nafxcw WM_DESTROY handler in message map 0x670d10 (base CWnd's map
// 0x670868): sends CB_GETCOUNT (0x1302) to the child combo-box window.

// LIBRARY: IMPERIALISM 0x005e67ec SYMBOL
// ?Create@CAnimateCtrl@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CAnimateCtrl::Create
// prototype: public: int __thiscall CAnimateCtrl::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e6825 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e685d SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e68a2 SYMBOL
// ??_GCGdiObject@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e68be SYMBOL
// ??1CBrush@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e68f1 SYMBOL
// ?Detach@CMenu@@QAEPAUHMENU__@@XZ

// LIBRARY: IMPERIALISM 0x005e691b SYMBOL
// ?afxMapHMENU@@YAPAVCHandleMap@@H@Z

// LIBRARY: IMPERIALISM 0x005e698b SYMBOL
// ?DestroyMenu@CMenu@@QAEHXZ
// name: CMenu::DestroyMenu
// prototype: public: int __thiscall CMenu::DestroyMenu(void)

// LIBRARY: IMPERIALISM 0x005e69a1 SYMBOL
// ?DeleteTempMap@CMenu@@SGXXZ

// LIBRARY: IMPERIALISM 0x005e69cb SYMBOL
// ?FromHandlePermanent@CMenu@@SGPAV1@PAUHMENU__@@@Z
// name: CMenu::FromHandlePermanent
// prototype: public: static class CMenu * __stdcall CMenu::FromHandlePermanent(struct HMENU__*)

// LIBRARY: IMPERIALISM 0x005e69e7 SYMBOL
// ?Create@CImageList@@QAEHHHIHH@Z
// name: CImageList::Create
// prototype: public: int __thiscall CImageList::Create(int, int, unsigned int, int, int)

// LIBRARY: IMPERIALISM 0x005e6a0f SYMBOL
// ?Create@CImageList@@QAEHIHHK@Z
// name: CImageList::Create
// prototype: public: int __thiscall CImageList::Create(unsigned int, int, int, unsigned long)

// LIBRARY: IMPERIALISM 0x005e6a41 SYMBOL
// ?Create@CImageList@@QAEHPBDHHK@Z
// name: CImageList::Create
// prototype: public: int __thiscall CImageList::Create(char const *, int, int, unsigned long)

// LIBRARY: IMPERIALISM 0x005e6a73 SYMBOL
// ?Create@CImageList@@QAEHAAV1@H0HHH@Z
// name: CImageList::Create
// prototype: public: int __thiscall CImageList::Create(class CImageList &, int, class CImageList &, int, int, int)

// LIBRARY: IMPERIALISM 0x005e6aa4 SYMBOL
// ?Attach@CImageList@@QAEHPAU_IMAGELIST@@@Z
// name: CImageList::Attach
// prototype: public: int __thiscall CImageList::Attach(struct _IMAGELIST *)

// LIBRARY: IMPERIALISM 0x005e6ad1 SYMBOL
// ?Read@CImageList@@QAEHPAVCArchive@@@Z
// name: CImageList::Read
// prototype: public: int __thiscall CImageList::Read(class CArchive *)

// LIBRARY: IMPERIALISM 0x005e6afe SYMBOL
// ?Write@CImageList@@QAEHPAVCArchive@@@Z
// name: CImageList::Write
// prototype: public: int __thiscall CImageList::Write(class CArchive *)

// LIBRARY: IMPERIALISM 0x005e6b22 SYMBOL
// ?GetCurSel@CListBox@@QBEHXZ
// name: CListBox::GetCurSel
// prototype: public: int __thiscall CListBox::GetCurSel(void) const

// LIBRARY: IMPERIALISM 0x005e6b35 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6b51 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6b6d SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6b89 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6ba5 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6bc1 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6bdd SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6bf9 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6c15 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6c31 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6c4d SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6c69 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6c85 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6ca1 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6cbd SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6cd9 SYMBOL
// ??_GCHeaderCtrl@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e6cf5 SYMBOL
// ?SetFilePath@CFile@@UAEXPBD@Z
// name: CFile::SetFilePath
// prototype: public: virtual void __thiscall CFile::SetFilePath(char const *)

// LIBRARY: IMPERIALISM 0x005e6d04 SYMBOL
// ??6CArchive@@QAEAAV0@E@Z
// name: CArchive::operator<<
// prototype: public: class CArchive & __thiscall CArchive::operator<<(unsigned char)

// LIBRARY: IMPERIALISM 0x005e6d27 SYMBOL
// ??6CArchive@@QAEAAV0@G@Z
// name: CArchive::operator<<
// prototype: public: class CArchive & __thiscall CArchive::operator<<(unsigned short)

// LIBRARY: IMPERIALISM 0x005e6d4e SYMBOL
// ??6CArchive@@QAEAAV0@K@Z
// name: CArchive::operator<<
// prototype: public: class CArchive & __thiscall CArchive::operator<<(unsigned long)

// LIBRARY: IMPERIALISM 0x005e6d74 SYMBOL
// ??5CArchive@@QAEAAV0@AAE@Z
// name: CArchive::operator>>
// prototype: public: class CArchive & __thiscall CArchive::operator>>(unsigned char &)

// LIBRARY: IMPERIALISM 0x005e6da3 SYMBOL
// ??5CArchive@@QAEAAV0@AAG@Z
// name: CArchive::operator>>
// prototype: public: class CArchive & __thiscall CArchive::operator>>(unsigned short &)

// LIBRARY: IMPERIALISM 0x005e6dd6 SYMBOL
// ??5CArchive@@QAEAAV0@AAK@Z
// name: CArchive::operator>>
// prototype: public: class CArchive & __thiscall CArchive::operator>>(unsigned long &)

// LIBRARY: IMPERIALISM 0x005e6e08 SYMBOL
// ??0CMemoryException@@QAE@HI@Z

// LIBRARY: IMPERIALISM 0x005e6e32 SYMBOL
// ??_GCResourceException@@UAEPAXI@Z
// name: CResourceException::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CResourceException::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e6e4e SYMBOL
// ??1CObject@@UAE@XZ
// name: CObject::~CObject
// prototype: public: virtual __thiscall CObject::~CObject(void)

// LIBRARY: IMPERIALISM 0x005e6e55 SYMBOL
// ??0CMemoryException@@QAE@HI@Z

// LIBRARY: IMPERIALISM 0x005e6e7f SYMBOL
// ??_GCUserException@@UAEPAXI@Z
// name: CUserException::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CUserException::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e6e9b SYMBOL
// ??1CObject@@UAE@XZ
// name: CObject::~CObject
// prototype: public: virtual __thiscall CObject::~CObject(void)

// SYNTHETIC: IMPERIALISM 0x005e6ea2
// ownership-only

// LIBRARY: IMPERIALISM 0x005e6ebe SYMBOL
// ?GetCurrentDirectoryA@CFtpConnection@@QBEHPADPAK@Z
// name: CFtpConnection::GetCurrentDirectoryA
// prototype: public: int __thiscall CFtpConnection::GetCurrentDirectoryA(char *, unsigned long *) const

// LIBRARY: IMPERIALISM 0x005e6ed2 SYMBOL
// ?RectVisible@CDC@@UBEHPBUtagRECT@@@Z
// name: CDC::RectVisible
// prototype: public: virtual int __thiscall CDC::RectVisible(struct tagRECT const *) const

// LIBRARY: IMPERIALISM 0x005e6ee2 SYMBOL
// ?DrawTextA@CDC@@UAEHPBDHPAUtagRECT@@I@Z
// name: CDC::DrawTextA
// prototype: public: virtual int __thiscall CDC::DrawTextA(char const *, int, struct tagRECT *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e6efe SYMBOL
// ?ExtTextOutA@CDC@@UAEHHHIPBUtagRECT@@PBDIPAH@Z
// name: CDC::ExtTextOutA
// prototype: public: virtual int __thiscall CDC::ExtTextOutA(int, int, unsigned int, struct tagRECT const *, char const *, unsigned int, int *)

// LIBRARY: IMPERIALISM 0x005e6f23 SYMBOL
// ?TabbedTextOutA@CDC@@UAE?AVCSize@@HHPBDHHPAHH@Z
// name: CDC::TabbedTextOutA
// prototype: public: virtual class CSize __thiscall CDC::TabbedTextOutA(int, int, char const *, int, int, int *, int)

// LIBRARY: IMPERIALISM 0x005e6f5b SYMBOL
// ?DrawTextA@CDC@@UAEHPBDHPAUtagRECT@@I@Z
// name: CDC::DrawTextA
// prototype: public: virtual int __thiscall CDC::DrawTextA(char const *, int, struct tagRECT *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e6f77 SYMBOL
// ?GrayStringA@CDC@@UAEHPAVCBrush@@P6GHPAUHDC__@@JH@ZJHHHHH@Z
// name: CDC::GrayStringA
// prototype: public: virtual int __thiscall CDC::GrayStringA(class CBrush *, int (__stdcall *)(struct HDC__*, long, int), long, int, int, int, int, int)

// LIBRARY: IMPERIALISM 0x005e6fa7 SYMBOL
// ?DrawTextA@CDC@@UAEHPBDHPAUtagRECT@@I@Z
// name: CDC::DrawTextA
// prototype: public: virtual int __thiscall CDC::DrawTextA(char const *, int, struct tagRECT *, unsigned int)

// LIBRARY: IMPERIALISM 0x005e6fc3 SYMBOL
// ??_GCException@@UAEPAXI@Z
// name: CException::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CException::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e6fdf SYMBOL
// ??0CMemoryException@@QAE@HI@Z

// LIBRARY: IMPERIALISM 0x005e7009 SYMBOL
// ??_GCMemoryException@@UAEPAXI@Z
// name: CMemoryException::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CMemoryException::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e7025 SYMBOL
// ??1CObject@@UAE@XZ
// name: CObject::~CObject
// prototype: public: virtual __thiscall CObject::~CObject(void)

// LIBRARY: IMPERIALISM 0x005e702c SYMBOL
// ??0CMemoryException@@QAE@HI@Z

// LIBRARY: IMPERIALISM 0x005e7056 SYMBOL
// ??_GCNotSupportedException@@UAEPAXI@Z
// name: CNotSupportedException::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CNotSupportedException::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e7072 SYMBOL
// ??1CObject@@UAE@XZ
// name: CObject::~CObject
// prototype: public: virtual __thiscall CObject::~CObject(void)

// LIBRARY: IMPERIALISM 0x005e7079
// ownership-only

// LIBRARY: IMPERIALISM 0x005e7095
// MFC nafxcw handler in message map 0x672aa0 (base CWnd's map 0x670868),
// MFC-internal message 0x364.

// LIBRARY: IMPERIALISM 0x005e709d
// CCtrlView::~CListView

// LIBRARY: IMPERIALISM 0x005e70ce SYMBOL
// ??_GCGdiObject@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x005e70ea SYMBOL
// ??1CBrush@@UAE@XZ

// LIBRARY: IMPERIALISM 0x005e711d SYMBOL
// ??0CArchiveStream@@QAE@PAVCArchive@@@Z
// name: CArchiveStream::CArchiveStream
// prototype: public: __thiscall CArchiveStream::CArchiveStream(class CArchive *)

// LIBRARY: IMPERIALISM 0x005e713a SYMBOL
// ?QueryInterface@CArchiveStream@@UAGJABU_GUID@@PAPAX@Z
// name: CArchiveStream::QueryInterface
// prototype: public: virtual long __stdcall CArchiveStream::QueryInterface(struct _GUID const &, void **)

// LIBRARY: IMPERIALISM 0x005e717e SYMBOL
// ?Read@CArchiveStream@@UAGJPAXKPAK@Z

// LIBRARY: IMPERIALISM 0x005e71d6 SYMBOL
// ?Write@CArchiveStream@@UAGJPBXKPAK@Z

// LIBRARY: IMPERIALISM 0x005e722f SYMBOL
// ?Seek@CArchiveStream@@UAGJT_LARGE_INTEGER@@KPAT_ULARGE_INTEGER@@@Z

// LIBRARY: IMPERIALISM 0x005e72f1 SYMBOL
// ??_GCFileException@@UAEPAXI@Z
// name: CFileException::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CFileException::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e730d
// CFileException::~CArchiveException

// LIBRARY: IMPERIALISM 0x005e7350 SYMBOL
// __fpmath
// name: _fpmath

// LIBRARY: IMPERIALISM 0x005e7370 SYMBOL
// __fpclear
// name: _fpclear
// prototype: void __cdecl _fpclear(void)

// LIBRARY: IMPERIALISM 0x005e7380 SYMBOL
// __cfltcvt_init
// name: _cfltcvt_init

// LIBRARY: IMPERIALISM 0x005e73d0 SYMBOL
// __ftol
// name: _ftol
// prototype: long __cdecl _ftol(void)

// LIBRARY: IMPERIALISM 0x005e7400 SYMBOL
// ?_JumpToContinuation@@YGXPAXPAUEHRegistrationNode@@@Z

// LIBRARY: IMPERIALISM 0x005e7440 SYMBOL
// ?_CallMemberFunction0@@YGXPAX0@Z
// name: _CallMemberFunction0
// prototype: void __stdcall _CallMemberFunction0(void *, void *)

// LIBRARY: IMPERIALISM 0x005e7450 SYMBOL
// ?_CallMemberFunction2@@YGXPAX00H@Z

// LIBRARY: IMPERIALISM 0x005e7460 SYMBOL
// ?_CallMemberFunction2@@YGXPAX00H@Z

// LIBRARY: IMPERIALISM 0x005e7470 SYMBOL
// ?_UnwindNestedFrames@@YGXPAUEHRegistrationNode@@PAUEHExceptionRecord@@@Z
// name: _UnwindNestedFrames
// prototype: void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *, struct EHExceptionRecord *)

// LIBRARY: IMPERIALISM 0x005e74d0 SYMBOL
// ___CxxFrameHandler

// LIBRARY: IMPERIALISM 0x005e7530 SYMBOL
// ?_CallCatchBlock2@@YAPAXPAUEHRegistrationNode@@PBU_s_FuncInfo@@PAXHK@Z
// name: _CallCatchBlock2
// prototype: void * __cdecl _CallCatchBlock2(struct EHRegistrationNode *, struct _s_FuncInfo const *, void *, int, unsigned long)

// LIBRARY: IMPERIALISM 0x005e7590 SYMBOL
// ?CatchGuardHandler@@YA?AW4_EXCEPTION_DISPOSITION@@PAUEHExceptionRecord@@PAUCatchGuardRN@@PAX2@Z

// LIBRARY: IMPERIALISM 0x005e75c0 SYMBOL
// ?_CallSETranslator@@YAHPAUEHExceptionRecord@@PAUEHRegistrationNode@@PAX2PBU_s_FuncInfo@@H1@Z
// name: _CallSETranslator
// prototype: int __cdecl _CallSETranslator(struct EHExceptionRecord *, struct EHRegistrationNode *, void *, void *, struct _s_FuncInfo const *, int, struct EHRegistrationNode *)

// LIBRARY: IMPERIALISM 0x005e7690 SYMBOL
// ?TranslatorGuardHandler@@YA?AW4_EXCEPTION_DISPOSITION@@PAUEHExceptionRecord@@PAUTranslatorGuardRN@@PAX2@Z

// LIBRARY: IMPERIALISM 0x005e7720 SYMBOL
// ?_GetRangeOfTrysToCheck@@YAPBU_s_TryBlockMapEntry@@PBU_s_FuncInfo@@HHPAI1@Z
// name: _GetRangeOfTrysToCheck
// prototype: struct _s_TryBlockMapEntry const * __cdecl _GetRangeOfTrysToCheck(struct _s_FuncInfo const *, int, int, unsigned int *, unsigned int *)

// LIBRARY: IMPERIALISM 0x005e77a0 SYMBOL
// __global_unwind2

// LIBRARY: IMPERIALISM 0x005e77e2 SYMBOL
// __local_unwind2

// LIBRARY: IMPERIALISM 0x005e784a SYMBOL
// __abnormal_termination

// LIBRARY: IMPERIALISM 0x005e786d SYMBOL
// __NLG_Notify1

// LIBRARY: IMPERIALISM 0x005e7876 SYMBOL
// __NLG_Notify

// LIBRARY: IMPERIALISM 0x005e7890 SYMBOL
// __onexit

// LIBRARY: IMPERIALISM 0x005e7920 SYMBOL
// _atexit
// name: atexit
// prototype: int __cdecl atexit(void (__cdecl*)(void))

// LIBRARY: IMPERIALISM 0x005e7980 SYMBOL
// __mbscmp
// name: _mbscmp

// LIBRARY: IMPERIALISM 0x005e7a80 SYMBOL
// ?_set_new_handler@@YAP6AHI@ZP6AHI@Z@Z
// name: _set_new_handler
// prototype: _PNH __cdecl _set_new_handler(_PNH)

// LIBRARY: IMPERIALISM 0x005e7ac0 SYMBOL
// __callnewh

// LIBRARY: IMPERIALISM 0x005e7ae0
// ownership-only

// LIBRARY: IMPERIALISM 0x005e7c10
// ownership-only

// LIBRARY: IMPERIALISM 0x005e7d30
// _findclose

// LIBRARY: IMPERIALISM 0x005e7d60
// ConvertFileTimeToLocalEpochSeconds

// LIBRARY: IMPERIALISM 0x005e7df0 SYMBOL
// __aullshr

// LIBRARY: IMPERIALISM 0x005e7e10 SYMBOL
// ??_M@YGXPAXIHP6EX0@Z@Z

// LIBRARY: IMPERIALISM 0x005e7e89
// ownership-only

// LIBRARY: IMPERIALISM 0x005e7ec0 SYMBOL
// ?__ArrayUnwind@@YGXPAXIHP6EX0@Z@Z

// LIBRARY: IMPERIALISM 0x005e7f50
// ownership-only

// LIBRARY: IMPERIALISM 0x005e7fc0 SYMBOL
// _realloc
// name: _realloc

// LIBRARY: IMPERIALISM 0x005e8170 SYMBOL
// ??1type_info@@UAE@XZ
// name: type_info::~type_info
// prototype: public: virtual __thiscall type_info::~type_info(void)

// LIBRARY: IMPERIALISM 0x005e81a0 SYMBOL
// ??_Gtype_info@@UAEPAXI@Z
// name: type_info::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall type_info::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005e8310
// AllocateWithGlobalNewMode

// LIBRARY: IMPERIALISM 0x005e8330 SYMBOL
// __nh_malloc

// LIBRARY: IMPERIALISM 0x005e8380 SYMBOL
// __heap_alloc

// LIBRARY: IMPERIALISM 0x005e83e0 SYMBOL
// _srand
// name: srand
// prototype: void __cdecl srand(unsigned int)

// LIBRARY: IMPERIALISM 0x005e83f0 SYMBOL
// _rand
// name: rand
// prototype: int __cdecl rand(void)

// LIBRARY: IMPERIALISM 0x005e8420 SYMBOL
// _memmove
// name: memmove
// prototype: void * __cdecl memmove(void *,void const *,unsigned int)

// LIBRARY: IMPERIALISM 0x005e8760
// ownership-only

// LIBRARY: IMPERIALISM 0x005e8800
// ownership-only

// LIBRARY: IMPERIALISM 0x005e8970
// _isdigit

// LIBRARY: IMPERIALISM 0x005e89d0
// _isspace

// LIBRARY: IMPERIALISM 0x005e8bb0
// _vsprintf

// LIBRARY: IMPERIALISM 0x005e8c20 SYMBOL
// __alloca_probe
// name: _alloca_probe

// LIBRARY: IMPERIALISM 0x005e8c50 SYMBOL
// ??_L@YGXPAXIHP6EX0@Z1@Z
// name: `eh vector ctor iterator'
// prototype: void __stdcall `eh vector ctor iterator'(void *, unsigned int, int, void (__thiscall *)(void *), void (__thiscall *)(void *))

// SYNTHETIC: IMPERIALISM 0x005e8cc8
// SehCleanup_CallCallbackRepeatedly

// LIBRARY: IMPERIALISM 0x005e8cf0 SYMBOL
// _localtime
// name: _localtime
// prototype: struct tm * __cdecl _localtime(long const *)

// LIBRARY: IMPERIALISM 0x005e8ee0 SYMBOL
// _time
// name: _time
// prototype: long __cdecl _time(long *)

// LIBRARY: IMPERIALISM 0x005e9010
// ownership-only

// LIBRARY: IMPERIALISM 0x005e9050
// ownership-only

// LIBRARY: IMPERIALISM 0x005e90c0
// ownership-only

// LIBRARY: IMPERIALISM 0x005e9100
// ownership-only

// LIBRARY: IMPERIALISM 0x005e9120
// _fprintf

// LIBRARY: IMPERIALISM 0x005e9170
// _fwrite

// LIBRARY: IMPERIALISM 0x005e91b0 SYMBOL
// __fwrite_lk

// LIBRARY: IMPERIALISM 0x005e9300
// _fscanf

// LIBRARY: IMPERIALISM 0x005e9340
// _strncpy

// LIBRARY: IMPERIALISM 0x005e9440
// ownership-only

// LIBRARY: IMPERIALISM 0x005e9480
// ownership-only

// LIBRARY: IMPERIALISM 0x005e95c0
// ownership-only

// LIBRARY: IMPERIALISM 0x005e9620 SYMBOL
// __itoa

// LIBRARY: IMPERIALISM 0x005e9660
// _xtoa

// LIBRARY: IMPERIALISM 0x005e9840
// _sprintf

// LIBRARY: IMPERIALISM 0x005e98b0
// _WinMainCRTStartup

// LIBRARY: IMPERIALISM 0x005e9a60 SYMBOL
// __amsg_exit
// name: _amsg_exit
// prototype: void __cdecl _amsg_exit(int)

// LIBRARY: IMPERIALISM 0x005e9a90 SYMBOL
// _memset
// name: memset
// prototype: void * __cdecl memset(void *,int,unsigned int)

// LIBRARY: IMPERIALISM 0x005e9ae8 SYMBOL
// __EH_prolog
// name: _EH_prolog

// LIBRARY: IMPERIALISM 0x005e9b10 SYMBOL
// __strdup

// LIBRARY: IMPERIALISM 0x005e9b60 SYMBOL
// __cinit

// LIBRARY: IMPERIALISM 0x005e9b90
// _exit

// LIBRARY: IMPERIALISM 0x005e9bb0 SYMBOL
// __exit
// name: _exit
// prototype: void __cdecl _exit(int)

// LIBRARY: IMPERIALISM 0x005e9bf0 SYMBOL
// _doexit
// name: _doexit
// prototype: void __cdecl _doexit(int status, int quick, int retcaller)

// LIBRARY: IMPERIALISM 0x005e9cb0 SYMBOL
// __lockexit

// LIBRARY: IMPERIALISM 0x005e9cc0 SYMBOL
// __unlockexit

// LIBRARY: IMPERIALISM 0x005e9cd0 SYMBOL
// __initterm

// LIBRARY: IMPERIALISM 0x005e9cf0
// _memcpy

// LIBRARY: IMPERIALISM 0x005ea030
// _wcslen

// LIBRARY: IMPERIALISM 0x005ea050 SYMBOL
// __mbschr

// LIBRARY: IMPERIALISM 0x005ea120 SYMBOL
// __mbspbrk

// LIBRARY: IMPERIALISM 0x005ea1d0 SYMBOL
// __mbsupr

// LIBRARY: IMPERIALISM 0x005ea280 SYMBOL
// __mbslwr

// LIBRARY: IMPERIALISM 0x005ea330 SYMBOL
// __mbsrev

// LIBRARY: IMPERIALISM 0x005ea3b0 SYMBOL
// __beginthreadex

// LIBRARY: IMPERIALISM 0x005ea430 SYMBOL
// __threadstartex@4

// LIBRARY: IMPERIALISM 0x005ea4e0 SYMBOL
// __endthreadex
// name: _endthreadex
// prototype: void __cdecl _endthreadex(unsigned int)

// LIBRARY: IMPERIALISM 0x005ea520
// _memcmp

// LIBRARY: IMPERIALISM 0x005ea5d0 SYMBOL
// __CxxThrowException@8

// LIBRARY: IMPERIALISM 0x005ea620 SYMBOL
// __mbsspn

// LIBRARY: IMPERIALISM 0x005ea6d0 SYMBOL
// __mbscspn

// LIBRARY: IMPERIALISM 0x005ea780 SYMBOL
// __mbsrchr

// LIBRARY: IMPERIALISM 0x005ea810 SYMBOL
// __mbsstr

// LIBRARY: IMPERIALISM 0x005ea8b0 SYMBOL
// __mbclen
// name: _mbclen

// LIBRARY: IMPERIALISM 0x005ea8d0 SYMBOL
// __ismbcdigit

// LIBRARY: IMPERIALISM 0x005ea970 SYMBOL
// __mbsinc

// LIBRARY: IMPERIALISM 0x005ea990 SYMBOL
// __ismbcspace

// LIBRARY: IMPERIALISM 0x005eaa30 SYMBOL
// _abs
// name: abs
// prototype: int __cdecl abs(int)

// LIBRARY: IMPERIALISM 0x005eaa40
// _strtol

// LIBRARY: IMPERIALISM 0x005eaa60
// _strtoxl

// LIBRARY: IMPERIALISM 0x005eacf0
// _strtoul

// LIBRARY: IMPERIALISM 0x005ead10 SYMBOL
// __purecall
// name: _purecall
// prototype: void __cdecl _purecall(void)

// LIBRARY: IMPERIALISM 0x005ead20 SYMBOL
// __dosmaperr

// LIBRARY: IMPERIALISM 0x005eada0 SYMBOL
// __errno
// name: _errno
// prototype: int * __cdecl _errno(void)

// LIBRARY: IMPERIALISM 0x005eadb0 SYMBOL
// ___doserrno
// name: __doserrno
// prototype: unsigned long * __cdecl __doserrno(void)

// LIBRARY: IMPERIALISM 0x005eadc0 SYMBOL
// __expand
// name: _expand
// prototype: void * __cdecl _expand(void *, unsigned int)

// LIBRARY: IMPERIALISM 0x005eae70 SYMBOL
// __msize

// LIBRARY: IMPERIALISM 0x005eaee0 SYMBOL
// __setmbcp

// LIBRARY: IMPERIALISM 0x005eb100
// _getSystemCP

// LIBRARY: IMPERIALISM 0x005eb150
// _CPtoLCID

// LIBRARY: IMPERIALISM 0x005eb1b0
// _setSBCS

// LIBRARY: IMPERIALISM 0x005eb1f0 SYMBOL
// ___initmbctable

// LIBRARY: IMPERIALISM 0x005eb200
// _mktime

// LIBRARY: IMPERIALISM 0x005eb220 SYMBOL
// __make_time_t

// LIBRARY: IMPERIALISM 0x005eb460
// _gmtime

// LIBRARY: IMPERIALISM 0x005ebb20
// _strftime

// LIBRARY: IMPERIALISM 0x005ebb40 SYMBOL
// __Strftime

// LIBRARY: IMPERIALISM 0x005ebc90 SYMBOL
// __expandtime

// LIBRARY: IMPERIALISM 0x005ec230 SYMBOL
// __store_str

// LIBRARY: IMPERIALISM 0x005ec260 SYMBOL
// __store_num

// LIBRARY: IMPERIALISM 0x005ec300 SYMBOL
// __store_number

// LIBRARY: IMPERIALISM 0x005ec370 SYMBOL
// __store_winword

// LIBRARY: IMPERIALISM 0x005ec6c0 SYMBOL
// __setdefaultprecision
// name: _setdefaultprecision

// LIBRARY: IMPERIALISM 0x005ec6e0 SYMBOL
// __ms_p5_test_fdiv
// name: _ms_p5_test_fdiv

// LIBRARY: IMPERIALISM 0x005ec730 SYMBOL
// __ms_p5_mp_test_fdiv
// name: _ms_p5_mp_test_fdiv

// LIBRARY: IMPERIALISM 0x005ec760 SYMBOL
// __forcdecpt
// name: _forcdecpt

// LIBRARY: IMPERIALISM 0x005ec850 SYMBOL
// __fassign
// name: _fassign

// LIBRARY: IMPERIALISM 0x005ec8b0 SYMBOL
// __cftoe
// name: _cftoe

// LIBRARY: IMPERIALISM 0x005ec930
// AppendExponentSuffixToNumericBuffer

// LIBRARY: IMPERIALISM 0x005eca30 SYMBOL
// __cftof
// name: _cftof

// LIBRARY: IMPERIALISM 0x005ecaa0
// AppendFractionalDigitsAndPadNumericBuffer

// LIBRARY: IMPERIALISM 0x005ecb60 SYMBOL
// __cftog
// name: _cftog

// LIBRARY: IMPERIALISM 0x005ecc20 SYMBOL
// __cfltcvt
// name: _cfltcvt

// LIBRARY: IMPERIALISM 0x005ecc90 SYMBOL
// __shift
// name: _shift

// LIBRARY: IMPERIALISM 0x005eccc0 SYMBOL
// ___InternalCxxFrameHandler

// LIBRARY: IMPERIALISM 0x005ecd90 SYMBOL
// ?FindHandler@@YAXPAUEHExceptionRecord@@PAUEHRegistrationNode@@PAU_CONTEXT@@PAXPBU_s_FuncInfo@@EH1@Z

// LIBRARY: IMPERIALISM 0x005ed050 SYMBOL
// ?FindHandlerForForeignException@@YAXPAUEHExceptionRecord@@PAUEHRegistrationNode@@PAU_CONTEXT@@PAXPBU_s_FuncInfo@@HH1@Z

// LIBRARY: IMPERIALISM 0x005ed130 SYMBOL
// ___FrameUnwindToState

// LIBRARY: IMPERIALISM 0x005ed210 SYMBOL
// ?CatchIt@@YAXPAUEHExceptionRecord@@PAUEHRegistrationNode@@PAU_CONTEXT@@PAXPBU_s_FuncInfo@@PBU_s_HandlerType@@PBU_s_CatchableType@@PBU_s_TryBlockMapEntry@@H1@Z

// LIBRARY: IMPERIALISM 0x005ed2a0 SYMBOL
// ?CallCatchBlock@@YAPAXPAUEHExceptionRecord@@PAUEHRegistrationNode@@PAU_CONTEXT@@PBU_s_FuncInfo@@PAXHK@Z

// LIBRARY: IMPERIALISM 0x005ed398
// ownership-only

// LIBRARY: IMPERIALISM 0x005ed430 SYMBOL
// ?BuildCatchObject@@YAXPAUEHExceptionRecord@@PAUEHRegistrationNode@@PBU_s_HandlerType@@PBU_s_CatchableType@@@Z

// LIBRARY: IMPERIALISM 0x005ed640 SYMBOL
// ?_DestructExceptionObject@@YAXPAUEHExceptionRecord@@E@Z

// LIBRARY: IMPERIALISM 0x005ed6c0 SYMBOL
// ?AdjustPointer@@YAPAXPAXABUPMD@@@Z

// LIBRARY: IMPERIALISM 0x005ed6f0 SYMBOL
// __CallSettingFrame@12

// LIBRARY: IMPERIALISM 0x005ed740 SYMBOL
// __mtinit

// LIBRARY: IMPERIALISM 0x005ed7d0 SYMBOL
// __initptd

// LIBRARY: IMPERIALISM 0x005ed7f0 SYMBOL
// __getptd

// LIBRARY: IMPERIALISM 0x005ed870 SYMBOL
// __freeptd

// LIBRARY: IMPERIALISM 0x005ed930 SYMBOL
// ?terminate@@YAXXZ
// name: terminate
// prototype: void __cdecl terminate(void)

// LIBRARY: IMPERIALISM 0x005ed9c0 SYMBOL
// ?unexpected@@YAXXZ
// name: unexpected
// prototype: void __cdecl unexpected(void)

// LIBRARY: IMPERIALISM 0x005ed9e0 SYMBOL
// ?_inconsistency@@YAXXZ

// SYNTHETIC: IMPERIALISM 0x005eda4e
// TerminateAfterInconsistencyEhCleanup
// prototype: void __cdecl TerminateAfterInconsistencyEhCleanup(void)

// LIBRARY: IMPERIALISM 0x005eda70 SYMBOL
// __mtinitlocks

// LIBRARY: IMPERIALISM 0x005edb20 SYMBOL
// __lock
// name: _lock

// LIBRARY: IMPERIALISM 0x005edba0 SYMBOL
// __unlock
// name: _unlock

// LIBRARY: IMPERIALISM 0x005edbc0
// ownership-only

// LIBRARY: IMPERIALISM 0x005edc00 SYMBOL
// __lock_file2

// LIBRARY: IMPERIALISM 0x005edc30
// ownership-only

// LIBRARY: IMPERIALISM 0x005edc70 SYMBOL
// __unlock_file2

// LIBRARY: IMPERIALISM 0x005edcc0
// ConvertBrokenDownLocalTimeToEpochSeconds

// LIBRARY: IMPERIALISM 0x005eddb8 SYMBOL
// __except_handler3
// name: _except_handler3

// LIBRARY: IMPERIALISM 0x005ede75 SYMBOL
// __seh_longjmp_unwind@4

// LIBRARY: IMPERIALISM 0x005ede90 SYMBOL
// __heap_init

// LIBRARY: IMPERIALISM 0x005edf40 SYMBOL
// ___sbh_new_region

// LIBRARY: IMPERIALISM 0x005ee0b0 SYMBOL
// ___sbh_release_region

// LIBRARY: IMPERIALISM 0x005ee110 SYMBOL
// ___sbh_decommit_pages

// LIBRARY: IMPERIALISM 0x005ee1e0 SYMBOL
// ___sbh_find_block

// LIBRARY: IMPERIALISM 0x005ee240 SYMBOL
// ___sbh_free_block

// LIBRARY: IMPERIALISM 0x005ee2a0 SYMBOL
// ___sbh_alloc_block

// LIBRARY: IMPERIALISM 0x005ee4e0 SYMBOL
// ___sbh_alloc_block_from_page

// LIBRARY: IMPERIALISM 0x005ee660 SYMBOL
// ___sbh_resize_block

// LIBRARY: IMPERIALISM 0x005ee900 SYMBOL
// __isctype

// LIBRARY: IMPERIALISM 0x005ee9a0 SYMBOL
// __allmul

// LIBRARY: IMPERIALISM 0x005ee9e0 SYMBOL
// __flsbuf

// LIBRARY: IMPERIALISM 0x005eeb10 SYMBOL
// __output

// LIBRARY: IMPERIALISM 0x005ef4a0
// _write_char

// LIBRARY: IMPERIALISM 0x005ef4f0
// _write_multi_char

// LIBRARY: IMPERIALISM 0x005ef530
// _write_string

// LIBRARY: IMPERIALISM 0x005ef570
// _get_int_arg

// LIBRARY: IMPERIALISM 0x005ef590
// _get_int64_arg

// LIBRARY: IMPERIALISM 0x005ef5b0
// _get_short_arg

// LIBRARY: IMPERIALISM 0x005ef5d0
// EnsureRuntimeLocaleTablesInitializedOnce

// LIBRARY: IMPERIALISM 0x005ef630 SYMBOL
// __tzset_lk

// LIBRARY: IMPERIALISM 0x005ef910
// isindst

// LIBRARY: IMPERIALISM 0x005ef940 SYMBOL
// __isindst_lk

// LIBRARY: IMPERIALISM 0x005efbb0
// _cvtdate

// LIBRARY: IMPERIALISM 0x005efd50
// ownership-only

// LIBRARY: IMPERIALISM 0x005efdc0 SYMBOL
// __close_lk

// LIBRARY: IMPERIALISM 0x005efe50
// ownership-only

// LIBRARY: IMPERIALISM 0x005efe90
// _fflush

// LIBRARY: IMPERIALISM 0x005efed0 SYMBOL
// __fflush_lk

// LIBRARY: IMPERIALISM 0x005eff10
// ownership-only

// LIBRARY: IMPERIALISM 0x005eff90
// _flsall

// LIBRARY: IMPERIALISM 0x005f0050
// ownership-only

// LIBRARY: IMPERIALISM 0x005f0220
// ownership-only

// LIBRARY: IMPERIALISM 0x005f0300 SYMBOL
// __stbuf

// LIBRARY: IMPERIALISM 0x005f03a0 SYMBOL
// __ftbuf

// LIBRARY: IMPERIALISM 0x005f03e0 SYMBOL
// __write

// LIBRARY: IMPERIALISM 0x005f0460 SYMBOL
// __write_lk

// LIBRARY: IMPERIALISM 0x005f0670 SYMBOL
// __input

// LIBRARY: IMPERIALISM 0x005f13b0 SYMBOL
// __hextodec

// LIBRARY: IMPERIALISM 0x005f13f0 SYMBOL
// __inc

// LIBRARY: IMPERIALISM 0x005f1420 SYMBOL
// __un_inc

// LIBRARY: IMPERIALISM 0x005f1440 SYMBOL
// __whiteout

// LIBRARY: IMPERIALISM 0x005f1490
// ownership-only

// LIBRARY: IMPERIALISM 0x005f1580
// ownership-only

// LIBRARY: IMPERIALISM 0x005f1600 SYMBOL
// __read_lk

// LIBRARY: IMPERIALISM 0x005f1830 SYMBOL
// __aulldiv

// LIBRARY: IMPERIALISM 0x005f18a0 SYMBOL
// __aullrem

// LIBRARY: IMPERIALISM 0x005f1c70 SYMBOL
// __ismbblead

// LIBRARY: IMPERIALISM 0x005f1ce0
// _x_ismbbtype

// LIBRARY: IMPERIALISM 0x005f1d20 SYMBOL
// __setenvp

// LIBRARY: IMPERIALISM 0x005f1e10 SYMBOL
// __setargv

// LIBRARY: IMPERIALISM 0x005f1eb0
// _parse_cmdline

// LIBRARY: IMPERIALISM 0x005f22c0 SYMBOL
// ___crtGetEnvironmentStringsA

// LIBRARY: IMPERIALISM 0x005f2420 SYMBOL
// __ioinit

// LIBRARY: IMPERIALISM 0x005f2690 SYMBOL
// __FF_MSGBANNER

// LIBRARY: IMPERIALISM 0x005f26d0 SYMBOL
// __NMSG_WRITE

// LIBRARY: IMPERIALISM 0x005f28f0
// _strchr

// LIBRARY: IMPERIALISM 0x005f29b0
// _strpbrk

// LIBRARY: IMPERIALISM 0x005f29f0 SYMBOL
// ___crtLCMapStringW

// LIBRARY: IMPERIALISM 0x005f2c00
// _wcsncnt

// LIBRARY: IMPERIALISM 0x005f2c40 SYMBOL
// ___crtLCMapStringA

// LIBRARY: IMPERIALISM 0x005f2e60
// _strncnt

// LIBRARY: IMPERIALISM 0x005f2e90 SYMBOL
// __strrev

// LIBRARY: IMPERIALISM 0x005f2ec0
// _calloc

// LIBRARY: IMPERIALISM 0x005f2f70 SYMBOL
// ?__CxxUnhandledExceptionFilter@@YGJPAU_EXCEPTION_POINTERS@@@Z
// name: __CxxUnhandledExceptionFilter
// prototype: long __stdcall __CxxUnhandledExceptionFilter(struct _EXCEPTION_POINTERS *)

// LIBRARY: IMPERIALISM 0x005f3000
// _strspn

// LIBRARY: IMPERIALISM 0x005f3040
// _strcspn

// LIBRARY: IMPERIALISM 0x005f3080
// _strrchr

// LIBRARY: IMPERIALISM 0x005f30b0
// _strstr

// LIBRARY: IMPERIALISM 0x005f3130 SYMBOL
// ___crtGetStringTypeW

// LIBRARY: IMPERIALISM 0x005f32c0 SYMBOL
// ___crtGetStringTypeA

// LIBRARY: IMPERIALISM 0x005f3400
// _toupper

// LIBRARY: IMPERIALISM 0x005f3490 SYMBOL
// __toupper_lk

// LIBRARY: IMPERIALISM 0x005f3ec0 SYMBOL
// __strcmpi

// LIBRARY: IMPERIALISM 0x005f3f90 SYMBOL
// __statusfp
// name: _statusfp

// LIBRARY: IMPERIALISM 0x005f3fb0 SYMBOL
// __clearfp
// name: _clearfp

// LIBRARY: IMPERIALISM 0x005f3fd0 SYMBOL
// __control87
// name: _control87

// LIBRARY: IMPERIALISM 0x005f4010 SYMBOL
// __controlfp
// name: _controlfp

// LIBRARY: IMPERIALISM 0x005f4060
// MapFpControlWordToRuntimeControlBits

// LIBRARY: IMPERIALISM 0x005f4100
// StoreMappedFpControlBits_NoOp

// LIBRARY: IMPERIALISM 0x005f4190 SYMBOL
// __abstract_sw
// name: _abstract_sw
// prototype: unsigned int __cdecl _abstract_sw(unsigned int)

// LIBRARY: IMPERIALISM 0x005f41e0
// _tolower

// LIBRARY: IMPERIALISM 0x005f4270 SYMBOL
// __tolower_lk

// LIBRARY: IMPERIALISM 0x005f4370 SYMBOL
// __ZeroTail
// name: _ZeroTail

// LIBRARY: IMPERIALISM 0x005f43e0 SYMBOL
// __IncMan
// name: _IncMan

// LIBRARY: IMPERIALISM 0x005f4450 SYMBOL
// __RoundMan
// name: _RoundMan

// LIBRARY: IMPERIALISM 0x005f44f0 SYMBOL
// __CopyMan
// name: _CopyMan

// LIBRARY: IMPERIALISM 0x005f4510 SYMBOL
// __FillZeroMan
// name: _FillZeroMan

// LIBRARY: IMPERIALISM 0x005f4520 SYMBOL
// __IsZeroMan
// name: _IsZeroMan

// LIBRARY: IMPERIALISM 0x005f4540 SYMBOL
// __ShrMan
// name: _ShrMan

// LIBRARY: IMPERIALISM 0x005f4600 SYMBOL
// __ld12cvt
// name: _ld12cvt

// LIBRARY: IMPERIALISM 0x005f47d0 SYMBOL
// ___ld12tod
// name: __ld12tod
// prototype: int __cdecl __ld12tod(_LDBL12 *,double *)

// LIBRARY: IMPERIALISM 0x005f47f0 SYMBOL
// ___ld12tof
// name: __ld12tof
// prototype: int __cdecl __ld12tof(_LDBL12 *,float *)

// LIBRARY: IMPERIALISM 0x005f4890 SYMBOL
// __atodbl
// name: _atodbl
// prototype: int __cdecl _atodbl(_CRT_DOUBLE *,char *)

// LIBRARY: IMPERIALISM 0x005f4910 SYMBOL
// __atoflt
// name: _atoflt
// prototype: int __cdecl _atoflt(_CRT_FLOAT *,char *)

// LIBRARY: IMPERIALISM 0x005f4950 SYMBOL
// __fptostr

// LIBRARY: IMPERIALISM 0x005f49f0 SYMBOL
// __fltout2
// name: _fltout2

// LIBRARY: IMPERIALISM 0x005f4a80 SYMBOL
// ___dtold
// name: __dtold

// LIBRARY: IMPERIALISM 0x005f4b40 SYMBOL
// __fptrap
// name: _fptrap
// prototype: void __cdecl _fptrap(void)

// LIBRARY: IMPERIALISM 0x005f4b50 SYMBOL
// ?_ValidateRead@@YAHPBXI@Z
// name: _ValidateRead
// prototype: int __cdecl _ValidateRead(void const *, unsigned int)

// LIBRARY: IMPERIALISM 0x005f4b70 SYMBOL
// ?_ValidateWrite@@YAHPAXI@Z
// name: _ValidateWrite
// prototype: int __cdecl _ValidateWrite(void *, unsigned int)

// LIBRARY: IMPERIALISM 0x005f4b90 SYMBOL
// ?_ValidateExecute@@YAHP6GHXZ@Z
// name: _ValidateExecute
// prototype: int __cdecl _ValidateExecute(int (__stdcall *)(void))

// LIBRARY: IMPERIALISM 0x005f4bb0
// ownership-only

// LIBRARY: IMPERIALISM 0x005f4cb0 SYMBOL
// __lseek

// LIBRARY: IMPERIALISM 0x005f4d30 SYMBOL
// __lseek_lk

// LIBRARY: IMPERIALISM 0x005f4db0 SYMBOL
// __getbuf

// LIBRARY: IMPERIALISM 0x005f4e10 SYMBOL
// __isatty

// LIBRARY: IMPERIALISM 0x005f4e40
// _wctomb

// LIBRARY: IMPERIALISM 0x005f4eb0 SYMBOL
// __wctomb_lk

// LIBRARY: IMPERIALISM 0x005f4f30
// _wcstombs

// LIBRARY: IMPERIALISM 0x005f4fb0 SYMBOL
// __wcstombs_lk

// LIBRARY: IMPERIALISM 0x005f51a0
// _wcsncnt

// LIBRARY: IMPERIALISM 0x005f5210 SYMBOL
// __getenv_lk

// LIBRARY: IMPERIALISM 0x005f52a0 SYMBOL
// __alloc_osfhnd

// LIBRARY: IMPERIALISM 0x005f5410 SYMBOL
// __set_osfhnd

// LIBRARY: IMPERIALISM 0x005f54c0 SYMBOL
// __free_osfhnd

// LIBRARY: IMPERIALISM 0x005f5560 SYMBOL
// __get_osfhandle

// LIBRARY: IMPERIALISM 0x005f5660 SYMBOL
// __lock_fhandle

// LIBRARY: IMPERIALISM 0x005f56d0 SYMBOL
// __unlock_fhandle

// LIBRARY: IMPERIALISM 0x005f5700 SYMBOL
// __commit

// LIBRARY: IMPERIALISM 0x005f57c0 SYMBOL
// __sopen

// LIBRARY: IMPERIALISM 0x005f5b60
// _mbtowc

// LIBRARY: IMPERIALISM 0x005f5be0 SYMBOL
// __mbtowc_lk

// LIBRARY: IMPERIALISM 0x005f5ce0 SYMBOL
// __allshl

// LIBRARY: IMPERIALISM 0x005f5d00 SYMBOL
// _ungetc
// name: ungetc
// prototype: int __cdecl ungetc(int, FILE *)

// LIBRARY: IMPERIALISM 0x005f5d30 SYMBOL
// __ungetc_lk

// LIBRARY: IMPERIALISM 0x005f5dc0 SYMBOL
// ___crtMessageBoxA

// LIBRARY: IMPERIALISM 0x005f5e50 SYMBOL
// ___init_time
// name: ___init_time
// prototype: int __cdecl ___init_time(void)

// LIBRARY: IMPERIALISM 0x005f5f00 SYMBOL
// __get_lc_time

// LIBRARY: IMPERIALISM 0x005f6280 SYMBOL
// __free_lc_time

// LIBRARY: IMPERIALISM 0x005f64c0
// _storeTimeFmt

// LIBRARY: IMPERIALISM 0x005f65c0 SYMBOL
// ___init_numeric
// name: ___init_numeric
// prototype: int __cdecl ___init_numeric(void)

// LIBRARY: IMPERIALISM 0x005f67c0
// _fix_grouping

// LIBRARY: IMPERIALISM 0x005f6800 SYMBOL
// ___lconv_init
// name: ___lconv_init
// prototype: int __cdecl ___lconv_init(void)

// LIBRARY: IMPERIALISM 0x005f68f0 SYMBOL
// __get_lc_lconv

// LIBRARY: IMPERIALISM 0x005f6a40
// _fix_grouping

// LIBRARY: IMPERIALISM 0x005f6a80 SYMBOL
// __free_lc_lconv

// LIBRARY: IMPERIALISM 0x005f6af9 SYMBOL
// ___init_ctype
// name: ___init_ctype
// prototype: void __cdecl ___init_ctype(void)

// LIBRARY: IMPERIALISM 0x005f6dc0
// _strncmp

// LIBRARY: IMPERIALISM 0x005f7300
// _signal

// LIBRARY: IMPERIALISM 0x005f7530 SYMBOL
// _ctrlevent_capture@4
// name: ctrlevent_capture
// prototype: int __stdcall ctrlevent_capture(unsigned long)

// LIBRARY: IMPERIALISM 0x005f75c0 SYMBOL
// _raise
// name: _raise
// prototype: int __cdecl _raise(int signal)

// LIBRARY: IMPERIALISM 0x005f77d0
// _siglookup

// LIBRARY: IMPERIALISM 0x005f7830 SYMBOL
// ___addl
// name: __addl

// LIBRARY: IMPERIALISM 0x005f7860 SYMBOL
// ___add_12
// name: __add_12

// LIBRARY: IMPERIALISM 0x005f78d0 SYMBOL
// ___shl_12
// name: __shl_12

// LIBRARY: IMPERIALISM 0x005f7900 SYMBOL
// ___shr_12
// name: __shr_12

// LIBRARY: IMPERIALISM 0x005f7930 SYMBOL
// ___mtold12
// name: __mtold12

// LIBRARY: IMPERIALISM 0x005f7a30 SYMBOL
// ___strgtold12
// name: __strgtold12
// prototype: unsigned int __cdecl __strgtold12(_LDBL12 *,char const * *,char const *,int,int,int,int)

// LIBRARY: IMPERIALISM 0x005f8210 SYMBOL
// _$I10_OUTPUT
// name: $I10_OUTPUT
// prototype: undefined ConvertExtendedFloatToStringInternal()

// LIBRARY: IMPERIALISM 0x005f8640 SYMBOL
// __mbsnbicoll

// LIBRARY: IMPERIALISM 0x005f8680 SYMBOL
// ___wtomb_environ

// LIBRARY: IMPERIALISM 0x005f8770 SYMBOL
// __chsize_lk

// LIBRARY: IMPERIALISM 0x005f88c0 SYMBOL
// ___getlocaleinfo

// LIBRARY: IMPERIALISM 0x005f8a80 SYMBOL
// ___crtGetLocaleInfoW

// LIBRARY: IMPERIALISM 0x005f8bb0 SYMBOL
// ___crtGetLocaleInfoA

// LIBRARY: IMPERIALISM 0x005f8d10
// _wcstoxl

// LIBRARY: IMPERIALISM 0x005f8f10 SYMBOL
// ___ld12mul
// name: __ld12mul

// LIBRARY: IMPERIALISM 0x005f91d0 SYMBOL
// ___multtenpow12
// name: __multtenpow12

// LIBRARY: IMPERIALISM 0x005f94b0 SYMBOL
// ___crtCompareStringA

// LIBRARY: IMPERIALISM 0x005f9780
// _strncnt

// LIBRARY: IMPERIALISM 0x005f97b0 SYMBOL
// ___crtsetenv

// LIBRARY: IMPERIALISM 0x005f99c0
// _findenv

// LIBRARY: IMPERIALISM 0x005f9a40
// _copy_environ

// LIBRARY: IMPERIALISM 0x005f9b20 SYMBOL
// __setmode_lk

// LIBRARY: IMPERIALISM 0x005f9b90
// _towupper

// LIBRARY: IMPERIALISM 0x005f9c20 SYMBOL
// __towupper_lk

// LIBRARY: IMPERIALISM 0x005f9ca0
// _iswctype

// LIBRARY: IMPERIALISM 0x005fa7c2
// ownership-only

// LIBRARY: IMPERIALISM 0x005fa7da SYMBOL
// ?AfxInitialize@@YGHHK@Z
// name: AfxInitialize
// prototype: int __stdcall AfxInitialize(int, unsigned long)

// LIBRARY: IMPERIALISM 0x005fa7f8 SYMBOL
// ??0_AFX_TERM_APP_STATE@@QAE@XZ
// name: _AFX_TERM_APP_STATE::_AFX_TERM_APP_STATE
// prototype: public: __thiscall _AFX_TERM_APP_STATE::_AFX_TERM_APP_STATE(void)

// LIBRARY: IMPERIALISM 0x005fa80b SYMBOL
// ??1_AFX_TERM_APP_STATE@@QAE@XZ
// name: _AFX_TERM_APP_STATE::~_AFX_TERM_APP_STATE
// prototype: public: __thiscall _AFX_TERM_APP_STATE::~_AFX_TERM_APP_STATE(void)

// LIBRARY: IMPERIALISM 0x005fa815
// InitializeMfcTermAppStateGlobal
// prototype: void __cdecl InitializeMfcTermAppStateGlobal(void)

// SYNTHETIC: IMPERIALISM 0x005fa81f
// ConstructMfcTermAppStateGlobal
// prototype: void __cdecl ConstructMfcTermAppStateGlobal(void)

// SYNTHETIC: IMPERIALISM 0x005fa829
// RegisterMfcGlobalCleanup_005fa835
// prototype: void __cdecl RegisterMfcGlobalCleanup_005fa835(void)

// SYNTHETIC: IMPERIALISM 0x005fa835
// DestroyMfcTermAppStateGlobalAtExit
// prototype: void __cdecl DestroyMfcTermAppStateGlobalAtExit(void)

// LIBRARY: IMPERIALISM 0x005fa845 SYMBOL
// ??0CToolTipCtrl@@QAE@XZ
// name: CToolTipCtrl::CToolTipCtrl
// prototype: public: __thiscall CToolTipCtrl::CToolTipCtrl(void)

// LIBRARY: IMPERIALISM 0x005fa87e SYMBOL
// ??_GCMonikerFile@@UAEPAXI@Z
// name: CMonikerFile::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CMonikerFile::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005fa89a SYMBOL
// ?Create@CToolTipCtrl@@QAEHPAVCWnd@@K@Z
// name: CToolTipCtrl::Create
// prototype: public: int __thiscall CToolTipCtrl::Create(class CWnd *, unsigned long)

// LIBRARY: IMPERIALISM 0x005fa8e5 SYMBOL
// ??1CToolTipCtrl@@UAE@XZ
// name: CToolTipCtrl::~CToolTipCtrl
// prototype: public: virtual __thiscall CToolTipCtrl::~CToolTipCtrl(void)

// LIBRARY: IMPERIALISM 0x005fa92c SYMBOL
// ?DestroyToolTipCtrl@CToolTipCtrl@@QAEHXZ
// name: CToolTipCtrl::DestroyToolTipCtrl
// prototype: public: int __thiscall CToolTipCtrl::DestroyToolTipCtrl(void)

// LIBRARY: IMPERIALISM 0x005fa946 SYMBOL
// ?OnAddTool@CToolTipCtrl@@IAEJIJ@Z
// name: CToolTipCtrl::OnAddTool
// prototype: protected: long __thiscall CToolTipCtrl::OnAddTool(unsigned int, long)

// LIBRARY: IMPERIALISM 0x005fa9ba
// MFC nafxcw handler in message map 0x674468 (base CWnd's map 0x670868),
// MFC-internal message 0x36c.

// LIBRARY: IMPERIALISM 0x005fa9d1 SYMBOL
// ?OnWindowFromPoint@CToolTipCtrl@@IAEJIJ@Z
// name: CToolTipCtrl::OnWindowFromPoint
// prototype: protected: long __thiscall CToolTipCtrl::OnWindowFromPoint(unsigned int, long)

// LIBRARY: IMPERIALISM 0x005faa44 SYMBOL
// ?AddTool@CToolTipCtrl@@QAEHPAVCWnd@@PBDPBUtagRECT@@I@Z
// name: CToolTipCtrl::AddTool
// prototype: public: int __thiscall CToolTipCtrl::AddTool(class CWnd *, char const *, struct tagRECT const *, unsigned int)

// LIBRARY: IMPERIALISM 0x005faa92 SYMBOL
// ?AddTool@CToolTipCtrl@@QAEHPAVCWnd@@IPBUtagRECT@@I@Z
// name: CToolTipCtrl::AddTool
// prototype: public: int __thiscall CToolTipCtrl::AddTool(class CWnd *, unsigned int, struct tagRECT const *, unsigned int)

// LIBRARY: IMPERIALISM 0x005faaec SYMBOL
// ?DelTool@CToolTipCtrl@@QAEXPAVCWnd@@I@Z
// name: CToolTipCtrl::DelTool
// prototype: public: void __thiscall CToolTipCtrl::DelTool(class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005fab1d SYMBOL
// ?GetText@CToolTipCtrl@@QBEXAAVCString@@PAVCWnd@@I@Z
// name: CToolTipCtrl::GetText
// prototype: public: void __thiscall CToolTipCtrl::GetText(class CString &, class CWnd *, unsigned int) const

// LIBRARY: IMPERIALISM 0x005fab68 SYMBOL
// ?GetToolInfo@CToolTipCtrl@@QBEHAAVCToolInfo@@PAVCWnd@@I@Z
// name: CToolTipCtrl::GetToolInfo
// prototype: public: int __thiscall CToolTipCtrl::GetToolInfo(class CToolInfo &, class CWnd *, unsigned int) const

// LIBRARY: IMPERIALISM 0x005fab9a SYMBOL
// ?HitTest@CToolTipCtrl@@QBEHPAVCWnd@@VCPoint@@PAUtagTOOLINFOA@@@Z
// name: CToolTipCtrl::HitTest
// prototype: public: int __thiscall CToolTipCtrl::HitTest(class CWnd *, class CPoint, struct tagTOOLINFOA *) const

// LIBRARY: IMPERIALISM 0x005fac0d SYMBOL
// ?SetToolRect@CToolTipCtrl@@QAEXPAVCWnd@@IPBUtagRECT@@@Z
// name: CToolTipCtrl::SetToolRect
// prototype: public: void __thiscall CToolTipCtrl::SetToolRect(class CWnd *, unsigned int, struct tagRECT const *)

// LIBRARY: IMPERIALISM 0x005fac4f SYMBOL
// ?UpdateTipText@CToolTipCtrl@@QAEXPBDPAVCWnd@@I@Z
// name: CToolTipCtrl::UpdateTipText
// prototype: public: void __thiscall CToolTipCtrl::UpdateTipText(char const *, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005fac86 SYMBOL
// ?UpdateTipText@CToolTipCtrl@@QAEXIPAVCWnd@@I@Z
// name: CToolTipCtrl::UpdateTipText
// prototype: public: void __thiscall CToolTipCtrl::UpdateTipText(unsigned int, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x005facd6 SYMBOL
// ?FillInToolInfo@CToolTipCtrl@@QBEXAAUtagTOOLINFOA@@PAVCWnd@@I@Z
// name: FillInToolInfo
// prototype: public: void __thiscall CToolTipCtrl::FillInToolInfo(struct tagTOOLINFOA &, class CWnd *, unsigned int) const

// LIBRARY: IMPERIALISM 0x005fad29 SYMBOL
// ?EnableToolTips@CWnd@@QAEHH@Z
// name: CWnd::EnableToolTips
// prototype: public: int __thiscall CWnd::EnableToolTips(int)

// LIBRARY: IMPERIALISM 0x005fadcb SYMBOL
// ?_FilterToolTipMessage@CWnd@@SGXPAUtagMSG@@PAV1@@Z
// name: CWnd::_FilterToolTipMessage
// prototype: public: static void __stdcall CWnd::_FilterToolTipMessage(struct tagMSG *, class CWnd *)

// LIBRARY: IMPERIALISM 0x005faddb SYMBOL
// ?FilterToolTipMessage@CWnd@@QAEXPAUtagMSG@@@Z
// name: CWnd::FilterToolTipMessage
// prototype: public: void __thiscall CWnd::FilterToolTipMessage(struct tagMSG *)

// LIBRARY: IMPERIALISM 0x005fb0d5 SYMBOL
// ?RelayToolTipMessage@@YGXPAVCToolTipCtrl@@PAUtagMSG@@@Z

// LIBRARY: IMPERIALISM 0x005feb02 SYMBOL
// ?AfxIsValidAddress@@YGHPBXIH@Z
// name: AfxIsValidAddress
// prototype: int __stdcall AfxIsValidAddress(void const *, unsigned int, int)

// LIBRARY: IMPERIALISM 0x005feb3b SYMBOL
// ??0CString@@QAE@DH@Z
// name: CString::CString
// prototype: public: __thiscall CString::CString(char, int)

// LIBRARY: IMPERIALISM 0x005feb73 SYMBOL
// ??0CString@@QAE@PBDH@Z
// name: CString::CString
// prototype: public: __thiscall CString::CString(char const *, int)

// LIBRARY: IMPERIALISM 0x005feba9 SYMBOL
// ??4CString@@QAEABV0@D@Z
// name: CString::operator=
// prototype: public: class CString const & __thiscall CString::operator=(char)

// LIBRARY: IMPERIALISM 0x005febbe SYMBOL
// ??H@YG?AVCString@@ABV0@D@Z
// name: operator+
// prototype: class CString __stdcall operator+(class CString const &, char)

// LIBRARY: IMPERIALISM 0x005fec20 SYMBOL
// ??H@YG?AVCString@@DABV0@@Z
// name: operator+
// prototype: class CString __stdcall operator+(char, class CString const &)

// LIBRARY: IMPERIALISM 0x005fec82 SYMBOL
// ?Mid@CString@@QBE?AV1@H@Z
// name: CString::Mid
// prototype: public: class CString __thiscall CString::Mid(int) const

// LIBRARY: IMPERIALISM 0x005feca5 SYMBOL
// ?Mid@CString@@QBE?AV1@HH@Z
// name: CString::Mid
// prototype: public: class CString __thiscall CString::Mid(int, int) const

// LIBRARY: IMPERIALISM 0x005fed30 SYMBOL
// ?Right@CString@@QBE?AV1@H@Z
// name: CString::Right
// prototype: public: class CString __thiscall CString::Right(int) const

// LIBRARY: IMPERIALISM 0x005fedad SYMBOL
// ?Left@CString@@QBE?AV1@H@Z
// name: CString::Left
// prototype: public: class CString __thiscall CString::Left(int) const

// LIBRARY: IMPERIALISM 0x005fee24 SYMBOL
// ?SpanExcluding@CString@@QBE?AV1@PBD@Z

// LIBRARY: IMPERIALISM 0x005fee4e SYMBOL
// ?SpanExcluding@CString@@QBE?AV1@PBD@Z

// LIBRARY: IMPERIALISM 0x005fee78 SYMBOL
// ?ReverseFind@CString@@QBEHD@Z
// name: CString::ReverseFind
// prototype: public: int __thiscall CString::ReverseFind(char) const

// LIBRARY: IMPERIALISM 0x005fee99 SYMBOL
// ?Find@CString@@QBEHPBD@Z
// name: CString::Find
// prototype: public: int __thiscall CString::Find(char const *) const

// LIBRARY: IMPERIALISM 0x005feeb8 SYMBOL
// ?FormatV@CString@@IAEXPBDPAD@Z
// name: CString::FormatV
// prototype: protected: void __thiscall CString::FormatV(char const *, char *)

// LIBRARY: IMPERIALISM 0x005ff1ba SYMBOL
// ?FormatMessageA@CString@@QAAXPBDZZ
// name: CString::FormatMessageA
// prototype: public: void __cdecl CString::FormatMessageA(char const *, ...)

// LIBRARY: IMPERIALISM 0x005ff206 SYMBOL
// ?FormatMessageA@CString@@QAAXIZZ
// name: CString::FormatMessageA
// prototype: public: void __cdecl CString::FormatMessageA(unsigned int, ...)

// LIBRARY: IMPERIALISM 0x005ff289 SYMBOL
// ?TrimRight@CString@@QAEXXZ
// name: CString::TrimRight
// prototype: public: void __thiscall CString::TrimRight(void)

// LIBRARY: IMPERIALISM 0x005ff2d2 SYMBOL
// ?TrimLeft@CString@@QAEXXZ
// name: CString::TrimLeft
// prototype: public: void __thiscall CString::TrimLeft(void)

// LIBRARY: IMPERIALISM 0x005ff36a SYMBOL
// ?CopyElements@@YGXPAVCString@@PBV1@H@Z
// name: CopyElements
// prototype: void __stdcall CopyElements(class CString *, class CString const *, int)

// LIBRARY: IMPERIALISM 0x005ff3cd SYMBOL
// ?InitString@CSimpleException@@QAEXXZ

// LIBRARY: IMPERIALISM 0x005ff3f6 SYMBOL
// ?GetErrorMessage@CSimpleException@@UAEHPADIPAI@Z
// name: CSimpleException::GetErrorMessage
// prototype: public: virtual int __thiscall CSimpleException::GetErrorMessage(char *, unsigned int, unsigned int *)

// LIBRARY: IMPERIALISM 0x005ff439 SYMBOL
// ?AfxThrowMemoryException@@YGXXZ
// name: AfxThrowMemoryException
// prototype: void __stdcall AfxThrowMemoryException(void)

// LIBRARY: IMPERIALISM 0x005ff454 SYMBOL
// ?AfxThrowNotSupportedException@@YGXXZ
// name: AfxThrowNotSupportedException
// prototype: void __stdcall AfxThrowNotSupportedException(void)

// LIBRARY: IMPERIALISM 0x005ff46f SYMBOL
// ??0CFileDialog@@QAE@HPBD0K0PAVCWnd@@@Z
// name: CFileDialog::CFileDialog
// prototype: public: __thiscall CFileDialog::CFileDialog(int, char const *, char const *, unsigned long, char const *, class CWnd *)

// LIBRARY: IMPERIALISM 0x005ff5c5 SYMBOL
// ??_GCFileDialog@@UAEPAXI@Z
// name: CFileDialog::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CFileDialog::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x005ff5e1 SYMBOL
// ?DoModal@CFileDialog@@UAEHXZ
// name: CFileDialog::DoModal
// prototype: public: virtual int __thiscall CFileDialog::DoModal(void)

// LIBRARY: IMPERIALISM 0x005ff69e SYMBOL
// ?GetPathName@CFileDialog@@QBE?AVCString@@XZ
// name: CFileDialog::GetPathName
// prototype: public: class CString __thiscall CFileDialog::GetPathName(void) const

// LIBRARY: IMPERIALISM 0x005ff7ac SYMBOL
// ?GetFileName@CFileDialog@@QBE?AVCString@@XZ
// name: CFileDialog::GetFileName
// prototype: public: class CString __thiscall CFileDialog::GetFileName(void) const

// LIBRARY: IMPERIALISM 0x005ff976 SYMBOL
// ?GetFileTitle@CFileDialog@@QBE?AVCString@@XZ
// name: CFileDialog::GetFileTitle
// prototype: public: class CString __thiscall CFileDialog::GetFileTitle(void) const

// LIBRARY: IMPERIALISM 0x005ff9e2 SYMBOL
// ?GetNextPathName@CFileDialog@@QBE?AVCString@@AAPAU__POSITION@@@Z
// name: CFileDialog::GetNextPathName
// prototype: public: class CString __thiscall CFileDialog::GetNextPathName(struct __POSITION *&) const

// LIBRARY: IMPERIALISM 0x005ffc15 SYMBOL
// ?GetFolderPath@CFileDialog@@QBE?AVCString@@XZ
// name: CFileDialog::GetFolderPath
// prototype: public: class CString __thiscall CFileDialog::GetFolderPath(void) const

// LIBRARY: IMPERIALISM 0x005ffd2d SYMBOL
// ?OnInitDone@CFileDialog@@MAEXXZ
// name: CFileDialog::OnInitDone
// prototype: protected: virtual void __thiscall CFileDialog::OnInitDone(void)

// LIBRARY: IMPERIALISM 0x005ffd49 SYMBOL
// ?OnNotify@CFileDialog@@MAEHIJPAJ@Z
// name: CFileDialog::OnNotify
// prototype: protected: virtual int __thiscall CFileDialog::OnNotify(unsigned int, long, long *)

// LIBRARY: IMPERIALISM 0x005ffe2c
// RegisterCommdlgLbSelChangedNotifyMessage
// prototype: void __cdecl RegisterCommdlgLbSelChangedNotifyMessage(void)

// LIBRARY: IMPERIALISM 0x005ffe42
// RegisterCommdlgShareViolationMessage
// prototype: void __cdecl RegisterCommdlgShareViolationMessage(void)

// LIBRARY: IMPERIALISM 0x005ffe58
// RegisterCommdlgFileNameOkMessage
// prototype: void __cdecl RegisterCommdlgFileNameOkMessage(void)

// LIBRARY: IMPERIALISM 0x005ffe6e
// RegisterCommdlgColorOkMessage
// prototype: void __cdecl RegisterCommdlgColorOkMessage(void)

// LIBRARY: IMPERIALISM 0x005ffe84
// RegisterCommdlgHelpMessage
// prototype: void __cdecl RegisterCommdlgHelpMessage(void)

// LIBRARY: IMPERIALISM 0x005ffe9a
// RegisterCommdlgSetRgbColorMessage
// prototype: void __cdecl RegisterCommdlgSetRgbColorMessage(void)

// LIBRARY: IMPERIALISM 0x005ffeb1 SYMBOL
// ?_AfxCommDlgProc@@YGIPAUHWND__@@IIJ@Z
// name: _AfxCommDlgProc
// prototype: unsigned int __stdcall _AfxCommDlgProc(struct HWND__*, unsigned int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x005fffe6 SYMBOL
// ?OnOK@CCommonDialog@@MAEXXZ
// name: CCommonDialog::OnOK
// prototype: protected: virtual void __thiscall CCommonDialog::OnOK(void)

// LIBRARY: IMPERIALISM 0x00600002
// MFC nafxcw handler in message map 0x673760 (base CDialog's map 0x66fb20),
// message 0x53 (WM_HELP).

// LIBRARY: IMPERIALISM 0x0060000a SYMBOL
// ??0CTime@@QAE@HHHHHHH@Z
// name: CTime::CTime
// prototype: public: __thiscall CTime::CTime(int, int, int, int, int, int, int)

// LIBRARY: IMPERIALISM 0x00600056 SYMBOL
// ??0CTime@@QAE@GGH@Z
// name: CTime::CTime
// prototype: public: __thiscall CTime::CTime(unsigned short, unsigned short, int)

// LIBRARY: IMPERIALISM 0x006000bf SYMBOL
// ??0CTime@@QAE@ABU_SYSTEMTIME@@H@Z
// name: CTime::CTime
// prototype: public: __thiscall CTime::CTime(struct _SYSTEMTIME const &, int)

// LIBRARY: IMPERIALISM 0x0060010b SYMBOL
// ??0CTime@@QAE@ABU_FILETIME@@H@Z
// name: CTime::CTime
// prototype: public: __thiscall CTime::CTime(struct _FILETIME const &, int)

// LIBRARY: IMPERIALISM 0x00600196 SYMBOL
// ?GetLocalTm@CTime@@QBEPAUtm@@PAU2@@Z
// name: CTime::GetLocalTm
// prototype: public: struct tm * __thiscall CTime::GetLocalTm(struct tm *) const

// LIBRARY: IMPERIALISM 0x00600205 SYMBOL
// ?Format@CTimeSpan@@QBE?AVCString@@PBD@Z
// name: CTimeSpan::Format
// prototype: public: class CString __thiscall CTimeSpan::Format(char const *) const

// LIBRARY: IMPERIALISM 0x00600331 SYMBOL
// ?Format@CTimeSpan@@QBE?AVCString@@I@Z
// name: CTimeSpan::Format
// prototype: public: class CString __thiscall CTimeSpan::Format(unsigned int) const

// LIBRARY: IMPERIALISM 0x0060038d SYMBOL
// ?FormatGmt@CTime@@QBE?AVCString@@PBD@Z

// LIBRARY: IMPERIALISM 0x006003de SYMBOL
// ?FormatGmt@CTime@@QBE?AVCString@@PBD@Z

// LIBRARY: IMPERIALISM 0x0060042f SYMBOL
// ?FormatGmt@CTime@@QBE?AVCString@@I@Z

// LIBRARY: IMPERIALISM 0x0060048b SYMBOL
// ?FormatGmt@CTime@@QBE?AVCString@@I@Z

// LIBRARY: IMPERIALISM 0x00601b74 SYMBOL
// ?Create@CPlex@@SGPAU1@AAPAU1@II@Z
// name: CPlex::Create
// prototype: public: static struct CPlex * __stdcall CPlex::Create(struct CPlex *&, unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x00601b94 SYMBOL
// ?FreeDataChain@CPlex@@QAEXXZ
// name: CPlex::FreeDataChain
// prototype: public: void __thiscall CPlex::FreeDataChain(void)

// LIBRARY: IMPERIALISM 0x00601baa SYMBOL
// ??0CPtrArray@@QAE@XZ
// name: CPtrArray::CPtrArray
// prototype: public: __thiscall CPtrArray::CPtrArray(void)

// LIBRARY: IMPERIALISM 0x00601bc1 SYMBOL
// ??_GCUIntArray@@UAEPAXI@Z
// name: CUIntArray::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CUIntArray::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00601bdd
// CPtrArray::~CPtrArray

// LIBRARY: IMPERIALISM 0x00601c14 SYMBOL
// ?SetSize@CPtrArray@@QAEXHH@Z
// name: CPtrArray::SetSize
// prototype: public: void __thiscall CPtrArray::SetSize(int, int)

// LIBRARY: IMPERIALISM 0x00601d37 SYMBOL
// ?Append@CUIntArray@@QAEHABV1@@Z
// name: CUIntArray::Append
// prototype: public: int __thiscall CUIntArray::Append(class CUIntArray const &)

// LIBRARY: IMPERIALISM 0x00601d71 SYMBOL
// ?Copy@CDWordArray@@QAEXABV1@@Z
// name: CDWordArray::Copy
// prototype: public: void __thiscall CDWordArray::Copy(class CDWordArray const &)

// LIBRARY: IMPERIALISM 0x00601d9d SYMBOL
// ?FreeExtra@CUIntArray@@QAEXXZ
// name: CUIntArray::FreeExtra
// prototype: public: void __thiscall CUIntArray::FreeExtra(void)

// LIBRARY: IMPERIALISM 0x00601de3
// CPtrArray::SetAtGrow

// LIBRARY: IMPERIALISM 0x00601e0a SYMBOL
// ?InsertAt@CPtrArray@@QAEXHPAXH@Z
// name: CPtrArray::InsertAt
// prototype: public: void __thiscall CPtrArray::InsertAt(int, void *, int)

// LIBRARY: IMPERIALISM 0x00601e9f
// CPtrArray::RemoveAt

// LIBRARY: IMPERIALISM 0x00601f1d SYMBOL
// ??0CPtrList@@QAE@H@Z
// name: CPtrList::CPtrList
// prototype: public: __thiscall CPtrList::CPtrList(int)

// SYNTHETIC: IMPERIALISM 0x00601f40
// ownership-only

// LIBRARY: IMPERIALISM 0x00601f5c SYMBOL
// ?RemoveAll@CPtrList@@QAEXXZ
// name: CPtrList::RemoveAll
// prototype: public: void __thiscall CPtrList::RemoveAll(void)

// LIBRARY: IMPERIALISM 0x00601f7c SYMBOL
// ??1CPtrList@@UAE@XZ
// name: CPtrList::~CPtrList
// prototype: public: virtual __thiscall CPtrList::~CPtrList(void)

// LIBRARY: IMPERIALISM 0x00601faf SYMBOL
// ?NewNode@CPtrList@@IAEPAUCNode@1@PAU21@0@Z
// name: CPtrList::NewNode
// prototype: protected: struct CPtrList::CNode * __thiscall CPtrList::NewNode(struct CPtrList::CNode *, struct CPtrList::CNode *)

// LIBRARY: IMPERIALISM 0x00602004
// CPtrList::FreeNode

// LIBRARY: IMPERIALISM 0x0060201d SYMBOL
// ?AddHead@CPtrList@@QAEPAU__POSITION@@PAX@Z
// name: CPtrList::AddHead
// prototype: public: struct __POSITION * __thiscall CPtrList::AddHead(void *)

// LIBRARY: IMPERIALISM 0x00602047 SYMBOL
// ?AddTail@CPtrList@@QAEPAU__POSITION@@PAX@Z
// name: CPtrList::AddTail
// prototype: public: struct __POSITION * __thiscall CPtrList::AddTail(void *)

// LIBRARY: IMPERIALISM 0x006020b9
// CPtrList::RemoveHead

// LIBRARY: IMPERIALISM 0x006020dd
// CPtrList::RemoveTail

// LIBRARY: IMPERIALISM 0x00602101
// CPtrList::InsertBefore

// LIBRARY: IMPERIALISM 0x00602140
// CPtrList::InsertAfter

// LIBRARY: IMPERIALISM 0x0060217d
// CPtrList::RemoveAt

// LIBRARY: IMPERIALISM 0x006021b4
// CPtrList::FindIndex

// LIBRARY: IMPERIALISM 0x006021d6
// CPtrList::Find

// LIBRARY: IMPERIALISM 0x0060339a SYMBOL
// ??0CMapPtrToPtr@@QAE@H@Z

// LIBRARY: IMPERIALISM 0x006033c1 SYMBOL
// ??_GCGdiObject@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x006033dd SYMBOL
// ?InitHashTable@CMapPtrToPtr@@QAEXIH@Z
// name: CMapPtrToPtr::InitHashTable
// prototype: public: void __thiscall CMapPtrToPtr::InitHashTable(unsigned int, int)

// LIBRARY: IMPERIALISM 0x00603423
// CMapPtrToPtr::RemoveAll

// LIBRARY: IMPERIALISM 0x0060344e SYMBOL
// ??1CMapPtrToPtr@@UAE@XZ
// name: CMapPtrToPtr::~CMapPtrToPtr
// prototype: public: virtual __thiscall CMapPtrToPtr::~CMapPtrToPtr(void)

// LIBRARY: IMPERIALISM 0x00603481 SYMBOL
// ?NewAssoc@CMapPtrToPtr@@IAEPAUCAssoc@1@XZ
// name: CMapPtrToPtr::NewAssoc
// prototype: protected: struct CMapPtrToPtr::CAssoc * __thiscall CMapPtrToPtr::NewAssoc(void)

// LIBRARY: IMPERIALISM 0x006034cb
// CMapPtrToPtr::FreeAssoc

// LIBRARY: IMPERIALISM 0x006034e4 SYMBOL
// ?GetAssocAt@CMapPtrToPtr@@IBEPAUCAssoc@1@PAXAAI@Z
// name: CMapPtrToPtr::GetAssocAt
// prototype: protected: struct CMapPtrToPtr::CAssoc * __thiscall CMapPtrToPtr::GetAssocAt(void *, unsigned int &) const

// LIBRARY: IMPERIALISM 0x00603516 SYMBOL
// ?GetValueAt@CMapPtrToPtr@@QBEPAXPAX@Z

// LIBRARY: IMPERIALISM 0x00603549 SYMBOL
// ?Lookup@CMapPtrToPtr@@QBEHPAXAAPAX@Z

// LIBRARY: IMPERIALISM 0x0060356b SYMBOL
// ??ACMapPtrToPtr@@QAEAAPAXPAX@Z
// name: CMapPtrToPtr::operator[]
// prototype: public: void *& __thiscall CMapPtrToPtr::operator[](void *)

// LIBRARY: IMPERIALISM 0x006035bb
// CMapPtrToPtr::RemoveKey

// LIBRARY: IMPERIALISM 0x006035fd SYMBOL
// ?GetNextAssoc@CMapPtrToPtr@@QBEXAAPAU__POSITION@@AAPAX1@Z
// name: CMapPtrToPtr::GetNextAssoc
// prototype: public: void __thiscall CMapPtrToPtr::GetNextAssoc(struct __POSITION *&, void *&, void *&) const

// LIBRARY: IMPERIALISM 0x0060366f SYMBOL
// ??0CMapStringToPtr@@QAE@H@Z
// name: CMapStringToPtr::CMapStringToPtr
// prototype: public: __thiscall CMapStringToPtr::CMapStringToPtr(int)

// LIBRARY: IMPERIALISM 0x00603696 SYMBOL
// ??_GCGdiObject@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x006036b2 SYMBOL
// ?InitHashTable@CMapStringToOb@@QAEXIH@Z

// LIBRARY: IMPERIALISM 0x006036f8 SYMBOL
// ?RemoveAll@CMapStringToOb@@QAEXXZ

// LIBRARY: IMPERIALISM 0x0060374a SYMBOL
// ??1CMapStringToPtr@@UAE@XZ
// name: CMapStringToPtr::~CMapStringToPtr
// prototype: public: virtual __thiscall CMapStringToPtr::~CMapStringToPtr(void)

// LIBRARY: IMPERIALISM 0x0060377d SYMBOL
// ?NewAssoc@CMapStringToOb@@IAEPAUCAssoc@1@XZ

// LIBRARY: IMPERIALISM 0x006037dd SYMBOL
// ?FreeAssoc@CMapStringToOb@@IAEXPAUCAssoc@1@@Z

// LIBRARY: IMPERIALISM 0x00603806 SYMBOL
// ?GetAssocAt@CMapStringToOb@@IBEPAUCAssoc@1@PBDAAI@Z

// LIBRARY: IMPERIALISM 0x00603860 SYMBOL
// ?Lookup@CMapStringToPtr@@QBEHPBDAAPAX@Z
// name: CMapStringToPtr::Lookup
// prototype: public: int __thiscall CMapStringToPtr::Lookup(char const *, void *&) const

// LIBRARY: IMPERIALISM 0x00603882 SYMBOL
// ?LookupKey@CMapStringToPtr@@QBEHPBDAAPBD@Z
// name: CMapStringToPtr::LookupKey
// prototype: public: int __thiscall CMapStringToPtr::LookupKey(char const *, char const *&) const

// LIBRARY: IMPERIALISM 0x006038a4 SYMBOL
// ??ACMapStringToPtr@@QAEAAPAXPBD@Z
// name: CMapStringToPtr::operator[]
// prototype: public: void *& __thiscall CMapStringToPtr::operator[](char const *)

// LIBRARY: IMPERIALISM 0x00603906 SYMBOL
// ?RemoveKey@CMapStringToOb@@QAEHPBD@Z

// LIBRARY: IMPERIALISM 0x0060396e SYMBOL
// ?GetNextAssoc@CMapStringToOb@@QBEXAAPAU__POSITION@@AAVCString@@AAPAVCObject@@@Z
// name: CMapStringToOb::GetNextAssoc
// prototype: public: void __thiscall CMapStringToOb::GetNextAssoc(struct __POSITION *&, class CString &, class CObject *&) const

// LIBRARY: IMPERIALISM 0x00604b68 SYMBOL
// ?AfxDlgProc@@YGHPAUHWND__@@IIJ@Z
// name: AfxDlgProc
// prototype: int __stdcall AfxDlgProc(struct HWND__*, unsigned int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x00604ba2 SYMBOL
// ?GetMessageMap@CDialog@@MBEPBUAFX_MSGMAP@@XZ
// name: CDialog::GetMessageMap
// prototype: protected: virtual struct AFX_MSGMAP const * __thiscall CDialog::GetMessageMap(void)const

// LIBRARY: IMPERIALISM 0x00604ba8 SYMBOL
// ?PreTranslateMessage@CDialog@@UAEHPAUtagMSG@@@Z
// name: CDialog::PreTranslateMessage
// prototype: public: virtual int __thiscall CDialog::PreTranslateMessage(struct tagMSG *)

// LIBRARY: IMPERIALISM 0x00604c41 SYMBOL
// ?OnCmdMsg@CDialog@@UAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z
// name: CDialog::OnCmdMsg
// prototype: public: virtual int __thiscall CDialog::OnCmdMsg(unsigned int,int,void *,struct AFX_CMDHANDLERINFO *)

// LIBRARY: IMPERIALISM 0x00604cc6 SYMBOL
// ??0CDialog@@QAE@XZ
// name: CDialog::CDialog
// prototype: public: __thiscall CDialog::CDialog(void)

// LIBRARY: IMPERIALISM 0x00604ce8
// ownership-only

// LIBRARY: IMPERIALISM 0x00604d04 SYMBOL
// ??1CDialog@@UAE@XZ

// LIBRARY: IMPERIALISM 0x00604d42 SYMBOL
// ?Create@CDialog@@QAEHPBDPAVCWnd@@@Z
// name: CDialog::Create
// prototype: public: int __thiscall CDialog::Create(char const *, class CWnd *)

// LIBRARY: IMPERIALISM 0x00604da4 SYMBOL
// ?CreateIndirect@CDialog@@IAEHPAXPAVCWnd@@PAUHINSTANCE__@@@Z
// name: CDialog::CreateIndirect
// prototype: protected: int __thiscall CDialog::CreateIndirect(void *, class CWnd *, struct HINSTANCE__*)

// LIBRARY: IMPERIALISM 0x00604ddd SYMBOL
// ?CreateIndirect@CDialog@@IAEHPBUDLGTEMPLATE@@PAVCWnd@@PAXPAUHINSTANCE__@@@Z
// name: CDialog::CreateIndirect
// prototype: protected: int __thiscall CDialog::CreateIndirect(struct DLGTEMPLATE const *, class CWnd *, void *, struct HINSTANCE__*)

// LIBRARY: IMPERIALISM 0x00604e08 SYMBOL
// ?CreateDlg@CWnd@@IAEHPBDPAV1@@Z
// name: CWnd::CreateDlg
// prototype: protected: int __thiscall CWnd::CreateDlg(char const *, class CWnd *)

// LIBRARY: IMPERIALISM 0x00604e4c SYMBOL
// ?CreateDlgIndirect@CWnd@@IAEHPBUDLGTEMPLATE@@PAV1@@Z
// name: CWnd::CreateDlgIndirect
// prototype: protected: int __thiscall CWnd::CreateDlgIndirect(struct DLGTEMPLATE const *, class CWnd *)

// LIBRARY: IMPERIALISM 0x00604e5e SYMBOL
// ?CreateDlgIndirect@CWnd@@IAEHPBUDLGTEMPLATE@@PAV1@PAUHINSTANCE__@@@Z

// LIBRARY: IMPERIALISM 0x0060507c SYMBOL
// ?SetOccDialogInfo@CWnd@@MAEHPAU_AFX_OCC_DIALOG_INFO@@@Z
// name: CWnd::SetOccDialogInfo
// prototype: protected: virtual int __thiscall CWnd::SetOccDialogInfo(struct _AFX_OCC_DIALOG_INFO *)

// LIBRARY: IMPERIALISM 0x00605081 SYMBOL
// ?SetOccDialogInfo@CDialog@@MAEHPAU_AFX_OCC_DIALOG_INFO@@@Z
// name: CDialog::SetOccDialogInfo
// prototype: protected: virtual int __thiscall CDialog::SetOccDialogInfo(struct _AFX_OCC_DIALOG_INFO *)

// LIBRARY: IMPERIALISM 0x0060508e SYMBOL
// ??0CDialog@@QAE@PBDPAVCWnd@@@Z
// name: CDialog::CDialog
// prototype: public: __thiscall CDialog::CDialog(char const *, class CWnd *)

// LIBRARY: IMPERIALISM 0x006050d0 SYMBOL
// ??0CDialog@@QAE@IPAVCWnd@@@Z
// name: CDialog::CDialog
// prototype: public: __thiscall CDialog::CDialog(unsigned int,class CWnd *)

// LIBRARY: IMPERIALISM 0x00605144 SYMBOL
// ?PreModal@CDialog@@IAEPAUHWND__@@XZ
// name: CDialog::PreModal
// prototype: protected: struct HWND__* __thiscall CDialog::PreModal(void)

// LIBRARY: IMPERIALISM 0x0060517b SYMBOL
// ?PostModal@CDialog@@IAEXXZ
// name: CDialog::PostModal
// prototype: protected: void __thiscall CDialog::PostModal(void)

// LIBRARY: IMPERIALISM 0x006051b9 SYMBOL
// ?DoModal@CDialog@@UAEHXZ
// name: CDialog::DoModal
// prototype: public: virtual int __thiscall CDialog::DoModal(void)

// LIBRARY: IMPERIALISM 0x0060531e SYMBOL
// ?EndDialog@CDialog@@QAEXH@Z
// name: CDialog::EndDialog
// prototype: public: void __thiscall CDialog::EndDialog(int)

// LIBRARY: IMPERIALISM 0x00605341
// MFC nafxcw handler in CDialog's message map 0x66fb20, MFC-internal
// message 0x30: forwards via 0x613a36.

// LIBRARY: IMPERIALISM 0x00605365 SYMBOL
// ?PreInitDialog@CDialog@@MAEXXZ
// name: CDialog::PreInitDialog
// prototype: protected: virtual void __thiscall CDialog::PreInitDialog(void)

// LIBRARY: IMPERIALISM 0x00605366 SYMBOL
// ?HandleInitDialog@CDialog@@IAEJIJ@Z
// name: CDialog::HandleInitDialog
// prototype: protected: long __thiscall CDialog::HandleInitDialog(unsigned int, long)

// LIBRARY: IMPERIALISM 0x006053ee SYMBOL
// ?AfxHelpEnabled@@YGHXZ
// name: AfxHelpEnabled
// prototype: int __stdcall AfxHelpEnabled(void)

// LIBRARY: IMPERIALISM 0x00605442 SYMBOL
// ?OnSetFont@CDialog@@UAEXPAVCFont@@@Z
// name: CDialog::OnSetFont
// prototype: protected: virtual void __thiscall CDialog::OnSetFont(class CFont *)

// LIBRARY: IMPERIALISM 0x00605445 SYMBOL
// ?OnInitDialog@CDialog@@UAEHXZ
// name: CDialog::OnInitDialog
// prototype: public: virtual int __thiscall CDialog::OnInitDialog(void)

// LIBRARY: IMPERIALISM 0x006054aa SYMBOL
// ?OnOK@CDialog@@MAEXXZ
// name: CDialog::OnOK
// prototype: protected: virtual void __thiscall CDialog::OnOK(void)

// LIBRARY: IMPERIALISM 0x006054c3 SYMBOL
// ?OnCancel@CDialog@@MAEXXZ
// name: CDialog::OnCancel
// prototype: protected: virtual void __thiscall CDialog::OnCancel(void)

// LIBRARY: IMPERIALISM 0x006054cb SYMBOL
// ?CheckAutoCenter@CDialog@@UAEHXZ
// name: CDialog::CheckAutoCenter
// prototype: public: virtual int __thiscall CDialog::CheckAutoCenter(void)

// LIBRARY: IMPERIALISM 0x00605547
// MFC nafxcw handler in CDialog's message map 0x66fb20, MFC-internal
// message 0x19: pushes the three WM_ params and forwards to 0x60a0e4.

// LIBRARY: IMPERIALISM 0x0060555b
// MFC nafxcw handler in CDialog's message map 0x66fb20, MFC-internal
// message 0x365: help-id translation via [ecx+0x3c] + 0x20000 (HID_COMMAND).

// LIBRARY: IMPERIALISM 0x00605595
// MFC nafxcw handler in CDialog's message map 0x66fb20, MFC-internal
// message 0x366: returns [ecx+0x3c] + 0x20000 (HID_COMMAND base).

// LIBRARY: IMPERIALISM 0x006055ae SYMBOL
// ?Run@CWinApp@@UAEHXZ
// name: CWinApp::Run
// prototype: public: virtual int __thiscall CWinApp::Run(void)

// LIBRARY: IMPERIALISM 0x006055d0 SYMBOL
// ?WinHelpA@CWinApp@@UAEXKI@Z
// name: CWinApp::WinHelpA
// prototype: public: virtual void __thiscall CWinApp::WinHelpA(unsigned long, unsigned int)

// LIBRARY: IMPERIALISM 0x00605607 SYMBOL
// ?ProcessWndProcException@CWinApp@@UAEJPAVCException@@PBUtagMSG@@@Z
// name: CWinApp::ProcessWndProcException
// prototype: public: virtual long __thiscall CWinApp::ProcessWndProcException(class CException *,struct tagMSG const *)

// LIBRARY: IMPERIALISM 0x0060567e SYMBOL
// ?OnIdle@CWinApp@@UAEHJ@Z
// name: CWinApp::OnIdle
// prototype: public: virtual int __thiscall CWinApp::OnIdle(long)

// LIBRARY: IMPERIALISM 0x006056e4 SYMBOL
// ?DevModeChange@CWinApp@@QAEXPAD@Z
// name: CWinApp::DevModeChange
// prototype: public: void __thiscall CWinApp::DevModeChange(char *)

// LIBRARY: IMPERIALISM 0x00605818 SYMBOL
// ?Release@CString@@IAEXXZ
// name: CString::Release
// prototype: protected: void __thiscall CString::Release(void)

// LIBRARY: IMPERIALISM 0x0060590b SYMBOL
// ?AllocCopy@CString@@IBEXAAV1@HHH@Z
// name: CString::AllocCopy
// prototype: protected: void __thiscall CString::AllocCopy(class CString &, int, int, int) const

// LIBRARY: IMPERIALISM 0x006059ae SYMBOL
// ??0CString@@QAE@PBG@Z
// name: CString::CString
// prototype: public: __thiscall CString::CString(unsigned short const *)

// LIBRARY: IMPERIALISM 0x00605a9f SYMBOL
// ??4CString@@QAEABV0@PBG@Z
// name: CString::operator=
// prototype: public: class CString const & __thiscall CString::operator=(unsigned short const *)

// LIBRARY: IMPERIALISM 0x00605e12 SYMBOL
// ?Find@CString@@QBEHD@Z

// LIBRARY: IMPERIALISM 0x00605e33 SYMBOL
// ?FindOneOf@CString@@QBEHPBD@Z

// LIBRARY: IMPERIALISM 0x00605e52
// ownership-only

// LIBRARY: IMPERIALISM 0x00605e64 SYMBOL
// ?MakeReverse@CString@@QAEXXZ

// LIBRARY: IMPERIALISM 0x00605e76 SYMBOL
// ?MakeReverse@CString@@QAEXXZ

// LIBRARY: IMPERIALISM 0x00605e88 SYMBOL
// ?SetAt@CString@@QAEXHD@Z
// name: CString::SetAt
// prototype: public: void __thiscall CString::SetAt(int, char)

// LIBRARY: IMPERIALISM 0x00605ea1 SYMBOL
// ?OemToCharA@CString@@QAEXXZ

// LIBRARY: IMPERIALISM 0x00605eb5 SYMBOL
// ?OemToCharA@CString@@QAEXXZ

// LIBRARY: IMPERIALISM 0x00605ec9 SYMBOL
// ?_wcstombsz@@YAHPADPBGI@Z
// name: _wcstombsz
// prototype: int __cdecl _wcstombsz(char *, unsigned short const *, unsigned int)

// LIBRARY: IMPERIALISM 0x00605eff SYMBOL
// ?_mbstowcsz@@YAHPAGPBDI@Z
// name: _mbstowcsz
// prototype: int __cdecl _mbstowcsz(unsigned short *, char const *, unsigned int)

// LIBRARY: IMPERIALISM 0x00605f34 SYMBOL
// ?AfxA2WHelper@@YGPAGPAGPBDH@Z
// name: AfxA2WHelper
// prototype: unsigned short * __stdcall AfxA2WHelper(unsigned short *, char const *, int)

// LIBRARY: IMPERIALISM 0x00605f87 SYMBOL
// ?_AfxThreadEntry@@YGIPAX@Z

// LIBRARY: IMPERIALISM 0x006060bc SYMBOL
// ?AfxGetThread@@YGPAVCWinThread@@XZ
// name: AfxGetThread
// prototype: class CWinThread * __stdcall AfxGetThread(void)

// LIBRARY: IMPERIALISM 0x00606155 SYMBOL
// ?AfxBeginThread@@YGPAVCWinThread@@PAUCRuntimeClass@@HIKPAU_SECURITY_ATTRIBUTES@@@Z
// name: AfxBeginThread
// prototype: class CWinThread * __stdcall AfxBeginThread(struct CRuntimeClass *, int, unsigned int, unsigned long, struct _SECURITY_ATTRIBUTES *)

// LIBRARY: IMPERIALISM 0x006061b7 SYMBOL
// ?AfxEndThread@@YGXIH@Z
// name: AfxEndThread
// prototype: void __stdcall AfxEndThread(unsigned int, int)

// LIBRARY: IMPERIALISM 0x006061ff SYMBOL
// ?AfxInitThread@@YGXXZ
// name: AfxInitThread
// prototype: void __stdcall AfxInitThread(void)

// LIBRARY: IMPERIALISM 0x0060625e SYMBOL
// ?AfxTermThread@@YGXPAUHINSTANCE__@@@Z
// name: AfxTermThread
// prototype: void __stdcall AfxTermThread(struct HINSTANCE__*)

// LIBRARY: IMPERIALISM 0x006062c2 SYMBOL
// ?CreateThread@CWinThread@@QAEHKIPAU_SECURITY_ATTRIBUTES@@@Z
// name: CWinThread::CreateThread
// prototype: public: int __thiscall CWinThread::CreateThread(unsigned long, unsigned int, struct _SECURITY_ATTRIBUTES *)

// LIBRARY: IMPERIALISM 0x006063b8 SYMBOL
// ?Delete@CWinThread@@UAEXXZ
// name: CWinThread::Delete
// prototype: public: virtual void __thiscall CWinThread::Delete(void)

// LIBRARY: IMPERIALISM 0x006063cd SYMBOL
// ?Run@CWinThread@@UAEHXZ
// name: CWinThread::Run
// prototype: public: virtual int __thiscall CWinThread::Run(void)

// LIBRARY: IMPERIALISM 0x00606451 SYMBOL
// ?IsIdleMessage@CWinThread@@UAEHPAUtagMSG@@@Z
// name: CWinThread::IsIdleMessage
// prototype: public: virtual int __thiscall CWinThread::IsIdleMessage(struct tagMSG *)

// LIBRARY: IMPERIALISM 0x006064b0 SYMBOL
// ?OnIdle@CWinThread@@UAEHJ@Z
// name: CWinThread::OnIdle
// prototype: public: virtual int __thiscall CWinThread::OnIdle(long)

// LIBRARY: IMPERIALISM 0x006065c7 SYMBOL
// ?DispatchThreadMessageEx@CWinThread@@IAEHPAUtagMSG@@@Z
// name: CWinThread::DispatchThreadMessageEx
// prototype: protected: int __thiscall CWinThread::DispatchThreadMessageEx(struct tagMSG *)

// LIBRARY: IMPERIALISM 0x00606640 SYMBOL
// ?PreTranslateMessage@CWinThread@@UAEHPAUtagMSG@@@Z
// name: CWinThread::PreTranslateMessage
// prototype: public: virtual int __thiscall CWinThread::PreTranslateMessage(struct tagMSG *)

// LIBRARY: IMPERIALISM 0x00606725 SYMBOL
// ?ProcessWndProcException@CWinThread@@UAEJPAVCException@@PBUtagMSG@@@Z
// name: CWinThread::ProcessWndProcException
// prototype: public: virtual long __thiscall CWinThread::ProcessWndProcException(class CException *, struct tagMSG const *)

// LIBRARY: IMPERIALISM 0x0060674a SYMBOL
// ?_AfxMsgFilterHook@@YGJHIJ@Z
// name: _AfxMsgFilterHook
// prototype: long __stdcall _AfxMsgFilterHook(int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x006067a2 SYMBOL
// ?ProcessMessageFilter@CWinThread@@UAEHHPAUtagMSG@@@Z
// name: CWinThread::ProcessMessageFilter
// prototype: public: virtual int __thiscall CWinThread::ProcessMessageFilter(int, struct tagMSG *)

// LIBRARY: IMPERIALISM 0x006068e9 SYMBOL
// ?IsHelpKey@@YGHPAUtagMSG@@@Z

// LIBRARY: IMPERIALISM 0x00606934 SYMBOL
// ?GetMainWnd@CWinThread@@UAEPAVCWnd@@XZ
// name: CWinThread::GetMainWnd
// prototype: public: virtual class CWnd * __thiscall CWinThread::GetMainWnd(void)

// LIBRARY: IMPERIALISM 0x0060694f SYMBOL
// ?PumpMessage@CWinThread@@UAEHXZ
// name: CWinThread::PumpMessage
// prototype: public: virtual int __thiscall CWinThread::PumpMessage(void)

// LIBRARY: IMPERIALISM 0x0060698f SYMBOL
// ??0CCmdTarget@@QAE@XZ
// name: CCmdTarget::CCmdTarget
// prototype: public: __thiscall CCmdTarget::CCmdTarget(void)

// LIBRARY: IMPERIALISM 0x006069af SYMBOL
// ??_GCCmdTarget@@UAEPAXI@Z
// name: CCmdTarget::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CCmdTarget::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x006069cb SYMBOL
// ??1CCmdTarget@@UAE@XZ
// name: CCmdTarget::~CCmdTarget
// prototype: public: virtual __thiscall CCmdTarget::~CCmdTarget(void)

// LIBRARY: IMPERIALISM 0x00606a07 SYMBOL
// ?OnCmdMsg@CCmdTarget@@UAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z
// name: CCmdTarget::OnCmdMsg
// prototype: public: virtual int __thiscall CCmdTarget::OnCmdMsg(unsigned int, int, void *, struct AFX_CMDHANDLERINFO *)

// LIBRARY: IMPERIALISM 0x00606b1f SYMBOL
// ?DispatchCmdMsg@@YAHPAVCCmdTarget@@IHP81@AEXXZPAXIPAUAFX_CMDHANDLERINFO@@@Z

// LIBRARY: IMPERIALISM 0x00606c4e SYMBOL
// ?IsInvokeAllowed@CCmdTarget@@UAEHJ@Z
// name: CCmdTarget::IsInvokeAllowed
// prototype: public: virtual int __thiscall CCmdTarget::IsInvokeAllowed(long)

// LIBRARY: IMPERIALISM 0x00606c54 SYMBOL
// ?GetDispatchIID@CCmdTarget@@UAEHPAU_GUID@@@Z
// name: CCmdTarget::GetDispatchIID
// prototype: public: virtual int __thiscall CCmdTarget::GetDispatchIID(struct _GUID *)

// LIBRARY: IMPERIALISM 0x00606c59 SYMBOL
// ?GetTypeInfoCount@CCmdTarget@@UAEIXZ
// name: CCmdTarget::GetTypeInfoCount
// prototype: public: virtual unsigned int __thiscall CCmdTarget::GetTypeInfoCount(void)

// LIBRARY: IMPERIALISM 0x00606c5c SYMBOL
// ?GetTypeLibCache@CCmdTarget@@UAEPAVCTypeLibCache@@XZ
// name: CCmdTarget::GetTypeLibCache
// prototype: public: virtual class CTypeLibCache * __thiscall CCmdTarget::GetTypeLibCache(void)

// LIBRARY: IMPERIALISM 0x00606c5f SYMBOL
// ?GetTypeLib@CCmdTarget@@UAEJKPAPAUITypeLib@@@Z
// name: CCmdTarget::GetTypeLib
// prototype: public: virtual long __thiscall CCmdTarget::GetTypeLib(unsigned long,struct ITypeLib * *)

// LIBRARY: IMPERIALISM 0x00606c67 SYMBOL
// ?BeginWaitCursor@CCmdTarget@@QAEXXZ
// name: CCmdTarget::BeginWaitCursor
// prototype: void __thiscall BeginWaitCursor()

// LIBRARY: IMPERIALISM 0x00606c7c SYMBOL
// ?EndWaitCursor@CCmdTarget@@QAEXXZ
// name: CCmdTarget::EndWaitCursor
// prototype: void __thiscall EndWaitCursor()

// LIBRARY: IMPERIALISM 0x00606c91 SYMBOL
// ?RestoreWaitCursor@CCmdTarget@@QAEXXZ
// name: CCmdTarget::RestoreWaitCursor
// prototype: public: void __thiscall CCmdTarget::RestoreWaitCursor(void)

// LIBRARY: IMPERIALISM 0x00606ca6 SYMBOL
// ?GetMessageMap@CCmdTarget@@MBEPBUAFX_MSGMAP@@XZ
// name: CCmdTarget::GetMessageMap
// prototype: protected: virtual struct AFX_MSGMAP const * __thiscall CCmdTarget::GetMessageMap(void) const

// LIBRARY: IMPERIALISM 0x00606cac SYMBOL
// ?GetDispatchMap@CCmdTarget@@MBEPBUAFX_DISPMAP@@XZ
// name: CCmdTarget::GetDispatchMap
// prototype: protected: virtual struct AFX_DISPMAP const * __thiscall CCmdTarget::GetDispatchMap(void)const

// LIBRARY: IMPERIALISM 0x00606cb2 SYMBOL
// ?GetEventSinkMap@CCmdTarget@@MBEPBUAFX_EVENTSINKMAP@@XZ
// name: CCmdTarget::GetEventSinkMap
// prototype: protected: virtual struct AFX_EVENTSINKMAP const * __thiscall CCmdTarget::GetEventSinkMap(void)const

// LIBRARY: IMPERIALISM 0x00606cb8 SYMBOL
// ?GetInterfaceMap@CCmdTarget@@MBEPBUAFX_INTERFACEMAP@@XZ
// name: CCmdTarget::GetInterfaceMap
// prototype: protected: virtual struct AFX_INTERFACEMAP const * __thiscall CCmdTarget::GetInterfaceMap(void)const

// LIBRARY: IMPERIALISM 0x00606cbe SYMBOL
// ?OnFinalRelease@CCmdTarget@@UAEXXZ
// name: CCmdTarget::OnFinalRelease
// prototype: public: virtual void __thiscall CCmdTarget::OnFinalRelease(void)

// LIBRARY: IMPERIALISM 0x00606cf0 SYMBOL
// ?OnCreateAggregates@CCmdTarget@@UAEHXZ
// name: CCmdTarget::OnCreateAggregates
// prototype: public: virtual int __thiscall CCmdTarget::OnCreateAggregates(void)

// LIBRARY: IMPERIALISM 0x00606cf4 SYMBOL
// ?GetInterfaceHook@CCmdTarget@@UAEPAUIUnknown@@PBX@Z
// name: CCmdTarget::GetInterfaceHook
// prototype: public: virtual struct IUnknown * __thiscall CCmdTarget::GetInterfaceHook(void const *)

// LIBRARY: IMPERIALISM 0x00606cf9 SYMBOL
// ?GetConnectionMap@CCmdTarget@@MBEPBUAFX_CONNECTIONMAP@@XZ
// name: CCmdTarget::GetConnectionMap
// prototype: protected: virtual struct AFX_CONNECTIONMAP const * __thiscall CCmdTarget::GetConnectionMap(void)const

// LIBRARY: IMPERIALISM 0x00606cff SYMBOL
// ?GetConnectionHook@CCmdTarget@@MAEPAUIConnectionPoint@@ABU_GUID@@@Z
// name: CCmdTarget::GetConnectionHook
// prototype: public: virtual struct IConnectionPoint * __thiscall CCmdTarget::GetConnectionHook(struct _GUID const &)

// LIBRARY: IMPERIALISM 0x00606d04 SYMBOL
// ?GetExtraConnectionPoints@CCmdTarget@@MAEHPAVCPtrArray@@@Z
// name: CCmdTarget::GetExtraConnectionPoints
// prototype: public: virtual int __thiscall CCmdTarget::GetExtraConnectionPoints(class CPtrArray *)

// LIBRARY: IMPERIALISM 0x00606d09 SYMBOL
// ?GetCommandMap@CCmdTarget@@MBEPBUAFX_OLECMDMAP@@XZ
// name: CCmdTarget::GetCommandMap
// prototype: protected: virtual struct AFX_CMDMAP const * __thiscall CCmdTarget::GetCommandMap(void)const

// LIBRARY: IMPERIALISM 0x00606d1b SYMBOL
// ?GetRoutingFrame@CCmdTarget@@IAEPAVCFrameWnd@@XZ
// name: CCmdTarget::GetRoutingFrame
// prototype: protected: class CFrameWnd * __thiscall CCmdTarget::GetRoutingFrame(void)

// LIBRARY: IMPERIALISM 0x00606d27 SYMBOL
// ??0CCmdUI@@QAE@XZ
// name: CCmdUI::CCmdUI
// prototype: public: __thiscall CCmdUI::CCmdUI(void)

// LIBRARY: IMPERIALISM 0x00606d4d SYMBOL
// ?Enable@CCmdUI@@UAEXH@Z
// name: CCmdUI::Enable
// prototype: public: virtual void __thiscall CCmdUI::Enable(int)

// LIBRARY: IMPERIALISM 0x00606ddd SYMBOL
// ?SetCheck@CCmdUI@@UAEXH@Z
// name: CCmdUI::SetCheck
// prototype: public: virtual void __thiscall CCmdUI::SetCheck(int)

// LIBRARY: IMPERIALISM 0x00606e3f SYMBOL
// ?SetRadio@CCmdUI@@UAEXH@Z
// name: CCmdUI::SetRadio
// prototype: public: virtual void __thiscall CCmdUI::SetRadio(int)

// LIBRARY: IMPERIALISM 0x00606e91 SYMBOL
// ?SetText@CCmdUI@@UAEXPBD@Z
// name: CCmdUI::SetText
// prototype: public: virtual void __thiscall CCmdUI::SetText(char const *)

// LIBRARY: IMPERIALISM 0x00606ee7 SYMBOL
// ?DoUpdate@CCmdUI@@QAEHPAVCCmdTarget@@H@Z
// name: CCmdUI::DoUpdate
// prototype: public: int __thiscall CCmdUI::DoUpdate(class CCmdTarget *, int)

// LIBRARY: IMPERIALISM 0x00606f4e SYMBOL
// ?AfxNewHandler@@YAHI@Z
// name: AfxNewHandler
// prototype: int __cdecl AfxNewHandler(unsigned int)

// LIBRARY: IMPERIALISM 0x00606f5f SYMBOL
// ?AfxSetNewHandler@@YGP6AHI@ZP6AHI@Z@Z
// name: int
// prototype: int (__cdecl * __stdcall AfxSetNewHandler(int (__cdecl *)(unsigned int)))(unsigned int)

// LIBRARY: IMPERIALISM 0x00606f73 SYMBOL
// ??2@YAPAXI@Z
// name: operator new
// prototype: void * __cdecl operator new(unsigned int)

// LIBRARY: IMPERIALISM 0x00606faf SYMBOL
// ??3@YAXPAX@Z
// name: operator delete
// prototype: void __cdecl operator delete(void *)

// LIBRARY: IMPERIALISM 0x00606fba
// CObject::GetRuntimeClass

// LIBRARY: IMPERIALISM 0x00606fc0 SYMBOL
// ?IsKindOf@CObject@@QBEHPBUCRuntimeClass@@@Z
// name: CObject::IsKindOf
// prototype: public: int __thiscall CObject::IsKindOf(struct CRuntimeClass const *) const

// LIBRARY: IMPERIALISM 0x00606fd2 SYMBOL
// ?AfxDynamicDownCast@@YAPAVCObject@@PAUCRuntimeClass@@PAV1@@Z
// name: AfxDynamicDownCast
// prototype: class CObject * __cdecl AfxDynamicDownCast(struct CRuntimeClass *, class CObject *)

// LIBRARY: IMPERIALISM 0x00606ff2 SYMBOL
// ?CreateObject@CRuntimeClass@@QAEPAVCObject@@XZ

// LIBRARY: IMPERIALISM 0x0060704b SYMBOL
// ??0AFX_CLASSINIT@@QAE@PAUCRuntimeClass@@@Z
// name: AFX_CLASSINIT::AFX_CLASSINIT
// prototype: public: __thiscall AFX_CLASSINIT::AFX_CLASSINIT(struct CRuntimeClass *)

// LIBRARY: IMPERIALISM 0x00607077 SYMBOL
// ?IsDerivedFrom@CRuntimeClass@@QBEHPBU1@@Z
// name: CRuntimeClass::IsDerivedFrom
// prototype: public: int __thiscall CRuntimeClass::IsDerivedFrom(struct CRuntimeClass const *) const

// LIBRARY: IMPERIALISM 0x00607090 SYMBOL
// ?OnAmbientProperty@CWnd@@UAEHPAVCOleControlSite@@JPAUtagVARIANT@@@Z
// name: CWnd::OnAmbientProperty
// prototype: public: virtual int __thiscall CWnd::OnAmbientProperty(class COleControlSite *, long, struct tagVARIANT *)

// LIBRARY: IMPERIALISM 0x006070df SYMBOL
// ?CheckRadioButton@CWnd@@QAEXHHH@Z
// name: CWnd::CheckRadioButton
// prototype: public: void __thiscall CWnd::CheckRadioButton(int, int, int)

// LIBRARY: IMPERIALISM 0x00607111 SYMBOL
// ?GetDlgItem@CWnd@@QBEPAV1@H@Z
// name: CWnd::GetDlgItem
// prototype: public: class CWnd * __thiscall CWnd::GetDlgItem(int) const

// LIBRARY: IMPERIALISM 0x0060713b SYMBOL
// ?GetDlgItem@CWnd@@QBEXHPAPAUHWND__@@@Z
// name: CWnd::GetDlgItem
// prototype: public: void __thiscall CWnd::GetDlgItem(int, struct HWND__**) const

// LIBRARY: IMPERIALISM 0x00607169 SYMBOL
// ?GetDlgItemInt@CWnd@@QBEIHPAHH@Z
// name: CWnd::GetDlgItemInt
// prototype: public: unsigned int __thiscall CWnd::GetDlgItemInt(int, int *, int) const

// LIBRARY: IMPERIALISM 0x0060719b SYMBOL
// ?GetDlgItemTextA@CWnd@@QBEHHPADH@Z
// name: CWnd::GetDlgItemTextA
// prototype: public: int __thiscall CWnd::GetDlgItemTextA(int, char *, int) const

// LIBRARY: IMPERIALISM 0x006071d0 SYMBOL
// ?SendDlgItemMessageA@CWnd@@QAEJHIIJ@Z
// name: CWnd::SendDlgItemMessageA
// prototype: public: long __thiscall CWnd::SendDlgItemMessageA(int, unsigned int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x0060720b SYMBOL
// ?SetDlgItemInt@CWnd@@QAEXHIH@Z
// name: CWnd::SetDlgItemInt
// prototype: public: void __thiscall CWnd::SetDlgItemInt(int, unsigned int, int)

// LIBRARY: IMPERIALISM 0x0060726f SYMBOL
// ?IsDlgButtonChecked@CWnd@@QBEIH@Z
// name: CWnd::IsDlgButtonChecked
// prototype: public: unsigned int __thiscall CWnd::IsDlgButtonChecked(int) const

// LIBRARY: IMPERIALISM 0x00607296 SYMBOL
// ?ScrollWindowEx@CWnd@@QAEHHHPBUtagRECT@@0PAVCRgn@@PAU2@I@Z
// name: CWnd::ScrollWindowEx
// prototype: public: int __thiscall CWnd::ScrollWindowEx(int, int, struct tagRECT const *, struct tagRECT const *, class CRgn *, struct tagRECT *, unsigned int)

// LIBRARY: IMPERIALISM 0x006072e5 SYMBOL
// ?IsDialogMessageA@CWnd@@QAEHPAUtagMSG@@@Z
// name: CWnd::IsDialogMessageA
// prototype: public: int __thiscall CWnd::IsDialogMessageA(struct tagMSG *)

// LIBRARY: IMPERIALISM 0x00607318 SYMBOL
// ?GetStyle@CWnd@@QBEKXZ
// name: CWnd::GetStyle
// prototype: public: unsigned long __thiscall CWnd::GetStyle(void)const

// LIBRARY: IMPERIALISM 0x00607332 SYMBOL
// ?GetExStyle@CWnd@@QBEKXZ
// name: CWnd::GetExStyle
// prototype: public: unsigned long __thiscall CWnd::GetExStyle(void) const

// LIBRARY: IMPERIALISM 0x0060734c SYMBOL
// ?ModifyStyle@CWnd@@QAEHKKI@Z
// name: CWnd::ModifyStyle
// prototype: public: int __thiscall CWnd::ModifyStyle(unsigned long, unsigned long, unsigned int)

// LIBRARY: IMPERIALISM 0x00607380 SYMBOL
// ?ModifyStyleEx@CWnd@@QAEHKKI@Z
// name: CWnd::ModifyStyleEx
// prototype: public: int __thiscall CWnd::ModifyStyleEx(unsigned long, unsigned long, unsigned int)

// LIBRARY: IMPERIALISM 0x006073b4 SYMBOL
// ?SetWindowTextA@CWnd@@QAEXPBD@Z
// name: CWnd::SetWindowText
// prototype: public: void __thiscall CWnd::SetWindowText(char const *)

// LIBRARY: IMPERIALISM 0x00607469 SYMBOL
// ?MoveWindow@CWnd@@QAEXHHHHH@Z
// name: CWnd::MoveWindow
// prototype: public: void __thiscall CWnd::MoveWindow(int, int, int, int, int)

// LIBRARY: IMPERIALISM 0x006074aa SYMBOL
// ?SetWindowPos@CWnd@@QAEHPBV1@HHHHI@Z
// name: CWnd::SetWindowPos
// prototype: public: int __thiscall CWnd::SetWindowPos(class CWnd const *, int, int, int, int, unsigned int)

// LIBRARY: IMPERIALISM 0x006074f9 SYMBOL
// ?ShowWindow@CWnd@@QAEHH@Z
// name: CWnd::ShowWindow
// prototype: public: int __thiscall CWnd::ShowWindow(int)

// LIBRARY: IMPERIALISM 0x00607520 SYMBOL
// ?IsWindowEnabled@CWnd@@QBEHXZ
// name: CWnd::IsWindowEnabled
// prototype: public: int __thiscall CWnd::IsWindowEnabled(void) const

// LIBRARY: IMPERIALISM 0x0060753b SYMBOL
// ?EnableWindow@CWnd@@QAEHH@Z
// name: CWnd::EnableWindow
// prototype: public: int __thiscall CWnd::EnableWindow(int)

// LIBRARY: IMPERIALISM 0x00607562 SYMBOL
// ?SetFocus@CWnd@@QAEPAV1@XZ
// name: CWnd::SetFocus
// prototype: public: class CWnd * __thiscall CWnd::SetFocus(void)

// LIBRARY: IMPERIALISM 0x006075ea SYMBOL
// ?GetDSCCursor@CWnd@@QAEPAUIUnknown@@XZ
// name: CWnd::GetDSCCursor
// prototype: public: struct IUnknown * __thiscall CWnd::GetDSCCursor(void)

// LIBRARY: IMPERIALISM 0x00607643 SYMBOL
// ?AttachControlSite@CWnd@@IAEXPAVCHandleMap@@@Z

// LIBRARY: IMPERIALISM 0x00607673 SYMBOL
// ?AttachControlSite@CWnd@@QAEXPAV1@@Z
// name: CWnd::AttachControlSite
// prototype: public: void __thiscall CWnd::AttachControlSite(class CWnd *)

// LIBRARY: IMPERIALISM 0x006076bd
// RegisterCommctrlDragListMessage
// prototype: void __cdecl RegisterCommctrlDragListMessage(void)

// LIBRARY: IMPERIALISM 0x006076ce
// InitializeMfcWndTopGlobal
// prototype: void __cdecl InitializeMfcWndTopGlobal(void)

// LIBRARY: IMPERIALISM 0x006076d8
// ownership-only

// SYNTHETIC: IMPERIALISM 0x006076e5
// RegisterMfcGlobalCleanup_006076f1
// prototype: void __cdecl RegisterMfcGlobalCleanup_006076f1(void)

// LIBRARY: IMPERIALISM 0x00607706
// CWnd::CWnd

// LIBRARY: IMPERIALISM 0x0060770c
// InitializeMfcWndBottomGlobal
// prototype: void __cdecl InitializeMfcWndBottomGlobal(void)

// LIBRARY: IMPERIALISM 0x00607716
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00607723
// RegisterMfcGlobalCleanup_0060772f
// prototype: void __cdecl RegisterMfcGlobalCleanup_0060772f(void)

// LIBRARY: IMPERIALISM 0x00607744
// CWnd::CWnd_00607744

// LIBRARY: IMPERIALISM 0x0060774a
// InitializeMfcWndTopMostGlobal
// prototype: void __cdecl InitializeMfcWndTopMostGlobal(void)

// LIBRARY: IMPERIALISM 0x00607754
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00607761
// RegisterMfcGlobalCleanup_0060776d
// prototype: void __cdecl RegisterMfcGlobalCleanup_0060776d(void)

// LIBRARY: IMPERIALISM 0x00607782
// CWnd::CWnd_00607782

// LIBRARY: IMPERIALISM 0x00607788
// InitializeMfcWndNoTopMostGlobal
// prototype: void __cdecl InitializeMfcWndNoTopMostGlobal(void)

// LIBRARY: IMPERIALISM 0x00607792
// ownership-only

// SYNTHETIC: IMPERIALISM 0x0060779f
// RegisterMfcGlobalCleanup_006077ab
// prototype: void __cdecl RegisterMfcGlobalCleanup_006077ab(void)

// LIBRARY: IMPERIALISM 0x006077c0
// CWnd::CWnd_006077C0

// LIBRARY: IMPERIALISM 0x006077c6 SYMBOL
// ??0CWnd@@QAE@XZ
// name: CWnd::CWnd
// prototype: public: __thiscall CWnd::CWnd(void)

// LIBRARY: IMPERIALISM 0x006077f0 SYMBOL
// ??_GCWnd@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x0060780c SYMBOL
// ??0CWnd@@AAE@PAUHWND__@@@Z
// name: CWnd::CWnd
// prototype: private: __thiscall CWnd::CWnd(struct HWND__*)

// LIBRARY: IMPERIALISM 0x00607840 SYMBOL
// ?ModifyStyle@CWnd@@SGHPAUHWND__@@KKI@Z
// name: CWnd::ModifyStyle
// prototype: public: static int __stdcall CWnd::ModifyStyle(struct HWND__*, unsigned long, unsigned long, unsigned int)

// LIBRARY: IMPERIALISM 0x0060785a SYMBOL
// ?_AfxModifyStyle@@YGHPAUHWND__@@HKKI@Z

// LIBRARY: IMPERIALISM 0x006078a9 SYMBOL
// ?ModifyStyleEx@CWnd@@SGHPAUHWND__@@KKI@Z
// name: CWnd::ModifyStyleEx
// prototype: public: static int __stdcall CWnd::ModifyStyleEx(struct HWND__*, unsigned long, unsigned long, unsigned int)

// LIBRARY: IMPERIALISM 0x006078c3 SYMBOL
// ?AfxCallWndProc@@YGJPAVCWnd@@PAUHWND__@@IIJ@Z

// LIBRARY: IMPERIALISM 0x006079b3 SYMBOL
// ?_AfxPreInitDialog@@YGXPAVCWnd@@PAUtagRECT@@PAK@Z

// LIBRARY: IMPERIALISM 0x006079d6 SYMBOL
// ?_AfxPostInitDialog@@YGXPAVCWnd@@ABUtagRECT@@K@Z

// LIBRARY: IMPERIALISM 0x00607a4f SYMBOL
// ?GetCurrentMessage@CWnd@@KGPBUtagMSG@@XZ
// name: CWnd::GetCurrentMessage
// prototype: protected: static struct tagMSG const * __stdcall CWnd::GetCurrentMessage(void)

// LIBRARY: IMPERIALISM 0x00607a84 SYMBOL
// ?Default@CWnd@@IAEJXZ
// name: CWnd::Default
// prototype: protected: long __thiscall CWnd::Default(void)

// LIBRARY: IMPERIALISM 0x00607aab SYMBOL
// ?DeleteTempMap@CMenu@@SGXXZ

// LIBRARY: IMPERIALISM 0x00607abf SYMBOL
// ?afxMapHWND@@YAPAVCHandleMap@@H@Z

// LIBRARY: IMPERIALISM 0x00607b2f SYMBOL
// ?FromHandle@CWnd@@SGPAV1@PAUHWND__@@@Z
// name: CWnd::FromHandle
// prototype: public: static class CWnd * __stdcall CWnd::FromHandle(struct HWND__*)

// LIBRARY: IMPERIALISM 0x00607b57 SYMBOL
// ?FromHandlePermanent@CWnd@@SGPAV1@PAUHWND__@@@Z
// name: CWnd::FromHandlePermanent
// prototype: public: static class CWnd * __stdcall CWnd::FromHandlePermanent(struct HWND__*)

// LIBRARY: IMPERIALISM 0x00607b73 SYMBOL
// ?Attach@CWnd@@QAEHPAUHWND__@@@Z
// name: CWnd::Attach
// prototype: public: int __thiscall CWnd::Attach(struct HWND__*)

// LIBRARY: IMPERIALISM 0x00607bac SYMBOL
// ?Detach@CWnd@@QAEPAUHWND__@@XZ
// name: CWnd::Detach
// prototype: public: struct HWND__* __thiscall CWnd::Detach(void)

// LIBRARY: IMPERIALISM 0x00607bda SYMBOL
// ?PreSubclassWindow@CWnd@@UAEXXZ
// name: CWnd::PreSubclassWindow
// prototype: public: virtual void __thiscall CWnd::PreSubclassWindow(void)

// LIBRARY: IMPERIALISM 0x00607bdb SYMBOL
// ?AfxWndProc@@YGJPAUHWND__@@IIJ@Z
// name: AfxWndProc
// prototype: long __stdcall AfxWndProc(struct HWND__*, unsigned int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x00607c0a SYMBOL
// ?AfxGetAfxWndProc@@YGP6GJPAUHWND__@@IIJ@ZXZ
// name: AfxGetAfxWndProc
// prototype: long (__stdcall * __stdcall AfxGetAfxWndProc(void))(struct HWND__ *, unsigned int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x00607c10 SYMBOL
// ?_AfxActivationWndProc@@YGJPAUHWND__@@IIJ@Z

// LIBRARY: IMPERIALISM 0x00607d5d SYMBOL
// ?_AfxHandleActivate@@YGXPAVCWnd@@I0@Z

// LIBRARY: IMPERIALISM 0x00607dbe SYMBOL
// ?_AfxHandleSetCursor@@YGHPAVCWnd@@II@Z

// LIBRARY: IMPERIALISM 0x00607e36 SYMBOL
// ?_AfxGrayBackgroundWndProc@@YGJPAUHWND__@@IIJ@Z
// name: _AfxGrayBackgroundWndProc
// prototype: long __stdcall _AfxGrayBackgroundWndProc(struct HWND__*, unsigned int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x00607eb2 SYMBOL
// ?_AfxCbtFilterHook@@YGJHIJ@Z
// name: _AfxCbtFilterHook
// prototype: long __stdcall _AfxCbtFilterHook(int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x00608040 SYMBOL
// ?AfxHookWindowCreate@@YGXPAVCWnd@@@Z
// name: AfxHookWindowCreate
// prototype: void __stdcall AfxHookWindowCreate(class CWnd *)

// LIBRARY: IMPERIALISM 0x0060808c SYMBOL
// ?AfxUnhookWindowCreate@@YGHXZ
// name: AfxUnhookWindowCreate
// prototype: int __stdcall AfxUnhookWindowCreate(void)

// LIBRARY: IMPERIALISM 0x006080ce SYMBOL
// ?CreateEx@CWnd@@QAEHKPBD0KABUtagRECT@@PAV1@IPAX@Z
// name: CWnd::CreateEx
// prototype: public: int __thiscall CWnd::CreateEx(unsigned long, char const *, char const *, unsigned long, struct tagRECT const &, class CWnd *, unsigned int, void *)

// LIBRARY: IMPERIALISM 0x00608115 SYMBOL
// ?CreateEx@CWnd@@QAEHKPBD0KHHHHPAUHWND__@@PAUHMENU__@@PAX@Z
// name: CWnd::CreateEx
// prototype: public: int __thiscall CWnd::CreateEx(unsigned long, char const *, char const *, unsigned long, int, int, int, int, struct HWND__*, struct HMENU__*, void *)

// LIBRARY: IMPERIALISM 0x006081d9 SYMBOL
// ?PreCreateWindow@CWnd@@UAEHAAUtagCREATESTRUCTA@@@Z
// name: CWnd::PreCreateWindow
// prototype: public: virtual int __thiscall CWnd::PreCreateWindow(struct tagCREATESTRUCTA &)

// LIBRARY: IMPERIALISM 0x0060820b SYMBOL
// ?Create@CWnd@@UAEHPBD0KABUtagRECT@@PAV1@IPAUCCreateContext@@@Z
// name: CWnd::Create
// prototype: public: virtual int __thiscall CWnd::Create(char const *, char const *, unsigned long, struct tagRECT const &, class CWnd *, unsigned int, struct CCreateContext *)

// LIBRARY: IMPERIALISM 0x00608257 SYMBOL
// ??1CWnd@@UAE@XZ

// LIBRARY: IMPERIALISM 0x006082d3 SYMBOL
// ?OnDestroy@CWnd@@IAEXXZ
// name: CWnd::OnDestroy
// prototype: protected: void __thiscall CWnd::OnDestroy(void)

// LIBRARY: IMPERIALISM 0x006082f1 SYMBOL
// ?OnNcDestroy@CWnd@@IAEXXZ
// name: CWnd::OnNcDestroy
// prototype: protected: void __thiscall CWnd::OnNcDestroy(void)

// LIBRARY: IMPERIALISM 0x00608408 SYMBOL
// ?PostNcDestroy@CWnd@@MAEXXZ
// name: CWnd::PostNcDestroy
// prototype: protected: virtual void __thiscall CWnd::PostNcDestroy(void)

// LIBRARY: IMPERIALISM 0x00608409 SYMBOL
// ?OnFinalRelease@CWnd@@UAEXXZ
// name: CWnd::OnFinalRelease
// prototype: public: virtual void __thiscall CWnd::OnFinalRelease(void)

// LIBRARY: IMPERIALISM 0x0060841a SYMBOL
// ?DestroyWindow@CWnd@@UAEHXZ
// name: CWnd::DestroyWindow
// prototype: public: virtual int __thiscall CWnd::DestroyWindow(void)

// LIBRARY: IMPERIALISM 0x00608467 SYMBOL
// ?DefWindowProcA@CWnd@@MAEJIIJ@Z
// name: CWnd::DefWindowProcA
// prototype: protected: virtual long __thiscall CWnd::DefWindowProcA(unsigned int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x006084ae SYMBOL
// ?GetSuperWndProcAddr@CWnd@@MAEPAP6GJPAUHWND__@@IIJ@ZXZ
// name: CWnd::GetSuperWndProcAddr
// prototype: protected: virtual long (__stdcall**__thiscall CWnd::GetSuperWndProcAddr(void))(struct HWND__ *,unsigned int,unsigned int,long)

// LIBRARY: IMPERIALISM 0x006084b2 SYMBOL
// ?PreTranslateMessage@CWnd@@UAEHPAUtagMSG@@@Z
// name: CWnd::PreTranslateMessage
// prototype: public: virtual int __thiscall CWnd::PreTranslateMessage(struct tagMSG *)

// LIBRARY: IMPERIALISM 0x006084d1 SYMBOL
// ?CancelToolTips@CWnd@@SGXH@Z
// name: CWnd::CancelToolTips
// prototype: public: static void __stdcall CWnd::CancelToolTips(int)

// LIBRARY: IMPERIALISM 0x0060852e SYMBOL
// ?OnToolHitTest@CWnd@@UBEHVCPoint@@PAUtagTOOLINFOA@@@Z
// name: CWnd::OnToolHitTest
// prototype: public: virtual int __thiscall CWnd::OnToolHitTest(struct tagPOINT,struct tagTOOLINFOA *)const

// LIBRARY: IMPERIALISM 0x0060859f SYMBOL
// ?GetWindowTextA@CWnd@@QBEXAAVCString@@@Z
// name: CWnd::GetWindowText
// prototype: public: void __thiscall CWnd::GetWindowText(class CString &)const

// LIBRARY: IMPERIALISM 0x00608657 SYMBOL
// ?GetWindowPlacement@CWnd@@QBEHPAUtagWINDOWPLACEMENT@@@Z
// name: CWnd::GetWindowPlacement
// prototype: public: int __thiscall CWnd::GetWindowPlacement(struct tagWINDOWPLACEMENT *) const

// LIBRARY: IMPERIALISM 0x0060866e SYMBOL
// ?GetWindowPlacement@CWnd@@QBEHPAUtagWINDOWPLACEMENT@@@Z
// name: CWnd::GetWindowPlacement
// prototype: public: int __thiscall CWnd::GetWindowPlacement(struct tagWINDOWPLACEMENT *) const

// LIBRARY: IMPERIALISM 0x00608685 SYMBOL
// ?OnDrawItem@CWnd@@IAEXHPAUtagDRAWITEMSTRUCT@@@Z
// name: CWnd::OnDrawItem
// prototype: protected: void __thiscall CWnd::OnDrawItem(int, struct tagDRAWITEMSTRUCT *)

// LIBRARY: IMPERIALISM 0x006086c2 SYMBOL
// ?OnCompareItem@CWnd@@IAEHHPAUtagCOMPAREITEMSTRUCT@@@Z
// name: CWnd::OnCompareItem
// prototype: protected: int __thiscall CWnd::OnCompareItem(int, struct tagCOMPAREITEMSTRUCT *)

// LIBRARY: IMPERIALISM 0x0060870c SYMBOL
// ?OnCharToItem@CWnd@@IAEHIPAVCListBox@@I@Z

// LIBRARY: IMPERIALISM 0x00608737 SYMBOL
// ?OnCharToItem@CWnd@@IAEHIPAVCListBox@@I@Z

// LIBRARY: IMPERIALISM 0x00608762 SYMBOL
// ?TrackPopupMenu@CMenu@@QAEHIHHPAVCWnd@@PBUtagRECT@@@Z
// name: CMenu::TrackPopupMenu
// prototype: public: int __thiscall CMenu::TrackPopupMenu(unsigned int, int, int, class CWnd *, struct tagRECT const *)

// LIBRARY: IMPERIALISM 0x006087b6 SYMBOL
// ?OnMeasureItem@CWnd@@IAEXHPAUtagMEASUREITEMSTRUCT@@@Z
// name: CWnd::OnMeasureItem
// prototype: protected: void __thiscall CWnd::OnMeasureItem(int, struct tagMEASUREITEMSTRUCT *)

// LIBRARY: IMPERIALISM 0x0060882f SYMBOL
// ?FindPopupMenuFromID@@YAPAVCMenu@@PAV1@I@Z

// LIBRARY: IMPERIALISM 0x00608892 SYMBOL
// ?AfxRegisterClass@@YGHPAUtagWNDCLASSA@@@Z

// LIBRARY: IMPERIALISM 0x0060893b SYMBOL
// ?AfxRegisterWndClass@@YGPBDIPAUHICON__@@PAUHBRUSH__@@0@Z
// name: AfxRegisterWndClass
// prototype: char const * __stdcall AfxRegisterWndClass(unsigned int, struct HICON__*, struct HBRUSH__*, struct HICON__*)

// LIBRARY: IMPERIALISM 0x006089ef SYMBOL
// ?OnNTCtlColor@CWnd@@IAEJIJ@Z
// name: CWnd::OnNTCtlColor
// prototype: protected: long __thiscall CWnd::OnNTCtlColor(unsigned int, long)

// LIBRARY: IMPERIALISM 0x00608a2b SYMBOL
// ?WinHelpA@CWnd@@UAEXKI@Z
// name: CWnd::WinHelpA
// prototype: public: virtual void __thiscall CWnd::WinHelpA(unsigned long,unsigned int)

// LIBRARY: IMPERIALISM 0x00608b11 SYMBOL
// ?AfxFindMessageEntry@@YGPBUAFX_MSGMAP_ENTRY@@PBU1@III@Z
// name: AfxFindMessageEntry
// prototype: AFX_MSGMAP_ENTRY * __stdcall ?AfxFindMessageEntry@@YGPBUAFX_MSGMAP_ENTRY@@PBU1@III@Z@00608b11(AFX_MSGMAP_ENTRY * param_1, uint param_2, uint param_3, uint param_4)

// LIBRARY: IMPERIALISM 0x00608b66 SYMBOL
// ?WindowProc@CWnd@@MAEJIIJ@Z
// name: CWnd::WindowProc
// prototype: protected: virtual long __thiscall CWnd::WindowProc(unsigned int, unsigned int, long)

// LIBRARY: IMPERIALISM 0x00608ba8 SYMBOL
// ?OnWndMsg@CWnd@@MAEHIIJPAJ@Z

// LIBRARY: IMPERIALISM 0x0060911a SYMBOL
// ??0CTestCmdUI@@QAE@XZ
// name: CTestCmdUI::CTestCmdUI
// prototype: public: __thiscall CTestCmdUI::CTestCmdUI(void)

// LIBRARY: IMPERIALISM 0x0060914d SYMBOL
// ?OnCommand@CWnd@@MAEHIJ@Z
// name: CWnd::OnCommand
// prototype: protected: virtual int __thiscall CWnd::OnCommand(unsigned int, long)

// LIBRARY: IMPERIALISM 0x006091d9 SYMBOL
// ?OnNotify@CWnd@@MAEHIJPAJ@Z
// name: CWnd::OnNotify
// prototype: protected: virtual int __thiscall CWnd::OnNotify(unsigned int,long,long *)

// LIBRARY: IMPERIALISM 0x00609253 SYMBOL
// ?GetParentFrame@CWnd@@QBEPAVCFrameWnd@@XZ
// name: CWnd::GetParentFrame
// prototype: public: class CFrameWnd * __thiscall CWnd::GetParentFrame(void) const

// LIBRARY: IMPERIALISM 0x00609297 SYMBOL
// ?AfxGetParentOwner@@YGPAUHWND__@@PAU1@@Z
// name: AfxGetParentOwner
// prototype: HWND__ * __stdcall ?AfxGetParentOwner@@YGPAUHWND__@@PAU1@@Z@00609297(HWND__ * param_1)

// LIBRARY: IMPERIALISM 0x006092dc SYMBOL
// ?GetTopLevelParent@CWnd@@QBEPAV1@XZ
// name: CWnd::GetTopLevelParent
// prototype: public: class CWnd * __thiscall CWnd::GetTopLevelParent(void) const

// LIBRARY: IMPERIALISM 0x0060933b SYMBOL
// ?GetParentOwner@CWnd@@QBEPAV1@XZ
// name: CWnd::GetParentOwner
// prototype: public: class CWnd * __thiscall CWnd::GetParentOwner(void) const

// LIBRARY: IMPERIALISM 0x00609382 SYMBOL
// ?IsTopParentActive@CWnd@@QBEHXZ
// name: CWnd::IsTopParentActive
// prototype: public: int __thiscall CWnd::IsTopParentActive(void) const

// LIBRARY: IMPERIALISM 0x006093b6 SYMBOL
// ?ActivateTopParent@CWnd@@QAEXXZ

// LIBRARY: IMPERIALISM 0x006093f3 SYMBOL
// ?GetTopLevelFrame@CWnd@@QBEPAVCFrameWnd@@XZ
// name: CWnd::GetTopLevelFrame
// prototype: public: class CFrameWnd * __thiscall CWnd::GetTopLevelFrame(void) const

// LIBRARY: IMPERIALISM 0x00609437 SYMBOL
// ?GetSafeOwner@CWnd@@SGPAV1@PAV1@PAPAUHWND__@@@Z
// name: CWnd::GetSafeOwner
// prototype: public: static class CWnd * __stdcall CWnd::GetSafeOwner(class CWnd *, struct HWND__**)

// LIBRARY: IMPERIALISM 0x006094d7 SYMBOL
// ?GetDescendantWindow@CWnd@@SGPAV1@PAUHWND__@@HH@Z
// name: CWnd::GetDescendantWindow
// prototype: public: static class CWnd * __stdcall CWnd::GetDescendantWindow(struct HWND__*, int, int)

// LIBRARY: IMPERIALISM 0x00609550 SYMBOL
// ?SendMessageToDescendants@CWnd@@SGXPAUHWND__@@IIJHH@Z
// name: CWnd::SendMessageToDescendants
// prototype: public: static void __stdcall CWnd::SendMessageToDescendants(struct HWND__*, unsigned int, unsigned int, long, int, int)

// LIBRARY: IMPERIALISM 0x006095cd SYMBOL
// ?GetScrollBarCtrl@CWnd@@UBEPAVCScrollBar@@H@Z
// name: CWnd::GetScrollBarCtrl
// prototype: public: virtual class CScrollBar * __thiscall CWnd::GetScrollBarCtrl(int)const

// LIBRARY: IMPERIALISM 0x006095d2 SYMBOL
// ?SetScrollPos@CWnd@@QAEHHHH@Z
// name: CWnd::SetScrollPos
// prototype: public: int __thiscall CWnd::SetScrollPos(int, int, int)

// LIBRARY: IMPERIALISM 0x00609602 SYMBOL
// ?GetScrollPos@CWnd@@QBEHH@Z
// name: CWnd::GetScrollPos
// prototype: public: int __thiscall CWnd::GetScrollPos(int) const

// LIBRARY: IMPERIALISM 0x0060962a SYMBOL
// ?SetScrollRange@CWnd@@QAEXHHHH@Z
// name: CWnd::SetScrollRange
// prototype: public: void __thiscall CWnd::SetScrollRange(int, int, int, int)

// LIBRARY: IMPERIALISM 0x0060965d SYMBOL
// ?GetScrollRange@CWnd@@QBEXHPAH0@Z
// name: CWnd::GetScrollRange
// prototype: public: void __thiscall CWnd::GetScrollRange(int, int *, int *) const

// LIBRARY: IMPERIALISM 0x0060968d SYMBOL
// ?EnableScrollBarCtrl@CWnd@@QAEXHH@Z
// name: CWnd::EnableScrollBarCtrl
// prototype: public: void __thiscall CWnd::EnableScrollBarCtrl(int, int)

// LIBRARY: IMPERIALISM 0x006096d0 SYMBOL
// ?SetScrollInfo@CWnd@@QAEHHPAUtagSCROLLINFO@@H@Z
// name: CWnd::SetScrollInfo
// prototype: public: int __thiscall CWnd::SetScrollInfo(int, struct tagSCROLLINFO *, int)

// LIBRARY: IMPERIALISM 0x0060971d SYMBOL
// ?GetScrollInfo@CWnd@@QAEHHPAUtagSCROLLINFO@@I@Z
// name: CWnd::GetScrollInfo
// prototype: public: int __thiscall CWnd::GetScrollInfo(int, struct tagSCROLLINFO *, unsigned int)

// LIBRARY: IMPERIALISM 0x0060976a SYMBOL
// ?GetScrollLimit@CWnd@@QAEHH@Z
// name: CWnd::GetScrollLimit
// prototype: public: int __thiscall CWnd::GetScrollLimit(int)

// LIBRARY: IMPERIALISM 0x006097ae SYMBOL
// ?ScrollWindow@CWnd@@QAEXHHPBUtagRECT@@0@Z
// name: CWnd::ScrollWindow
// prototype: public: void __thiscall CWnd::ScrollWindow(int, int, struct tagRECT const *, struct tagRECT const *)

// LIBRARY: IMPERIALISM 0x0060986b SYMBOL
// ?RepositionBars@CWnd@@QAEXIIIIPAUtagRECT@@PBU2@H@Z
// name: CWnd::RepositionBars
// prototype: public: void __thiscall CWnd::RepositionBars(unsigned int, unsigned int, unsigned int, unsigned int, struct tagRECT *, struct tagRECT const *, int)

// LIBRARY: IMPERIALISM 0x006099a5 SYMBOL
// ?AfxRepositionWindow@@YGXPAUAFX_SIZEPARENTPARAMS@@PAUHWND__@@PBUtagRECT@@@Z
// name: AfxRepositionWindow
// prototype: void __stdcall AfxRepositionWindow(struct AFX_SIZEPARENTPARAMS *, struct HWND__*, struct tagRECT const *)

// LIBRARY: IMPERIALISM 0x00609a3f SYMBOL
// ?CalcWindowRect@CWnd@@UAEXPAUtagRECT@@I@Z
// name: CWnd::CalcWindowRect
// prototype: public: virtual void __thiscall CWnd::CalcWindowRect(struct tagRECT *, unsigned int)

// LIBRARY: IMPERIALISM 0x00609a6a SYMBOL
// ?HandleFloatingSysCommand@CWnd@@QAEHIJ@Z
// name: CWnd::HandleFloatingSysCommand
// prototype: public: int __thiscall CWnd::HandleFloatingSysCommand(unsigned int, long)

// LIBRARY: IMPERIALISM 0x00609b24 SYMBOL
// ?WalkPreTranslateTree@CWnd@@SGHPAUHWND__@@PAUtagMSG@@@Z
// name: CWnd::WalkPreTranslateTree
// prototype: public: static int __stdcall CWnd::WalkPreTranslateTree(struct HWND__*, struct tagMSG *)

// LIBRARY: IMPERIALISM 0x00609b66 SYMBOL
// ?SendChildNotifyLastMsg@CWnd@@QAEHPAJ@Z
// name: CWnd::SendChildNotifyLastMsg
// prototype: public: int __thiscall CWnd::SendChildNotifyLastMsg(long *)

// LIBRARY: IMPERIALISM 0x00609b93 SYMBOL
// ?ReflectLastMsg@CWnd@@KGHPAUHWND__@@PAJ@Z
// name: CWnd::ReflectLastMsg
// prototype: protected: static int __stdcall CWnd::ReflectLastMsg(struct HWND__*, long *)

// LIBRARY: IMPERIALISM 0x00609c37 SYMBOL
// ?OnChildNotify@CWnd@@MAEHIIJPAJ@Z
// name: CWnd::OnChildNotify
// prototype: protected: virtual int __thiscall CWnd::OnChildNotify(unsigned int, unsigned int, long, long *)

// LIBRARY: IMPERIALISM 0x00609c92 SYMBOL
// ?ReflectChildNotify@CWnd@@IAEHIIJPAJ@Z
// name: CWnd::ReflectChildNotify
// prototype: protected: int __thiscall CWnd::ReflectChildNotify(unsigned int, unsigned int, long, long *)

// LIBRARY: IMPERIALISM 0x00609d88 SYMBOL
// ?OnParentNotify@CWnd@@IAEXIJ@Z

// LIBRARY: IMPERIALISM 0x00609dd7 SYMBOL
// ?OnSysColorChange@CWnd@@IAEXXZ
// name: CWnd::OnSysColorChange
// prototype: protected: void __thiscall CWnd::OnSysColorChange(void)

// LIBRARY: IMPERIALISM 0x00609e61 SYMBOL
// ?OnSettingChange@CWnd@@IAEXIPBD@Z
// name: CWnd::OnSettingChange
// prototype: protected: void __thiscall CWnd::OnSettingChange(unsigned int, char const *)

// LIBRARY: IMPERIALISM 0x00609eb5 SYMBOL
// ?OnWinIniChange@CWnd@@IAEXPBD@Z
// name: CWnd::OnWinIniChange
// prototype: protected: void __thiscall CWnd::OnWinIniChange(char const *)

// LIBRARY: IMPERIALISM 0x00609f01 SYMBOL
// ?OnDevModeChange@CWnd@@IAEXPAD@Z
// name: CWnd::OnDevModeChange
// prototype: protected: void __thiscall CWnd::OnDevModeChange(char *)

// LIBRARY: IMPERIALISM 0x00609f56 SYMBOL
// ?OnHelpInfo@CWnd@@IAEHPAUtagHELPINFO@@@Z
// name: CWnd::OnHelpInfo
// prototype: protected: int __thiscall CWnd::OnHelpInfo(struct tagHELPINFO *)

// LIBRARY: IMPERIALISM 0x00609fba SYMBOL
// ?OnDisplayChange@CWnd@@IAEJIJ@Z

// LIBRARY: IMPERIALISM 0x0060a007 SYMBOL
// ?OnDragList@CWnd@@IAEJIJ@Z
// name: CWnd::OnDragList
// prototype: protected: long __thiscall CWnd::OnDragList(unsigned int, long)

// LIBRARY: IMPERIALISM 0x0060a031 SYMBOL
// ?OnVScroll@CWnd@@IAEXIIPAVCScrollBar@@@Z

// LIBRARY: IMPERIALISM 0x0060a052 SYMBOL
// ?OnVScroll@CWnd@@IAEXIIPAVCScrollBar@@@Z

// LIBRARY: IMPERIALISM 0x0060a073 SYMBOL
// ?OnEnterIdle@CWnd@@IAEXIPAV1@@Z
// name: CWnd::OnEnterIdle
// prototype: protected: void __thiscall CWnd::OnEnterIdle(unsigned int, class CWnd *)

// LIBRARY: IMPERIALISM 0x0060a0bd SYMBOL
// ?OnCtlColor@CWnd@@IAEPAUHBRUSH__@@PAVCDC@@PAV1@I@Z
// name: CWnd::OnCtlColor
// prototype: protected: struct HBRUSH__* __thiscall CWnd::OnCtlColor(class CDC *, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x0060a0e4 SYMBOL
// ?OnGrayCtlColor@CWnd@@QAEPAUHBRUSH__@@PAVCDC@@PAV1@I@Z
// name: CWnd::OnGrayCtlColor
// prototype: public: struct HBRUSH__* __thiscall CWnd::OnGrayCtlColor(class CDC *, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x0060a147 SYMBOL
// ?GrayCtlColor@CWnd@@SGHPAUHDC__@@PAUHWND__@@IPAUHBRUSH__@@K@Z
// name: CWnd::GrayCtlColor
// prototype: public: static int __stdcall CWnd::GrayCtlColor(struct HDC__*, struct HWND__*, unsigned int, struct HBRUSH__*, unsigned long)

// LIBRARY: IMPERIALISM 0x0060a1bc
// MFC nafxcw handler in CDialog's message map 0x66fb20, MFC-internal
// message 0x36f: `mov eax,0xffff; ret 8`.

// LIBRARY: IMPERIALISM 0x0060a1c4 SYMBOL
// ?UpdateData@CWnd@@QAEHH@Z
// name: CWnd::UpdateData
// prototype: public: int __thiscall CWnd::UpdateData(int)

// LIBRARY: IMPERIALISM 0x0060a267 SYMBOL
// ??0CDataExchange@@QAE@PAVCWnd@@H@Z
// name: CDataExchange::CDataExchange
// prototype: public: __thiscall CDataExchange::CDataExchange(class CWnd *, int)

// LIBRARY: IMPERIALISM 0x0060a27d SYMBOL
// ?CenterWindow@CWnd@@QAEXPAV1@@Z
// name: CWnd::CenterWindow
// prototype: public: void __thiscall CWnd::CenterWindow(class CWnd *)

// LIBRARY: IMPERIALISM 0x0060a3f7 SYMBOL
// ?CheckAutoCenter@CWnd@@UAEHXZ
// name: CWnd::CheckAutoCenter
// prototype: public: virtual int __thiscall CWnd::CheckAutoCenter(void)

// LIBRARY: IMPERIALISM 0x0060a3fb SYMBOL
// ?ExecuteDlgInit@CWnd@@QAEHPBD@Z
// name: CWnd::ExecuteDlgInit
// prototype: public: int __thiscall CWnd::ExecuteDlgInit(char const *)

// LIBRARY: IMPERIALISM 0x0060a44b SYMBOL
// ?ExecuteDlgInit@CWnd@@QAEHPAX@Z
// name: CWnd::ExecuteDlgInit
// prototype: public: int __thiscall CWnd::ExecuteDlgInit(void *)

// LIBRARY: IMPERIALISM 0x0060a4d5 SYMBOL
// ?UpdateDialogControls@CWnd@@QAEXPAVCCmdTarget@@H@Z
// name: CWnd::UpdateDialogControls
// prototype: public: void __thiscall CWnd::UpdateDialogControls(class CCmdTarget *, int)

// LIBRARY: IMPERIALISM 0x0060a5da SYMBOL
// ?PreTranslateInput@CWnd@@QAEHPAUtagMSG@@@Z
// name: CWnd::PreTranslateInput
// prototype: public: int __thiscall CWnd::PreTranslateInput(struct tagMSG *)

// LIBRARY: IMPERIALISM 0x0060a60a SYMBOL
// ?RunModalLoop@CWnd@@QAEHK@Z
// name: CWnd::RunModalLoop
// prototype: public: int __thiscall CWnd::RunModalLoop(unsigned long)

// LIBRARY: IMPERIALISM 0x0060a769 SYMBOL
// ?ContinueModal@CWnd@@UAEHXZ
// name: CWnd::ContinueModal
// prototype: public: virtual int __thiscall CWnd::ContinueModal(void)

// LIBRARY: IMPERIALISM 0x0060a770 SYMBOL
// ?EndModalLoop@CWnd@@UAEXH@Z
// name: CWnd::EndModalLoop
// prototype: public: virtual void __thiscall CWnd::EndModalLoop(int)

// LIBRARY: IMPERIALISM 0x0060a794 SYMBOL
// ?AfxEndDeferRegisterClass@@YGHF@Z
// name: AfxEndDeferRegisterClass
// prototype: int __stdcall AfxEndDeferRegisterClass(short)

// LIBRARY: IMPERIALISM 0x0060a8ce
// AfxRegisterWithIcon

// LIBRARY: IMPERIALISM 0x0060a90f SYMBOL
// ?IsFrameWnd@CWnd@@UBEHXZ
// name: CWnd::IsFrameWnd
// prototype: public: virtual int __thiscall CWnd::IsFrameWnd(void)const

// LIBRARY: IMPERIALISM 0x0060a912 SYMBOL
// ?IsFrameWnd@CFrameWnd@@UBEHXZ
// name: CFrameWnd::IsFrameWnd
// prototype: public: virtual int __thiscall CFrameWnd::IsFrameWnd(void)const

// LIBRARY: IMPERIALISM 0x0060a916 SYMBOL
// ?IsTracking@CFrameWnd@@QBEHXZ
// name: CFrameWnd::IsTracking
// prototype: public: int __thiscall CFrameWnd::IsTracking(void) const

// LIBRARY: IMPERIALISM 0x0060a935 SYMBOL
// ?SubclassCtl3d@CWnd@@QAEHH@Z
// name: CWnd::SubclassCtl3d
// prototype: public: int __thiscall CWnd::SubclassCtl3d(int)

// LIBRARY: IMPERIALISM 0x0060a97f SYMBOL
// ?SubclassDlg3d@CWnd@@QAEHK@Z
// name: CWnd::SubclassDlg3d
// prototype: public: int __thiscall CWnd::SubclassDlg3d(unsigned long)

// LIBRARY: IMPERIALISM 0x0060a9c4 SYMBOL
// ?SubclassWindow@CWnd@@QAEHPAUHWND__@@@Z
// name: CWnd::SubclassWindow
// prototype: public: int __thiscall CWnd::SubclassWindow(struct HWND__*)

// LIBRARY: IMPERIALISM 0x0060aa6e SYMBOL
// ?UnsubclassWindow@CWnd@@QAEPAUHWND__@@XZ
// name: CWnd::UnsubclassWindow
// prototype: public: struct HWND__* __thiscall CWnd::UnsubclassWindow(void)

// LIBRARY: IMPERIALISM 0x0060aa96 SYMBOL
// ??0CException@@QAE@XZ
// name: CException::CException
// prototype: public: __thiscall CException::CException(void)

// LIBRARY: IMPERIALISM 0x0060aaa6 SYMBOL
// ??0CException@@QAE@H@Z
// name: CException::CException
// prototype: public: __thiscall CException::CException(int)

// LIBRARY: IMPERIALISM 0x0060aab8 SYMBOL
// ?Delete@CException@@QAEXXZ
// name: CException::Delete
// prototype: public: void __thiscall CException::Delete(void)

// LIBRARY: IMPERIALISM 0x0060aaeb SYMBOL
// ?ReportError@CException@@UAEHII@Z
// name: CException::ReportError
// prototype: public: virtual int __thiscall CException::ReportError(unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x0060ab40 SYMBOL
// ??0AFX_EXCEPTION_LINK@@QAE@XZ
// name: AFX_EXCEPTION_LINK::AFX_EXCEPTION_LINK
// prototype: public: __thiscall AFX_EXCEPTION_LINK::AFX_EXCEPTION_LINK(void)

// LIBRARY: IMPERIALISM 0x0060ab56 SYMBOL
// ?AfxGetExceptionContext@@YAPAUAFX_EXCEPTION_CONTEXT@@XZ
// name: AfxGetExceptionContext
// prototype: struct AFX_EXCEPTION_CONTEXT * __cdecl AfxGetExceptionContext(void)

// LIBRARY: IMPERIALISM 0x0060ab7e SYMBOL
// ?AfxTryCleanup@@YGXXZ
// name: AfxTryCleanup
// prototype: void __stdcall AfxTryCleanup(void)

// LIBRARY: IMPERIALISM 0x0060abac SYMBOL
// ??0CFile@@QAE@XZ
// name: CFile::CFile
// prototype: public: __thiscall CFile::CFile(void)

// LIBRARY: IMPERIALISM 0x0060abec SYMBOL
// ??_GCFile@@UAEPAXI@Z
// name: CFile::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CFile::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0060ac08 SYMBOL
// ??0CFile@@QAE@H@Z
// name: CFile::CFile
// prototype: public: __thiscall CFile::CFile(int)

// LIBRARY: IMPERIALISM 0x0060ac4c SYMBOL
// ??0CFile@@QAE@PBDI@Z
// name: CFile::CFile
// prototype: public: __thiscall CFile::CFile(char const *, unsigned int)

// LIBRARY: IMPERIALISM 0x0060acf6 SYMBOL
// ??1CFile@@UAE@XZ
// name: CFile::~CFile
// prototype: public: virtual __thiscall CFile::~CFile(void)

// LIBRARY: IMPERIALISM 0x0060ad44 SYMBOL
// ?Duplicate@CFile@@UBEPAV1@XZ
// name: CFile::Duplicate
// prototype: public: virtual class CFile * __thiscall CFile::Duplicate(void) const

// LIBRARY: IMPERIALISM 0x0060add5 SYMBOL
// ?Open@CFile@@UAEHPBDIPAVCFileException@@@Z
// name: CFile::Open
// prototype: public: virtual int __thiscall CFile::Open(char const *, unsigned int, class CFileException *)

// LIBRARY: IMPERIALISM 0x0060aefd SYMBOL
// ?Read@CFile@@UAEIPAXI@Z
// name: CFile::Read
// prototype: public: virtual unsigned int __thiscall CFile::Read(void *, unsigned int)

// LIBRARY: IMPERIALISM 0x0060af37 SYMBOL
// ?Write@CFile@@UAEXPBXI@Z
// name: CFile::Write
// prototype: public: virtual void __thiscall CFile::Write(void const *, unsigned int)

// LIBRARY: IMPERIALISM 0x0060af82 SYMBOL
// ?Seek@CFile@@UAEJJI@Z
// name: CFile::Seek
// prototype: public: virtual long __thiscall CFile::Seek(long, unsigned int)

// LIBRARY: IMPERIALISM 0x0060afb1 SYMBOL
// ?GetPosition@CFile@@UBEKXZ
// name: CFile::GetPosition
// prototype: public: virtual unsigned long __thiscall CFile::GetPosition(void) const

// LIBRARY: IMPERIALISM 0x0060afda SYMBOL
// ?Flush@CFile@@UAEXXZ
// name: CFile::Flush
// prototype: public: virtual void __thiscall CFile::Flush(void)

// LIBRARY: IMPERIALISM 0x0060affb SYMBOL
// ?Close@CFile@@UAEXXZ
// name: CFile::Close
// prototype: public: virtual void __thiscall CFile::Close(void)

// LIBRARY: IMPERIALISM 0x0060b03c SYMBOL
// ?Abort@CFile@@UAEXXZ
// name: CFile::Abort
// prototype: public: virtual void __thiscall CFile::Abort(void)

// LIBRARY: IMPERIALISM 0x0060b05c SYMBOL
// ?LockRange@CFile@@UAEXKK@Z

// LIBRARY: IMPERIALISM 0x0060b085 SYMBOL
// ?LockRange@CFile@@UAEXKK@Z

// LIBRARY: IMPERIALISM 0x0060b0ae SYMBOL
// ?SetLength@CFile@@UAEXK@Z
// name: CFile::SetLength
// prototype: public: virtual void __thiscall CFile::SetLength(unsigned long)

// LIBRARY: IMPERIALISM 0x0060b0da SYMBOL
// ?GetLength@CFile@@UBEKXZ
// name: CFile::GetLength
// prototype: public: virtual unsigned long __thiscall CFile::GetLength(void) const

// LIBRARY: IMPERIALISM 0x0060b10a SYMBOL
// ?Rename@CFile@@SGXPBD0@Z
// name: CFile::Rename
// prototype: public: static void __stdcall CFile::Rename(char const *, char const *)

// LIBRARY: IMPERIALISM 0x0060b12c SYMBOL
// ?Remove@CFile@@SGXPBD@Z
// name: CFile::Remove
// prototype: public: static void __stdcall CFile::Remove(char const *)

// LIBRARY: IMPERIALISM 0x0060b14a SYMBOL
// ??1AFX_COM@@QAE@XZ
// name: AFX_COM::~AFX_COM
// prototype: public: __thiscall AFX_COM::~AFX_COM(void)

// LIBRARY: IMPERIALISM 0x0060b158 SYMBOL
// ?CreateInstance@AFX_COM@@QAEJABU_GUID@@PAUIUnknown@@0PAPAX@Z
// name: AFX_COM::CreateInstance
// prototype: public: long __thiscall AFX_COM::CreateInstance(struct _GUID const &, struct IUnknown *, struct _GUID const &, void **)

// LIBRARY: IMPERIALISM 0x0060b19a SYMBOL
// ?GetClassObject@AFX_COM@@QAEJABU_GUID@@0PAPAX@Z
// name: AFX_COM::GetClassObject
// prototype: public: long __thiscall AFX_COM::GetClassObject(struct _GUID const &, struct _GUID const &, void **)

// LIBRARY: IMPERIALISM 0x0060b266 SYMBOL
// ?AfxStringFromCLSID@@YG?AVCString@@ABU_GUID@@@Z
// name: AfxStringFromCLSID
// prototype: class CString __stdcall AfxStringFromCLSID(struct _GUID const &)

// LIBRARY: IMPERIALISM 0x0060b2d5 SYMBOL
// ?AfxGetInProcServer@@YGHPBDAAVCString@@@Z
// name: AfxGetInProcServer
// prototype: int __stdcall AfxGetInProcServer(char const *, class CString &)

// LIBRARY: IMPERIALISM 0x0060b381 SYMBOL
// ?AfxResolveShortcut@@YGHPAVCWnd@@PBDPADH@Z
// name: AfxResolveShortcut
// prototype: int __stdcall AfxResolveShortcut(class CWnd *, char const *, char *, int)

// LIBRARY: IMPERIALISM 0x0060b4cb SYMBOL
// ?AfxFullPath@@YGHPADPBD@Z
// name: AfxFullPath
// prototype: int __stdcall AfxFullPath(char *, char const *)

// LIBRARY: IMPERIALISM 0x0060b5a4 SYMBOL
// ?AfxGetRoot@@YGXPBDAAVCString@@@Z
// name: AfxGetRoot
// prototype: void __stdcall AfxGetRoot(char const *, class CString &)

// LIBRARY: IMPERIALISM 0x0060b66a SYMBOL
// ?AfxComparePath@@YGHPBD0@Z
// name: AfxComparePath
// prototype: int __stdcall AfxComparePath(char const *, char const *)

// LIBRARY: IMPERIALISM 0x0060b72d SYMBOL
// ?AfxGetFileTitle@@YGIPBDPADI@Z
// name: AfxGetFileTitle
// prototype: unsigned int __stdcall AfxGetFileTitle(char const *, char *, unsigned int)

// LIBRARY: IMPERIALISM 0x0060b783 SYMBOL
// ?AfxGetModuleShortFileName@@YGXPAUHINSTANCE__@@AAVCString@@@Z
// name: AfxGetModuleShortFileName
// prototype: void __stdcall AfxGetModuleShortFileName(struct HINSTANCE__*, class CString &)

// LIBRARY: IMPERIALISM 0x0060b7dd SYMBOL
// ?GetFileName@CFile@@UBE?AVCString@@XZ
// name: CFile::GetFileName
// prototype: public: virtual class CString __thiscall CFile::GetFileName(void) const

// LIBRARY: IMPERIALISM 0x0060b85f SYMBOL
// ?GetFileTitle@CFile@@UBE?AVCString@@XZ
// name: CFile::GetFileTitle
// prototype: public: virtual class CString __thiscall CFile::GetFileTitle(void) const

// LIBRARY: IMPERIALISM 0x0060b8e1 SYMBOL
// ?GetFilePath@CFile@@UBE?AVCString@@XZ
// name: CFile::GetFilePath
// prototype: public: virtual class CString __thiscall CFile::GetFilePath(void) const

// LIBRARY: IMPERIALISM 0x0060b910 SYMBOL
// ?GetStatus@CFile@@QBEHAAUCFileStatus@@@Z
// name: CFile::GetStatus
// prototype: public: int __thiscall CFile::GetStatus(struct CFileStatus &) const

// LIBRARY: IMPERIALISM 0x0060b9ea SYMBOL
// ?GetStatus@CFile@@SGHPBDAAUCFileStatus@@@Z
// name: CFile::GetStatus
// prototype: public: static int __stdcall CFile::GetStatus(char const *, struct CFileStatus &)

// LIBRARY: IMPERIALISM 0x0060ba9c SYMBOL
// ?AfxTimeToFileTime@@YAXABVCTime@@PAU_FILETIME@@@Z
// name: AfxTimeToFileTime
// prototype: void __cdecl AfxTimeToFileTime(class CTime const &, struct _FILETIME *)

// LIBRARY: IMPERIALISM 0x0060bb4b SYMBOL
// ?SetStatus@CFile@@SGXPBDABUCFileStatus@@@Z
// name: CFile::SetStatus
// prototype: public: static void __stdcall CFile::SetStatus(char const *, struct CFileStatus const &)

// LIBRARY: IMPERIALISM 0x0060bc98 SYMBOL
// ?ThrowOsError@CFileException@@SGXJPBD@Z
// name: CFileException::ThrowOsError
// prototype: public: static void __stdcall CFileException::ThrowOsError(long, char const *)

// LIBRARY: IMPERIALISM 0x0060bcdd SYMBOL
// ?GetErrorMessage@CFileException@@UAEHPADIPAI@Z
// name: CFileException::GetErrorMessage
// prototype: public: virtual int __thiscall CFileException::GetErrorMessage(char *, unsigned int, unsigned int *)

// LIBRARY: IMPERIALISM 0x0060bd7d SYMBOL
// ?AfxThrowFileException@@YGXHJPBD@Z
// name: AfxThrowFileException
// prototype: void __stdcall AfxThrowFileException(int, long, char const *)

// LIBRARY: IMPERIALISM 0x0060be52 SYMBOL
// ?OsErrorToException@CFileException@@SGHJ@Z

// LIBRARY: IMPERIALISM 0x0060c087 SYMBOL
// ??0CDialogTemplate@@QAE@PBUDLGTEMPLATE@@@Z
// name: CDialogTemplate::CDialogTemplate
// prototype: public: __thiscall CDialogTemplate::CDialogTemplate(struct DLGTEMPLATE const *)

// LIBRARY: IMPERIALISM 0x0060c0b6 SYMBOL
// ??0CDialogTemplate@@QAE@PAX@Z
// name: CDialogTemplate::CDialogTemplate
// prototype: public: __thiscall CDialogTemplate::CDialogTemplate(void *)

// LIBRARY: IMPERIALISM 0x0060c0f7 SYMBOL
// ?SetTemplate@CDialogTemplate@@IAEHPBUDLGTEMPLATE@@I@Z
// name: CDialogTemplate::SetTemplate
// prototype: protected: int __thiscall CDialogTemplate::SetTemplate(struct DLGTEMPLATE const *, unsigned int)

// LIBRARY: IMPERIALISM 0x0060c157 SYMBOL
// ??1CDialogTemplate@@QAE@XZ
// name: CDialogTemplate::~CDialogTemplate
// prototype: public: __thiscall CDialogTemplate::~CDialogTemplate(void)

// LIBRARY: IMPERIALISM 0x0060c165 SYMBOL
// ?Load@CDialogTemplate@@QAEHPBD@Z
// name: CDialogTemplate::Load
// prototype: public: int __thiscall CDialogTemplate::Load(char const *)

// LIBRARY: IMPERIALISM 0x0060c1ba SYMBOL
// ?Detach@CDialogTemplate@@QAEPAXXZ
// name: CDialogTemplate::Detach
// prototype: public: void * __thiscall CDialogTemplate::Detach(void)

// LIBRARY: IMPERIALISM 0x0060c1c0 SYMBOL
// ?HasFont@CDialogTemplate@@QBEHXZ
// name: CDialogTemplate::HasFont
// prototype: public: int __thiscall CDialogTemplate::HasFont(void) const

// LIBRARY: IMPERIALISM 0x0060c1eb SYMBOL
// ?GetFontSizeField@CDialogTemplate@@KAPAEPBUDLGTEMPLATE@@@Z
// name: CDialogTemplate::GetFontSizeField
// prototype: protected: static unsigned char * __cdecl CDialogTemplate::GetFontSizeField(struct DLGTEMPLATE const *)

// LIBRARY: IMPERIALISM 0x0060c241 SYMBOL
// ?GetTemplateSize@CDialogTemplate@@KAIPBUDLGTEMPLATE@@@Z
// name: CDialogTemplate::GetTemplateSize
// prototype: protected: static unsigned int __cdecl CDialogTemplate::GetTemplateSize(struct DLGTEMPLATE const *)

// LIBRARY: IMPERIALISM 0x0060c2f8 SYMBOL
// ?GetFont@CDialogTemplate@@SAHPBUDLGTEMPLATE@@AAVCString@@AAG@Z
// name: CDialogTemplate::GetFont
// prototype: public: static int __cdecl CDialogTemplate::GetFont(struct DLGTEMPLATE const *, class CString &, unsigned short &)

// LIBRARY: IMPERIALISM 0x0060c367 SYMBOL
// ?GetFont@CDialogTemplate@@QBEHAAVCString@@AAG@Z
// name: CDialogTemplate::GetFont
// prototype: public: int __thiscall CDialogTemplate::GetFont(class CString &, unsigned short &) const

// LIBRARY: IMPERIALISM 0x0060c395 SYMBOL
// ?SetFont@CDialogTemplate@@QAEHPBDG@Z
// name: CDialogTemplate::SetFont
// prototype: public: int __thiscall CDialogTemplate::SetFont(char const *, unsigned short)

// LIBRARY: IMPERIALISM 0x0060c4ac SYMBOL
// ?SetSystemFont@CDialogTemplate@@QAEHG@Z
// name: CDialogTemplate::SetSystemFont
// prototype: public: int __thiscall CDialogTemplate::SetSystemFont(unsigned short)

// LIBRARY: IMPERIALISM 0x0060c53d SYMBOL
// ?GetSizeInDialogUnits@CDialogTemplate@@QBEXPAUtagSIZE@@@Z
// name: CDialogTemplate::GetSizeInDialogUnits
// prototype: public: void __thiscall CDialogTemplate::GetSizeInDialogUnits(struct tagSIZE *) const

// LIBRARY: IMPERIALISM 0x0060c57d SYMBOL
// ?GetSizeInPixels@CDialogTemplate@@QBEXPAUtagSIZE@@@Z
// name: CDialogTemplate::GetSizeInPixels
// prototype: public: void __thiscall CDialogTemplate::GetSizeInPixels(struct tagSIZE *) const

// LIBRARY: IMPERIALISM 0x0060c622 SYMBOL
// ?ConvertDialogUnitsToPixels@@YAXPBDGHHPAUtagSIZE@@@Z

// LIBRARY: IMPERIALISM 0x0060c723 SYMBOL
// ??0CRecentFileList@@QAE@IPBD0HH@Z
// name: CRecentFileList::CRecentFileList
// prototype: public: __thiscall CRecentFileList::CRecentFileList(unsigned int, char const *, char const *, int, int)

// LIBRARY: IMPERIALISM 0x0060c7df SYMBOL
// ??_GCRecentFileList@@UAEPAXI@Z
// name: CRecentFileList::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CRecentFileList::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0060c7fb SYMBOL
// ??_ECString@@QAEPAXI@Z
// name: CString::`vector deleting dtor'
// prototype: public: void * __thiscall CString::`vector deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0060c837 SYMBOL
// ??1CRecentFileList@@UAE@XZ
// name: CRecentFileList::~CRecentFileList
// prototype: public: virtual __thiscall CRecentFileList::~CRecentFileList(void)

// LIBRARY: IMPERIALISM 0x0060c894 SYMBOL
// ?Add@CRecentFileList@@UAEXPBD@Z
// name: CRecentFileList::Add
// prototype: public: virtual void __thiscall CRecentFileList::Add(char const *)

// LIBRARY: IMPERIALISM 0x0060c900 SYMBOL
// ?Remove@CRecentFileList@@UAEXH@Z
// name: CRecentFileList::Remove
// prototype: public: virtual void __thiscall CRecentFileList::Remove(int)

// LIBRARY: IMPERIALISM 0x0060c93b SYMBOL
// ?GetDisplayName@CRecentFileList@@QBEHAAVCString@@HPBDHH@Z
// name: CRecentFileList::GetDisplayName
// prototype: public: int __thiscall CRecentFileList::GetDisplayName(class CString &, int, char const *, int, int) const

// LIBRARY: IMPERIALISM 0x0060ca44 SYMBOL
// ?UpdateMenu@CRecentFileList@@UAEXPAVCCmdUI@@@Z
// name: CRecentFileList::UpdateMenu
// prototype: public: virtual void __thiscall CRecentFileList::UpdateMenu(class CCmdUI *)

// LIBRARY: IMPERIALISM 0x0060cc8e SYMBOL
// ?WriteList@CRecentFileList@@UAEXXZ
// name: CRecentFileList::WriteList
// prototype: public: virtual void __thiscall CRecentFileList::WriteList(void)

// LIBRARY: IMPERIALISM 0x0060cd0c SYMBOL
// ?ReadList@CRecentFileList@@UAEXXZ
// name: CRecentFileList::ReadList
// prototype: public: virtual void __thiscall CRecentFileList::ReadList(void)

// LIBRARY: IMPERIALISM 0x0060cda8 SYMBOL
// ?AbbreviateName@@YAXPADHH@Z

// LIBRARY: IMPERIALISM 0x0060ce85 SYMBOL
// ?LoadStringA@CString@@QAEHI@Z
// name: CString::LoadStringA
// prototype: public: int __thiscall CString::LoadStringA(unsigned int)

// LIBRARY: IMPERIALISM 0x0060cf09 SYMBOL
// ?AfxLoadString@@YGHIPADI@Z
// name: AfxLoadString
// prototype: int __stdcall AfxLoadString(unsigned int, char *, unsigned int)

// LIBRARY: IMPERIALISM 0x0060cf30 SYMBOL
// ?AfxExtractSubString@@YGHAAVCString@@PBDHD@Z
// name: AfxExtractSubString
// prototype: int __stdcall AfxExtractSubString(class CString &, char const *, int, char)

// LIBRARY: IMPERIALISM 0x0060cfa8 SYMBOL
// ?UpdateSysColors@AUX_DATA@@QAEXXZ
// name: AUX_DATA::UpdateSysColors
// prototype: public: void __thiscall AUX_DATA::UpdateSysColors(void)

// LIBRARY: IMPERIALISM 0x0060cfec SYMBOL
// ?UpdateSysMetrics@AUX_DATA@@QAEXXZ
// name: AUX_DATA::UpdateSysMetrics
// prototype: public: void __thiscall AUX_DATA::UpdateSysMetrics(void)

// LIBRARY: IMPERIALISM 0x0060d044 SYMBOL
// ?DeleteTempMap@CMenu@@SGXXZ

// LIBRARY: IMPERIALISM 0x0060d058
// afxMapHMENU_60d058

// LIBRARY: IMPERIALISM 0x0060d0c8 SYMBOL
// ?FromHandle@CMenu@@SGPAV1@PAUHMENU__@@@Z
// name: CMenu::FromHandle
// prototype: public: static class CMenu * __stdcall CMenu::FromHandle(struct HMENU__*)

// LIBRARY: IMPERIALISM 0x0060d0de SYMBOL
// ?FromHandlePermanent@CMenu@@SGPAV1@PAUHMENU__@@@Z
// name: CMenu::FromHandlePermanent
// prototype: public: static class CMenu * __stdcall CMenu::FromHandlePermanent(struct HMENU__*)

// LIBRARY: IMPERIALISM 0x0060d127 SYMBOL
// ?Detach@CGdiObject@@QAEPAXXZ
// name: CGdiObject::Detach
// prototype: public: void * __thiscall CGdiObject::Detach(void)

// LIBRARY: IMPERIALISM 0x0060d151
// CMenu::DeleteObject

// LIBRARY: IMPERIALISM 0x0060d16d SYMBOL
// ?AfxLockTempMaps@@YGXXZ
// name: AfxLockTempMaps
// prototype: void __stdcall AfxLockTempMaps(void)

// LIBRARY: IMPERIALISM 0x0060d176 SYMBOL
// ?AfxUnlockTempMaps@@YGHH@Z
// name: AfxUnlockTempMaps
// prototype: int __stdcall AfxUnlockTempMaps(int)

// LIBRARY: IMPERIALISM 0x0060d264 SYMBOL
// ??0CHandleMap@@QAE@PAUCRuntimeClass@@IH@Z
// name: CHandleMap::CHandleMap
// prototype: public: __thiscall CHandleMap::CHandleMap(struct CRuntimeClass *, unsigned int, int)

// LIBRARY: IMPERIALISM 0x0060d2c0 SYMBOL
// ?FromHandle@CHandleMap@@QAEPAVCObject@@PAX@Z

// LIBRARY: IMPERIALISM 0x0060d39b SYMBOL
// ?DeleteTemp@CHandleMap@@QAEXXZ
// name: CHandleMap::DeleteTemp
// prototype: public: void __thiscall CHandleMap::DeleteTemp(void)

// LIBRARY: IMPERIALISM 0x0060d3fc SYMBOL
// ?AfxWinMain@@YGHPAUHINSTANCE__@@0PADH@Z
// name: AfxWinMain
// prototype: int __stdcall AfxWinMain(struct HINSTANCE__*, struct HINSTANCE__*, char *, int)

// LIBRARY: IMPERIALISM 0x0061069f
// MFC nafxcw handler in message map 0x66fd60 (base 0x670560 = CCmdTarget),
// ON_COMMAND 0xe141: SendMessage(m_hWnd, WM_CLOSE) forwarder.

// LIBRARY: IMPERIALISM 0x006106bd SYMBOL
// ??0CSingleDocTemplate@@QAE@IPAUCRuntimeClass@@00@Z
// name: CSingleDocTemplate::CSingleDocTemplate
// prototype: public: __thiscall CSingleDocTemplate::CSingleDocTemplate(unsigned int, struct CRuntimeClass *, struct CRuntimeClass *, struct CRuntimeClass *)

// LIBRARY: IMPERIALISM 0x006106e5 SYMBOL
// ??_GCSingleDocTemplate@@UAEPAXI@Z
// name: CSingleDocTemplate::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CSingleDocTemplate::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00610701 SYMBOL
// ??1CSingleDocTemplate@@UAE@XZ
// name: CSingleDocTemplate::~CSingleDocTemplate
// prototype: public: virtual __thiscall CSingleDocTemplate::~CSingleDocTemplate(void)

// LIBRARY: IMPERIALISM 0x00610728 SYMBOL
// ?AddDocument@CSingleDocTemplate@@UAEXPAVCDocument@@@Z
// name: CSingleDocTemplate::AddDocument
// prototype: public: virtual void __thiscall CSingleDocTemplate::AddDocument(class CDocument *)

// LIBRARY: IMPERIALISM 0x0061073e SYMBOL
// ?RemoveDocument@CSingleDocTemplate@@UAEXPAVCDocument@@@Z
// name: CSingleDocTemplate::RemoveDocument
// prototype: public: virtual void __thiscall CSingleDocTemplate::RemoveDocument(class CDocument *)

// LIBRARY: IMPERIALISM 0x00610752 SYMBOL
// ?OpenDocumentFile@CSingleDocTemplate@@UAEPAVCDocument@@PBDH@Z
// name: CSingleDocTemplate::OpenDocumentFile
// prototype: public: virtual class CDocument * __thiscall CSingleDocTemplate::OpenDocumentFile(char const *, int)

// LIBRARY: IMPERIALISM 0x006108fe SYMBOL
// ?SetDefaultTitle@CSingleDocTemplate@@UAEXPAVCDocument@@@Z
// name: CSingleDocTemplate::SetDefaultTitle
// prototype: public: virtual void __thiscall CSingleDocTemplate::SetDefaultTitle(class CDocument *)

// LIBRARY: IMPERIALISM 0x00610965 SYMBOL
// ?GetMessageMap@CDocument@@MBEPBUAFX_MSGMAP@@XZ
// name: CDocument::GetMessageMap
// prototype: protected: virtual struct AFX_MSGMAP const * __thiscall CDocument::GetMessageMap(void) const

// LIBRARY: IMPERIALISM 0x0061096b SYMBOL
// ??0CDocument@@QAE@XZ
// name: CDocument::CDocument
// prototype: public: __thiscall CDocument::CDocument(void)

// SYNTHETIC: IMPERIALISM 0x006109cf
// ownership-only

// LIBRARY: IMPERIALISM 0x006109eb SYMBOL
// ??1CDocument@@UAE@XZ
// name: CDocument::DestructCDocumentBaseState

// LIBRARY: IMPERIALISM 0x00610a57 SYMBOL
// ?OnFinalRelease@CDocument@@UAEXXZ
// name: CDocument::OnFinalRelease
// prototype: public: virtual void __thiscall CDocument::OnFinalRelease(void)

// LIBRARY: IMPERIALISM 0x00610a5f SYMBOL
// ?DisconnectViews@CDocument@@QAEXXZ
// name: CDocument::DisconnectViews
// prototype: public: void __thiscall CDocument::DisconnectViews(void)

// LIBRARY: IMPERIALISM 0x00610a80 SYMBOL
// ?SetTitle@CDocument@@UAEXPBD@Z
// name: CDocument::SetTitle
// prototype: public: virtual void __thiscall CDocument::SetTitle(char const *)

// LIBRARY: IMPERIALISM 0x00610a9d SYMBOL
// ?DeleteContents@CDocument@@UAEXXZ
// name: CDocument::DeleteContents
// prototype: public: virtual void __thiscall CDocument::DeleteContents(void)

// LIBRARY: IMPERIALISM 0x00610a9e SYMBOL
// ?OnChangedViewList@CDocument@@UAEXXZ
// name: CDocument::OnChangedViewList
// prototype: public: virtual void __thiscall CDocument::OnChangedViewList(void)

// LIBRARY: IMPERIALISM 0x00610aba SYMBOL
// ?UpdateFrameCounts@CDocument@@UAEXXZ
// name: CDocument::UpdateFrameCounts
// prototype: public: virtual void __thiscall CDocument::UpdateFrameCounts(void)

// LIBRARY: IMPERIALISM 0x00610bbd SYMBOL
// ?CanCloseFrame@CDocument@@UAEHPAVCFrameWnd@@@Z
// name: CDocument::CanCloseFrame
// prototype: public: virtual int __thiscall CDocument::CanCloseFrame(class CFrameWnd *)

// LIBRARY: IMPERIALISM 0x00610c08
// CDocument::PreCloseFrame

// LIBRARY: IMPERIALISM 0x00610c0b SYMBOL
// ?SetPathName@CDocument@@UAEXPBDH@Z
// name: CDocument::SetPathName
// prototype: public: virtual void __thiscall CDocument::SetPathName(char const *, int)

// LIBRARY: IMPERIALISM 0x00610c87 SYMBOL
// ?OnFileClose@CDocument@@IAEXXZ
// name: CDocument::OnFileClose
// prototype: protected: void __thiscall CDocument::OnFileClose(void)

// LIBRARY: IMPERIALISM 0x00610ca2
// MFC nafxcw handler in CDocument's message map 0x672078 (ON_COMMAND
// 0xe103): `mov eax,[ecx]; jmp [eax+0xa4]` virtual tail-call.

// LIBRARY: IMPERIALISM 0x00610caa
// MFC nafxcw handler in CDocument's message map 0x672078 (ON_COMMAND
// 0xe104): `push 1; push 0; call [eax+0xa0]` virtual forwarder.

// LIBRARY: IMPERIALISM 0x00610cb7 SYMBOL
// ?DoFileSave@CDocument@@UAEHXZ
// name: CDocument::DoFileSave
// prototype: public: virtual int __thiscall CDocument::DoFileSave(void)

// LIBRARY: IMPERIALISM 0x00610ce5 SYMBOL
// ?DoSave@CDocument@@UAEHPBDH@Z

// LIBRARY: IMPERIALISM 0x00610e6f SYMBOL
// ?SaveModified@CDocument@@UAEHXZ
// name: CDocument::SaveModified
// prototype: public: virtual int __thiscall CDocument::SaveModified(void)

// LIBRARY: IMPERIALISM 0x00610f84
// CDocument::GetDefaultMenu

// LIBRARY: IMPERIALISM 0x00610f87
// CDocument::GetDefaultAccelerator

// LIBRARY: IMPERIALISM 0x00610f8a SYMBOL
// ?ReportSaveLoadException@CDocument@@UAEXPBDPAVCException@@HI@Z
// name: CDocument::ReportSaveLoadException
// prototype: public: virtual void __thiscall CDocument::ReportSaveLoadException(char const *, class CException *, int, unsigned int)

// LIBRARY: IMPERIALISM 0x006110fa SYMBOL
// ?Open@CMirrorFile@@UAEHPBDIPAVCFileException@@@Z
// name: CMirrorFile::Open
// prototype: public: virtual int __thiscall CMirrorFile::Open(char const *, unsigned int, class CFileException *)

// LIBRARY: IMPERIALISM 0x006112c1 SYMBOL
// ?Abort@CMirrorFile@@UAEXXZ
// name: CMirrorFile::Abort
// prototype: public: virtual void __thiscall CMirrorFile::Abort(void)

// LIBRARY: IMPERIALISM 0x006112da SYMBOL
// ?Close@CMirrorFile@@UAEXXZ
// name: CMirrorFile::Close
// prototype: public: virtual void __thiscall CMirrorFile::Close(void)

// LIBRARY: IMPERIALISM 0x00611334 SYMBOL
// ?GetFile@CDocument@@UAEPAVCFile@@PBDIPAVCFileException@@@Z
// name: CDocument::GetFile
// prototype: public: virtual class CFile * __thiscall CDocument::GetFile(char const *, unsigned int, class CFileException *)

// LIBRARY: IMPERIALISM 0x006113aa SYMBOL
// ??_GCCtrlView@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x006113c6 SYMBOL
// ??1CMirrorFile@@UAE@XZ
// name: CMirrorFile::~CMirrorFile
// prototype: public: virtual __thiscall CMirrorFile::~CMirrorFile(void)

// LIBRARY: IMPERIALISM 0x006113f7 SYMBOL
// ?ReleaseFile@CDocument@@UAEXPAVCFile@@H@Z
// name: CDocument::ReleaseFile
// prototype: public: virtual void __thiscall CDocument::ReleaseFile(class CFile *, int)

// LIBRARY: IMPERIALISM 0x00611420 SYMBOL
// ?OnNewDocument@CDocument@@UAEHXZ
// name: CDocument::OnNewDocument
// prototype: public: virtual int __thiscall CDocument::OnNewDocument(void)

// LIBRARY: IMPERIALISM 0x00611443 SYMBOL
// ?OnOpenDocument@CDocument@@UAEHPBD@Z

// LIBRARY: IMPERIALISM 0x0061160e SYMBOL
// ?OnSaveDocument@CDocument@@UAEHPBD@Z

// LIBRARY: IMPERIALISM 0x006117b5 SYMBOL
// ?OnCloseDocument@CDocument@@UAEXXZ
// name: CDocument::OnCloseDocument
// prototype: public: virtual void __thiscall CDocument::OnCloseDocument(void)

// LIBRARY: IMPERIALISM 0x0061180f
// CDocument::OnIdle

// LIBRARY: IMPERIALISM 0x00611810 SYMBOL
// ?AddView@CDocument@@QAEXPAVCView@@@Z
// name: CDocument::AddView
// prototype: public: void __thiscall CDocument::AddView(class CView *)

// LIBRARY: IMPERIALISM 0x00611830 SYMBOL
// ?RemoveView@CDocument@@QAEXPAVCView@@@Z
// name: CDocument::RemoveView
// prototype: public: void __thiscall CDocument::RemoveView(class CView *)

// LIBRARY: IMPERIALISM 0x0061185f SYMBOL
// ?GetFirstViewPosition@CDocument@@UBEPAU__POSITION@@XZ
// name: CDocument::GetFirstViewPosition
// prototype: public: virtual struct __POSITION * __thiscall CDocument::GetFirstViewPosition(void)const

// LIBRARY: IMPERIALISM 0x00611863 SYMBOL
// ?GetNextView@CDocument@@UBEPAVCView@@AAPAU__POSITION@@@Z
// name: CDocument::GetNextView
// prototype: public: virtual class CView * __thiscall CDocument::GetNextView(struct __POSITION * &)const

// LIBRARY: IMPERIALISM 0x00611877 SYMBOL
// ?UpdateAllViews@CDocument@@QAEXPAVCView@@JPAVCObject@@@Z
// name: CDocument::UpdateAllViews
// prototype: public: void __thiscall CDocument::UpdateAllViews(class CView *, long, class CObject *)

// LIBRARY: IMPERIALISM 0x006118ba SYMBOL
// ?SendInitialUpdate@CDocument@@QAEXXZ
// name: CDocument::SendInitialUpdate
// prototype: public: void __thiscall CDocument::SendInitialUpdate(void)

// LIBRARY: IMPERIALISM 0x006118ed SYMBOL
// ?OnCmdMsg@CDocument@@UAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z
// name: CDocument::OnCmdMsg
// prototype: public: virtual int __thiscall CDocument::OnCmdMsg(unsigned int, int, void *, struct AFX_CMDHANDLERINFO *)

// LIBRARY: IMPERIALISM 0x00611930 SYMBOL
// ??6@YGAAVCArchive@@AAV0@ABVCString@@@Z
// name: operator<<
// prototype: class CArchive & __stdcall operator<<(class CArchive &, class CString const &)

// LIBRARY: IMPERIALISM 0x006119aa SYMBOL
// ??5@YGAAVCArchive@@AAV0@AAVCString@@@Z
// name: operator>>
// prototype: class CArchive & __stdcall operator>>(class CArchive &, class CString &)

// LIBRARY: IMPERIALISM 0x00611a47 SYMBOL
// ?ReadStringLength@@YGIAAVCArchive@@@Z

// LIBRARY: IMPERIALISM 0x00611a9e SYMBOL
// ?SerializeElements@@YGXAAVCArchive@@PAVCString@@H@Z
// name: SerializeElements
// prototype: void __stdcall SerializeElements(class CArchive &, class CString *, int)

// LIBRARY: IMPERIALISM 0x00611aec SYMBOL
// ?Load@CRuntimeClass@@SGPAU1@AAVCArchive@@PAI@Z
// name: CRuntimeClass::Load
// prototype: public: static struct CRuntimeClass * __stdcall CRuntimeClass::Load(class CArchive &, unsigned int *)

// LIBRARY: IMPERIALISM 0x00611b7c SYMBOL
// ?Store@CRuntimeClass@@QBEXAAVCArchive@@@Z
// name: CRuntimeClass::Store
// prototype: public: void __thiscall CRuntimeClass::Store(class CArchive &) const

// LIBRARY: IMPERIALISM 0x00611bb4 SYMBOL
// ??0CArchive@@QAE@PAVCFile@@IHPAX@Z
// name: CArchive::CArchive
// prototype: public: __thiscall CArchive::CArchive(class CFile *, unsigned int, int, void *)

// LIBRARY: IMPERIALISM 0x00611c90 SYMBOL
// ??1CArchive@@QAE@XZ
// name: CArchive::~CArchive
// prototype: public: __thiscall CArchive::~CArchive(void)

// LIBRARY: IMPERIALISM 0x00611cd6 SYMBOL
// ?Abort@CArchive@@QAEXXZ
// name: CArchive::Abort
// prototype: public: void __thiscall CArchive::Abort(void)

// LIBRARY: IMPERIALISM 0x00611d18 SYMBOL
// ?Close@CArchive@@QAEXXZ
// name: CArchive::Close
// prototype: public: void __thiscall CArchive::Close(void)

// LIBRARY: IMPERIALISM 0x00611d26 SYMBOL
// ?Read@CArchive@@QAEIPAXI@Z
// name: CArchive::Read
// prototype: public: unsigned int __thiscall CArchive::Read(void *, unsigned int)

// LIBRARY: IMPERIALISM 0x00611e34 SYMBOL
// ?Write@CArchive@@QAEXPBXI@Z
// name: CArchive::Write
// prototype: public: void __thiscall CArchive::Write(void const *, unsigned int)

// LIBRARY: IMPERIALISM 0x00611ec4 SYMBOL
// ?Flush@CArchive@@QAEXXZ
// name: CArchive::Flush
// prototype: public: void __thiscall CArchive::Flush(void)

// LIBRARY: IMPERIALISM 0x00611f3e SYMBOL
// ?FillBuffer@CArchive@@QAEXI@Z
// name: CArchive::FillBuffer
// prototype: public: void __thiscall CArchive::FillBuffer(unsigned int)

// LIBRARY: IMPERIALISM 0x00612000 SYMBOL
// ?WriteCount@CArchive@@QAEXK@Z
// name: CArchive::WriteCount
// prototype: public: void __thiscall CArchive::WriteCount(unsigned long)

// LIBRARY: IMPERIALISM 0x0061202e SYMBOL
// ?ReadCount@CArchive@@QAEKXZ
// name: CArchive::ReadCount
// prototype: public: unsigned long __thiscall CArchive::ReadCount(void)

// LIBRARY: IMPERIALISM 0x0061205e SYMBOL
// ?WriteString@CArchive@@QAEXPBD@Z
// name: CArchive::WriteString
// prototype: public: void __thiscall CArchive::WriteString(char const *)

// LIBRARY: IMPERIALISM 0x0061207b SYMBOL
// ?ReadString@CArchive@@QAEPADPADI@Z

// LIBRARY: IMPERIALISM 0x00612132 SYMBOL
// ?ReadString@CArchive@@QAEHAAVCString@@@Z
// name: CArchive::ReadString
// prototype: public: int __thiscall CArchive::ReadString(class CString &)

// LIBRARY: IMPERIALISM 0x006121cd SYMBOL
// ?CheckCount@CArchive@@QAEXXZ
// name: CArchive::CheckCount
// prototype: public: void __thiscall CArchive::CheckCount(void)

// LIBRARY: IMPERIALISM 0x006121e1 SYMBOL
// ?WriteObject@CArchive@@QAEXPBVCObject@@@Z
// name: CArchive::WriteObject
// prototype: public: void __thiscall CArchive::WriteObject(class CObject const *)

// LIBRARY: IMPERIALISM 0x0061225e SYMBOL
// ?ReadObject@CArchive@@QAEPAVCObject@@PBUCRuntimeClass@@@Z
// name: CArchive::ReadObject
// prototype: public: class CObject * __thiscall CArchive::ReadObject(struct CRuntimeClass const *)

// LIBRARY: IMPERIALISM 0x00612315 SYMBOL
// ?MapObject@CArchive@@QAEXPBVCObject@@@Z
// name: CArchive::MapObject
// prototype: public: void __thiscall CArchive::MapObject(class CObject const *)

// LIBRARY: IMPERIALISM 0x0061240d SYMBOL
// ?WriteClass@CArchive@@QAEXPBUCRuntimeClass@@@Z
// name: CArchive::WriteClass
// prototype: public: void __thiscall CArchive::WriteClass(struct CRuntimeClass const *)

// LIBRARY: IMPERIALISM 0x0061249e SYMBOL
// ?ReadClass@CArchive@@QAEPAUCRuntimeClass@@PBU2@PAIPAK@Z
// name: CArchive::ReadClass
// prototype: public: struct CRuntimeClass * __thiscall CArchive::ReadClass(struct CRuntimeClass const *, unsigned int *, unsigned long *)

// LIBRARY: IMPERIALISM 0x00612682 SYMBOL
// ??0CDC@@QAE@XZ
// name: CDC::CDC
// prototype: public: __thiscall CDC::CDC(void)

// LIBRARY: IMPERIALISM 0x00612696 SYMBOL
// ??_GCDC@@UAEPAXI@Z
// name: CDC::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CDC::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x006126b2 SYMBOL
// ?DeleteTempMap@CMenu@@SGXXZ

// LIBRARY: IMPERIALISM 0x006126c6 SYMBOL
// ?afxMapHDC@@YAPAVCHandleMap@@H@Z

// LIBRARY: IMPERIALISM 0x00612736 SYMBOL
// ?FromHandle@CDC@@SGPAV1@PAUHDC__@@@Z
// name: CDC::FromHandle
// prototype: public: static class CDC * __stdcall CDC::FromHandle(struct HDC__*)

// LIBRARY: IMPERIALISM 0x0061274c SYMBOL
// ?Attach@CDC@@QAEHPAUHDC__@@@Z
// name: CDC::Attach
// prototype: public: int __thiscall CDC::Attach(struct HDC__*)

// LIBRARY: IMPERIALISM 0x00612783 SYMBOL
// ?Detach@CDC@@QAEPAUHDC__@@XZ
// name: CDC::Detach
// prototype: public: struct HDC__* __thiscall CDC::Detach(void)

// LIBRARY: IMPERIALISM 0x006127ca SYMBOL
// ??1CDC@@UAE@XZ
// name: CDC::~CDC
// prototype: public: virtual __thiscall CDC::~CDC(void)

// LIBRARY: IMPERIALISM 0x00612828 SYMBOL
// ?StartDocA@CDC@@QAEHPBD@Z
// name: CDC::StartDocA
// prototype: public: int __thiscall CDC::StartDocA(char const *)

// LIBRARY: IMPERIALISM 0x00612860 SYMBOL
// ?SaveDC@CDC@@UAEHXZ
// name: CDC::SaveDC
// prototype: public: virtual int __thiscall CDC::SaveDC(void)

// LIBRARY: IMPERIALISM 0x00612897 SYMBOL
// ?RestoreDC@CDC@@UAEHH@Z
// name: CDC::RestoreDC
// prototype: public: virtual int __thiscall CDC::RestoreDC(int)

// LIBRARY: IMPERIALISM 0x006128ec SYMBOL
// ?SelectStockObject@CDC@@UAEPAVCGdiObject@@H@Z
// name: CDC::SelectStockObject
// prototype: public: virtual class CGdiObject * __thiscall CDC::SelectStockObject(int)

// LIBRARY: IMPERIALISM 0x00612931 SYMBOL
// ?SelectObject@CDC@@QAEPAVCPen@@PAV2@@Z
// name: CDC::SelectObject
// prototype: public: class CPen * __thiscall CDC::SelectObject(class CPen *)

// LIBRARY: IMPERIALISM 0x00612984 SYMBOL
// ?SelectObject@CDC@@QAEPAVCBrush@@PAV2@@Z

// LIBRARY: IMPERIALISM 0x006129d7 SYMBOL
// ?SelectObject@CDC@@UAEPAVCFont@@PAV2@@Z
// name: CDC::SelectObject
// prototype: public: virtual class CFont * __thiscall CDC::SelectObject(class CFont *)

// LIBRARY: IMPERIALISM 0x00612a2a
// CDC::SelectClipRgn

// LIBRARY: IMPERIALISM 0x00612a78
// ownership-only

// LIBRARY: IMPERIALISM 0x00612a9a SYMBOL
// ?SetPolyFillMode@CDC@@QAEHH@Z

// LIBRARY: IMPERIALISM 0x00612ad2 SYMBOL
// ?SetBkMode@CDC@@QAEHH@Z
// name: CDC::SetBkMode
// prototype: public: int __thiscall CDC::SetBkMode(int)

// LIBRARY: IMPERIALISM 0x00612b0a SYMBOL
// ?SetPolyFillMode@CDC@@QAEHH@Z

// LIBRARY: IMPERIALISM 0x00612b42 SYMBOL
// ?SetPolyFillMode@CDC@@QAEHH@Z

// LIBRARY: IMPERIALISM 0x00612b7a SYMBOL
// ?SetPolyFillMode@CDC@@QAEHH@Z

// LIBRARY: IMPERIALISM 0x00612bb2 SYMBOL
// ?SetPolyFillMode@CDC@@QAEHH@Z

// LIBRARY: IMPERIALISM 0x00612bea SYMBOL
// ?SetMapMode@CDC@@UAEHH@Z
// name: CDC::SetMapMode
// prototype: public: virtual int __thiscall CDC::SetMapMode(int)

// LIBRARY: IMPERIALISM 0x00612c22 SYMBOL
// ?MoveTo@CDC@@QAE?AVCPoint@@HH@Z

// LIBRARY: IMPERIALISM 0x00612c6e SYMBOL
// ?MoveTo@CDC@@QAE?AVCPoint@@HH@Z

// LIBRARY: IMPERIALISM 0x00612cba SYMBOL
// ?MoveTo@CDC@@QAE?AVCPoint@@HH@Z

// LIBRARY: IMPERIALISM 0x00612d06 SYMBOL
// ?ScaleWindowExt@CDC@@UAE?AVCSize@@HHHH@Z

// LIBRARY: IMPERIALISM 0x00612d5e SYMBOL
// ?SetWindowOrg@CDC@@QAE?AVCPoint@@HH@Z
// name: CDC::SetWindowOrg
// prototype: public: class CPoint __thiscall CDC::SetWindowOrg(int, int)

// LIBRARY: IMPERIALISM 0x00612daa SYMBOL
// ?MoveTo@CDC@@QAE?AVCPoint@@HH@Z

// LIBRARY: IMPERIALISM 0x00612df6 SYMBOL
// ?MoveTo@CDC@@QAE?AVCPoint@@HH@Z

// LIBRARY: IMPERIALISM 0x00612e42 SYMBOL
// ?ScaleWindowExt@CDC@@UAE?AVCSize@@HHHH@Z

// LIBRARY: IMPERIALISM 0x00612e9a SYMBOL
// ?GetClipBox@CDC@@UBEHPAUtagRECT@@@Z
// name: CDC::GetClipBox
// prototype: public: virtual int __thiscall CDC::GetClipBox(struct tagRECT *) const

// LIBRARY: IMPERIALISM 0x00612eaa SYMBOL
// ?SelectClipRgn@CDC@@QAEHPAVCRgn@@@Z

// LIBRARY: IMPERIALISM 0x00612ef8 SYMBOL
// ?ExcludeClipRect@CDC@@QAEHHHHH@Z

// LIBRARY: IMPERIALISM 0x00612f42 SYMBOL
// ?ExcludeClipRect@CDC@@QAEHPBUtagRECT@@@Z

// LIBRARY: IMPERIALISM 0x00612f8e SYMBOL
// ?IntersectClipRect@CDC@@QAEHHHHH@Z

// LIBRARY: IMPERIALISM 0x00612fd8 SYMBOL
// ?IntersectClipRect@CDC@@QAEHPBUtagRECT@@@Z

// LIBRARY: IMPERIALISM 0x00613024 SYMBOL
// ?OffsetClipRgn@CDC@@QAEHHH@Z

// LIBRARY: IMPERIALISM 0x00613062 SYMBOL
// ?OffsetClipRgn@CDC@@QAEHUtagSIZE@@@Z

// LIBRARY: IMPERIALISM 0x006130a0 SYMBOL
// ?MoveTo@CDC@@QAE?AVCPoint@@HH@Z

// LIBRARY: IMPERIALISM 0x006130ec SYMBOL
// ?LineTo@CDC@@QAEHHH@Z
// name: LineTo
// prototype: int __thiscall CDC::LineTo(int param_1, int param_2)

// LIBRARY: IMPERIALISM 0x00613121 SYMBOL
// ?SetTextAlign@CDC@@QAEII@Z
// name: CDC::SetTextAlign
// prototype: public: unsigned int __thiscall CDC::SetTextAlign(unsigned int)

// LIBRARY: IMPERIALISM 0x00613155
// CDC::OffsetClipRgn

// LIBRARY: IMPERIALISM 0x00613193 SYMBOL
// ?SetPolyFillMode@CDC@@QAEHH@Z

// LIBRARY: IMPERIALISM 0x006131cb SYMBOL
// ?SetMapperFlags@CDC@@QAEKK@Z

// LIBRARY: IMPERIALISM 0x00613203 SYMBOL
// ?ArcTo@CDC@@QAEHHHHHHHHH@Z

// LIBRARY: IMPERIALISM 0x0061325b SYMBOL
// ?SetPolyFillMode@CDC@@QAEHH@Z

// LIBRARY: IMPERIALISM 0x00613293 SYMBOL
// ?PolyDraw@CDC@@QAEHPBUtagPOINT@@PBEH@Z

// LIBRARY: IMPERIALISM 0x006132dc SYMBOL
// ?PolyBezierTo@CDC@@QAEHPBUtagPOINT@@H@Z

// LIBRARY: IMPERIALISM 0x00613322 SYMBOL
// ?SetPolyFillMode@CDC@@QAEHH@Z

// LIBRARY: IMPERIALISM 0x0061335a SYMBOL
// ?PolyBezierTo@CDC@@QAEHPBUtagPOINT@@H@Z

// LIBRARY: IMPERIALISM 0x006133a0 SYMBOL
// ?SelectClipPath@CDC@@QAEHH@Z
// name: CDC::SelectClipPath
// prototype: public: int __thiscall CDC::SelectClipPath(int)

// LIBRARY: IMPERIALISM 0x006133fe SYMBOL
// ?SelectClipRgn@CDC@@QAEHPAVCRgn@@H@Z
// name: CDC::SelectClipRgn
// prototype: public: int __thiscall CDC::SelectClipRgn(class CRgn *, int)

// LIBRARY: IMPERIALISM 0x00613452 SYMBOL
// ?AfxEnumMetaFileProc@@YGHPAUHDC__@@PAUtagHANDLETABLE@@PAUtagMETARECORD@@HJ@Z
// name: AfxEnumMetaFileProc
// prototype: int __stdcall AfxEnumMetaFileProc(struct HDC__*, struct tagHANDLETABLE *, struct tagMETARECORD *, int, long)

// LIBRARY: IMPERIALISM 0x00613686 SYMBOL
// ?PlayMetaFile@CDC@@QAEHPAUHMETAFILE__@@@Z
// name: PlayMetaFile
// prototype: int __thiscall CDC::PlayMetaFile(HMETAFILE__ * param_1)

// LIBRARY: IMPERIALISM 0x006136bf SYMBOL
// ?LPtoDP@CDC@@QBEXPAUtagSIZE@@@Z
// name: CDC::LPtoDP
// prototype: public: void __thiscall CDC::LPtoDP(struct tagSIZE *) const

// LIBRARY: IMPERIALISM 0x00613728 SYMBOL
// ?DPtoLP@CDC@@QBEXPAUtagSIZE@@@Z
// name: CDC::DPtoLP
// prototype: public: void __thiscall CDC::DPtoLP(struct tagSIZE *) const

// LIBRARY: IMPERIALISM 0x00613791 SYMBOL
// ??0CClientDC@@QAE@PAVCWnd@@@Z
// name: CClientDC::CClientDC
// prototype: public: __thiscall CClientDC::CClientDC(class CWnd *)

// LIBRARY: IMPERIALISM 0x006137e7
// ownership-only

// LIBRARY: IMPERIALISM 0x00613803 SYMBOL
// ??1CClientDC@@UAE@XZ
// name: CClientDC::~CClientDC
// prototype: public: virtual __thiscall CClientDC::~CClientDC(void)

// LIBRARY: IMPERIALISM 0x00613845 SYMBOL
// ??0CWindowDC@@QAE@PAVCWnd@@@Z
// name: CWindowDC::CWindowDC
// prototype: public: __thiscall CWindowDC::CWindowDC(class CWnd *)

// LIBRARY: IMPERIALISM 0x0061389b SYMBOL
// ??_GCClientDC@@UAEPAXI@Z
// name: CClientDC::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CClientDC::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x006138b7 SYMBOL
// ??1CWindowDC@@UAE@XZ
// name: CWindowDC::~CWindowDC
// prototype: public: virtual __thiscall CWindowDC::~CWindowDC(void)

// LIBRARY: IMPERIALISM 0x006138f9 SYMBOL
// ??0CPaintDC@@QAE@PAVCWnd@@@Z
// name: CPaintDC::CPaintDC
// prototype: public: __thiscall CPaintDC::CPaintDC(class CWnd *)

// LIBRARY: IMPERIALISM 0x0061394f SYMBOL
// ??_GCPaintDC@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x0061396b SYMBOL
// ??1CPaintDC@@UAE@XZ

// LIBRARY: IMPERIALISM 0x006139b2 SYMBOL
// ?DeleteTempMap@CMenu@@SGXXZ

// LIBRARY: IMPERIALISM 0x006139c6 SYMBOL
// ?afxMapHGDIOBJ@@YGPAVCHandleMap@@H@Z

// LIBRARY: IMPERIALISM 0x00613a36 SYMBOL
// ?FromHandle@CGdiObject@@SGPAV1@PAX@Z
// name: CGdiObject::FromHandle
// prototype: public: static class CGdiObject * __stdcall CGdiObject::FromHandle(void *)

// LIBRARY: IMPERIALISM 0x00613a4c SYMBOL
// ?Attach@CGdiObject@@QAEHPAX@Z
// name: CGdiObject::Attach
// prototype: public: int __thiscall CGdiObject::Attach(void *)

// LIBRARY: IMPERIALISM 0x00613a79 SYMBOL
// ?Detach@CMenu@@QAEPAUHMENU__@@XZ

// LIBRARY: IMPERIALISM 0x00613aa3 SYMBOL
// ?DeleteObject@CGdiObject@@QAEHXZ
// name: CGdiObject::DeleteObject
// prototype: public: int __thiscall CGdiObject::DeleteObject(void)

// LIBRARY: IMPERIALISM 0x00613ab9 SYMBOL
// ??0CPen@@QAE@HHK@Z
// name: CPen::CPen
// prototype: public: __thiscall CPen::CPen(int, int, unsigned long)

// LIBRARY: IMPERIALISM 0x00613b09 SYMBOL
// ??0CPen@@QAE@HHPBUtagLOGBRUSH@@HPBK@Z
// name: CPen::CPen
// prototype: public: __thiscall CPen::CPen(int, int, struct tagLOGBRUSH const *, int, unsigned long const *)

// LIBRARY: IMPERIALISM 0x00613b5f SYMBOL
// ??0CBrush@@QAE@K@Z
// name: CBrush::CBrush
// prototype: public: __thiscall CBrush::CBrush(unsigned long)

// LIBRARY: IMPERIALISM 0x00613ba9 SYMBOL
// ??0CBrush@@QAE@HK@Z
// name: CBrush::CBrush
// prototype: public: __thiscall CBrush::CBrush(int, unsigned long)

// LIBRARY: IMPERIALISM 0x00613bf6 SYMBOL
// ??0CBrush@@QAE@PAVCBitmap@@@Z
// name: CBrush::CBrush
// prototype: public: __thiscall CBrush::CBrush(class CBitmap *)

// LIBRARY: IMPERIALISM 0x00613c43 SYMBOL
// ?CreateDIBPatternBrush@CBrush@@QAEHPAXI@Z

// LIBRARY: IMPERIALISM 0x00613c75 SYMBOL
// ?AfxThrowResourceException@@YGXXZ
// name: AfxThrowResourceException
// prototype: void __stdcall AfxThrowResourceException(void)

// LIBRARY: IMPERIALISM 0x00613c90 SYMBOL
// ?AfxThrowUserException@@YGXXZ
// name: AfxThrowUserException
// prototype: void __stdcall AfxThrowUserException(void)

// LIBRARY: IMPERIALISM 0x00613cb1 SYMBOL
// ??0CView@@IAE@XZ
// name: CView::CView
// prototype: protected: __thiscall CView::CView(void)

// LIBRARY: IMPERIALISM 0x00613cc7 SYMBOL
// ??_GCView@@UAEPAXI@Z
// name: CView::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CView::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00613ce3 SYMBOL
// ??1CView@@UAE@XZ
// name: CView::~CView
// prototype: public: virtual __thiscall CView::~CView(void)

// LIBRARY: IMPERIALISM 0x00613d23 SYMBOL
// ?PreCreateWindow@CView@@MAEHAAUtagCREATESTRUCTA@@@Z
// name: CView::PreCreateWindow
// prototype: protected: virtual int __thiscall CView::PreCreateWindow(struct tagCREATESTRUCTA &)

// LIBRARY: IMPERIALISM 0x00613d76 SYMBOL
// ?OnCreate@CView@@IAEHPAUtagCREATESTRUCTA@@@Z
// name: CView::OnCreate
// prototype: protected: int __thiscall CView::OnCreate(struct tagCREATESTRUCTA *)

// LIBRARY: IMPERIALISM 0x00613da6 SYMBOL
// ?OnDestroy@CView@@IAEXXZ
// name: CView::OnDestroy
// prototype: protected: void __thiscall CView::OnDestroy(void)

// LIBRARY: IMPERIALISM 0x00613dd5 SYMBOL
// ?PostNcDestroy@CView@@MAEXXZ
// name: CView::PostNcDestroy
// prototype: protected: virtual void __thiscall CView::PostNcDestroy(void)

// LIBRARY: IMPERIALISM 0x00613de1 SYMBOL
// ?CalcWindowRect@CView@@UAEXPAUtagRECT@@I@Z
// name: CView::CalcWindowRect
// prototype: public: virtual void __thiscall CView::CalcWindowRect(struct tagRECT *, unsigned int)

// LIBRARY: IMPERIALISM 0x00613e49 SYMBOL
// ?OnCmdMsg@CView@@MAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z
// name: CView::OnCmdMsg
// prototype: protected: virtual int __thiscall CView::OnCmdMsg(unsigned int, int, void *, struct AFX_CMDHANDLERINFO *)

// LIBRARY: IMPERIALISM 0x00613eb0 SYMBOL
// ?OnPaint@CView@@IAEXXZ
// name: CView::OnPaint
// prototype: protected: void __thiscall CView::OnPaint(void)

// LIBRARY: IMPERIALISM 0x00613f04 SYMBOL
// ?OnInitialUpdate@CView@@UAEXXZ
// name: CView::OnInitialUpdate
// prototype: public: virtual void __thiscall CView::OnInitialUpdate(void)

// LIBRARY: IMPERIALISM 0x00613f12 SYMBOL
// ?OnUpdate@CView@@MAEXPAV1@JPAVCObject@@@Z
// name: CView::OnUpdate
// prototype: protected: virtual void __thiscall CView::OnUpdate(class CView *, long, class CObject *)

// LIBRARY: IMPERIALISM 0x00613f22 SYMBOL
// ?OnPrint@CView@@MAEXPAVCDC@@PAUCPrintInfo@@@Z
// name: CView::OnPrint
// prototype: protected: virtual void __thiscall CView::OnPrint(class CDC *, struct CPrintInfo *)

// LIBRARY: IMPERIALISM 0x00613f34 SYMBOL
// ?IsSelected@CView@@UBEHPBVCObject@@@Z
// name: CView::IsSelected
// prototype: public: virtual int __thiscall CView::IsSelected(class CObject const *)const

// LIBRARY: IMPERIALISM 0x00613f39 SYMBOL
// ?OnActivateView@CView@@MAEXHPAV1@0@Z
// name: CView::OnActivateView
// prototype: protected: virtual void __thiscall CView::OnActivateView(int, class CView *, class CView *)

// LIBRARY: IMPERIALISM 0x00613f57 SYMBOL
// ?OnActivateFrame@CView@@MAEXIPAVCFrameWnd@@@Z
// name: CView::OnActivateFrame
// prototype: protected: virtual void __thiscall CView::OnActivateFrame(unsigned int,class CFrameWnd *)

// LIBRARY: IMPERIALISM 0x00613f5a SYMBOL
// ?OnMouseActivate@CView@@IAEHPAVCWnd@@II@Z
// name: CView::OnMouseActivate
// prototype: protected: int __thiscall CView::OnMouseActivate(class CWnd *, unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x00613fc7 SYMBOL
// ?OnScroll@CView@@UAEHIIH@Z
// name: CView::OnScroll
// prototype: public: virtual int __thiscall CView::OnScroll(unsigned int,unsigned int,int)

// LIBRARY: IMPERIALISM 0x00613fcc SYMBOL
// ?OnScrollBy@CView@@UAEHVCSize@@H@Z
// name: CView::OnScrollBy
// prototype: public: virtual int __thiscall CView::OnScrollBy(class CSize,int)

// LIBRARY: IMPERIALISM 0x00613fd1 SYMBOL
// ?OnDragScroll@CView@@UAEKKVCPoint@@@Z
// name: CView::OnDragScroll
// prototype: public: virtual unsigned long __thiscall CView::OnDragScroll(unsigned long,class CPoint)

// LIBRARY: IMPERIALISM 0x00613fd9 SYMBOL
// ?OnDragEnter@CView@@UAEKPAVCOleDataObject@@KVCPoint@@@Z
// name: CView::OnDragEnter
// prototype: public: virtual unsigned long __thiscall CView::OnDragEnter(class COleDataObject *,unsigned long,class CPoint)

// LIBRARY: IMPERIALISM 0x00613fde SYMBOL
// ?OnDragOver@CView@@UAEKPAVCOleDataObject@@KVCPoint@@@Z
// name: CView::OnDragOver
// prototype: public: virtual unsigned long __thiscall CView::OnDragOver(class COleDataObject *,unsigned long,class CPoint)

// LIBRARY: IMPERIALISM 0x00613fe3 SYMBOL
// ?OnDrop@CView@@UAEHPAVCOleDataObject@@KVCPoint@@@Z
// name: CView::OnDrop
// prototype: public: virtual int __thiscall CView::OnDrop(class COleDataObject *,unsigned long,class CPoint)

// LIBRARY: IMPERIALISM 0x00613fe8 SYMBOL
// ?OnDropEx@CView@@UAEKPAVCOleDataObject@@KKVCPoint@@@Z
// name: CView::OnDropEx
// prototype: public: virtual unsigned long __thiscall CView::OnDropEx(class COleDataObject *,unsigned long,unsigned long,class CPoint)

// LIBRARY: IMPERIALISM 0x00613fee SYMBOL
// ?OnDragLeave@CView@@UAEXXZ
// name: CView::OnDragLeave
// prototype: public: virtual void __thiscall CView::OnDragLeave(void)

// LIBRARY: IMPERIALISM 0x00613fef SYMBOL
// ?GetParentSplitter@CView@@SGPAVCSplitterWnd@@PBVCWnd@@H@Z
// name: CView::GetParentSplitter
// prototype: public: static class CSplitterWnd * __stdcall CView::GetParentSplitter(class CWnd const *, int)

// LIBRARY: IMPERIALISM 0x0061404d SYMBOL
// ?GetScrollBarCtrl@CView@@UBEPAVCScrollBar@@H@Z
// name: CView::GetScrollBarCtrl
// prototype: public: virtual class CScrollBar * __thiscall CView::GetScrollBarCtrl(int)const

// LIBRARY: IMPERIALISM 0x006140c2
// MFC nafxcw handler in message map 0x672aa0 (base CWnd), ON_COMMAND
// 0xe135 -- MFC frame/window command family.

// LIBRARY: IMPERIALISM 0x006140ea
// MFC nafxcw handler in message map 0x672aa0 (base CWnd), ON_COMMAND
// 0xe135 -- MFC frame/window command family.

// LIBRARY: IMPERIALISM 0x00614106
// MFC nafxcw handler in message map 0x672aa0 (base CWnd), ON_COMMAND
// 0xe150/0xe151 -- MFC frame/window command family.

// LIBRARY: IMPERIALISM 0x00614144
// MFC nafxcw handler in message map 0x672aa0 (base CWnd), ON_COMMAND
// 0xe150/0xe151 -- MFC frame/window command family.

// LIBRARY: IMPERIALISM 0x0061416e SYMBOL
// ?OnPrepareDC@CView@@UAEXPAVCDC@@PAUCPrintInfo@@@Z
// name: CView::OnPrepareDC
// prototype: public: virtual void __thiscall CView::OnPrepareDC(class CDC *, struct CPrintInfo *)

// LIBRARY: IMPERIALISM 0x00614193 SYMBOL
// ?OnPreparePrinting@CView@@MAEHPAUCPrintInfo@@@Z
// name: CView::OnPreparePrinting
// prototype: protected: virtual int __thiscall CView::OnPreparePrinting(struct CPrintInfo *)

// LIBRARY: IMPERIALISM 0x00614199 SYMBOL
// ?OnBeginPrinting@CView@@MAEXPAVCDC@@PAUCPrintInfo@@@Z
// name: CView::OnBeginPrinting
// prototype: protected: virtual void __thiscall CView::OnBeginPrinting(class CDC *,struct CPrintInfo *)

// LIBRARY: IMPERIALISM 0x0061419c SYMBOL
// ?OnEndPrinting@CView@@MAEXPAVCDC@@PAUCPrintInfo@@@Z
// name: CView::OnEndPrinting
// prototype: protected: virtual void __thiscall CView::OnEndPrinting(class CDC *,struct CPrintInfo *)

// LIBRARY: IMPERIALISM 0x0061419f SYMBOL
// ?OnEndPrintPreview@CView@@MAEXPAVCDC@@PAUCPrintInfo@@UtagPOINT@@PAVCPreviewView@@@Z
// name: CView::OnEndPrintPreview
// prototype: protected: virtual void __thiscall CView::OnEndPrintPreview(class CDC *,struct CPrintInfo *,struct tagPOINT,class CPreviewView *)

// LIBRARY: IMPERIALISM 0x006142c0 SYMBOL
// ??_GCCtrlView@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x006142dc SYMBOL
// ?PreCreateWindow@CCtrlView@@MAEHAAUtagCREATESTRUCTA@@@Z
// name: CCtrlView::PreCreateWindow
// prototype: protected: virtual int __thiscall CCtrlView::PreCreateWindow(struct tagCREATESTRUCTA &)

// LIBRARY: IMPERIALISM 0x00614331 SYMBOL
// ?AfxCustomLogFont@@YGHIPAUtagLOGFONTA@@@Z
// name: AfxCustomLogFont
// prototype: int __stdcall AfxCustomLogFont(unsigned int, struct tagLOGFONTA *)

// LIBRARY: IMPERIALISM 0x006143a9 SYMBOL
// ?_AfxIsComboBoxControl@@YGHPAUHWND__@@I@Z
// name: _AfxIsComboBoxControl
// prototype: int __stdcall _AfxIsComboBoxControl(struct HWND__*, unsigned int)

// LIBRARY: IMPERIALISM 0x006143f3 SYMBOL
// ?_AfxCompareClassName@@YGHPAUHWND__@@PBD@Z
// name: _AfxCompareClassName
// prototype: int __stdcall _AfxCompareClassName(struct HWND__*, char const *)

// LIBRARY: IMPERIALISM 0x0061441e SYMBOL
// ?_AfxChildWindowFromPoint@@YGPAUHWND__@@PAU1@UtagPOINT@@@Z
// name: _AfxChildWindowFromPoint
// prototype: struct HWND__* __stdcall _AfxChildWindowFromPoint(struct HWND__*, struct tagPOINT)

// LIBRARY: IMPERIALISM 0x00614493 SYMBOL
// ?AfxSetWindowText@@YGXPAUHWND__@@PBD@Z
// name: AfxSetWindowText
// prototype: void __stdcall AfxSetWindowText(struct HWND__*, char const *)

// LIBRARY: IMPERIALISM 0x006144eb SYMBOL
// ?AfxDeleteObject@@YGXPAPAX@Z
// name: AfxDeleteObject
// prototype: void __stdcall AfxDeleteObject(void **)

// LIBRARY: IMPERIALISM 0x00614504 SYMBOL
// ?AfxCancelModes@@YGXPAUHWND__@@@Z
// name: AfxCancelModes
// prototype: void __stdcall AfxCancelModes(struct HWND__*)

// LIBRARY: IMPERIALISM 0x0061457b SYMBOL
// ?AfxGlobalFree@@YGXPAX@Z
// name: AfxGlobalFree
// prototype: void __stdcall AfxGlobalFree(void *)

// LIBRARY: IMPERIALISM 0x006145b1 SYMBOL
// ?AfxCriticalNewHandler@@YAHI@Z
// name: AfxCriticalNewHandler
// prototype: int __cdecl AfxCriticalNewHandler(unsigned int)

// LIBRARY: IMPERIALISM 0x00614603 SYMBOL
// ?OpenDocumentFile@CDocManager@@UAEPAVCDocument@@PBD@Z
// name: CDocManager::OpenDocumentFile
// prototype: public: virtual class CDocument * __thiscall CDocManager::OpenDocumentFile(char const *)

// LIBRARY: IMPERIALISM 0x00614744 SYMBOL
// ?GetOpenDocumentCount@CDocManager@@UAEHXZ
// name: CDocManager::GetOpenDocumentCount
// prototype: public: virtual int __thiscall CDocManager::GetOpenDocumentCount(void)

// LIBRARY: IMPERIALISM 0x00614790 SYMBOL
// ??0CDocTemplate@@IAE@IPAUCRuntimeClass@@00@Z
// name: CDocTemplate::CDocTemplate
// prototype: protected: __thiscall CDocTemplate::CDocTemplate(unsigned int, struct CRuntimeClass *, struct CRuntimeClass *, struct CRuntimeClass *)

// LIBRARY: IMPERIALISM 0x00614893 SYMBOL
// ??_GCDocTemplate@@UAEPAXI@Z
// name: CDocTemplate::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CDocTemplate::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x006148af SYMBOL
// ?LoadTemplate@CDocTemplate@@UAEXXZ
// name: CDocTemplate::LoadTemplate
// prototype: public: virtual void __thiscall CDocTemplate::LoadTemplate(void)

// LIBRARY: IMPERIALISM 0x0061499c SYMBOL
// ??1CDocTemplate@@UAE@XZ
// name: CDocTemplate::~CDocTemplate
// prototype: public: virtual __thiscall CDocTemplate::~CDocTemplate(void)

// LIBRARY: IMPERIALISM 0x00614a04 SYMBOL
// ?GetDocString@CDocTemplate@@UBEHAAVCString@@W4DocStringIndex@1@@Z
// name: CDocTemplate::GetDocString
// prototype: public: virtual int __thiscall CDocTemplate::GetDocString(class CString &, enum CDocTemplate::DocStringIndex) const

// LIBRARY: IMPERIALISM 0x00614a19 SYMBOL
// ?AddDocument@CDocTemplate@@UAEXPAVCDocument@@@Z
// name: CDocTemplate::AddDocument
// prototype: public: virtual void __thiscall CDocTemplate::AddDocument(class CDocument *)

// LIBRARY: IMPERIALISM 0x00614a23 SYMBOL
// ?RemoveDocument@CDocTemplate@@UAEXPAVCDocument@@@Z
// name: CDocTemplate::RemoveDocument
// prototype: public: virtual void __thiscall CDocTemplate::RemoveDocument(class CDocument *)

// LIBRARY: IMPERIALISM 0x00614a2e SYMBOL
// ?MatchDocType@CDocTemplate@@UAE?AW4Confidence@1@PBDAAPAVCDocument@@@Z
// name: CDocTemplate::MatchDocType
// prototype: public: virtual enum CDocTemplate::Confidence __thiscall CDocTemplate::MatchDocType(char const *, class CDocument *&)

// LIBRARY: IMPERIALISM 0x00614aeb SYMBOL
// ?CreateNewDocument@CDocTemplate@@UAEPAVCDocument@@XZ
// name: CDocTemplate::CreateNewDocument
// prototype: public: virtual class CDocument * __thiscall CDocTemplate::CreateNewDocument(void)

// LIBRARY: IMPERIALISM 0x00614b12 SYMBOL
// ?CreateNewFrame@CDocTemplate@@UAEPAVCFrameWnd@@PAVCDocument@@PAV2@@Z
// name: CDocTemplate::CreateNewFrame
// prototype: public: virtual class CFrameWnd * __thiscall CDocTemplate::CreateNewFrame(class CDocument *, class CFrameWnd *)

// LIBRARY: IMPERIALISM 0x00614b7b SYMBOL
// ?CreateOleFrame@CDocTemplate@@QAEPAVCFrameWnd@@PAVCWnd@@PAVCDocument@@H@Z
// name: CDocTemplate::CreateOleFrame
// prototype: public: class CFrameWnd * __thiscall CDocTemplate::CreateOleFrame(class CWnd *, class CDocument *, int)

// LIBRARY: IMPERIALISM 0x00614bef SYMBOL
// ?InitialUpdateFrame@CDocTemplate@@UAEXPAVCFrameWnd@@PAVCDocument@@H@Z
// name: CDocTemplate::InitialUpdateFrame
// prototype: public: virtual void __thiscall CDocTemplate::InitialUpdateFrame(class CFrameWnd *, class CDocument *, int)

// LIBRARY: IMPERIALISM 0x00614c03 SYMBOL
// ?SaveAllModified@CDocTemplate@@UAEHXZ
// name: CDocTemplate::SaveAllModified
// prototype: public: virtual int __thiscall CDocTemplate::SaveAllModified(void)

// LIBRARY: IMPERIALISM 0x00614c41 SYMBOL
// ?CloseAllDocuments@CDocTemplate@@UAEXH@Z
// name: CDocTemplate::CloseAllDocuments
// prototype: public: virtual void __thiscall CDocTemplate::CloseAllDocuments(int)

// LIBRARY: IMPERIALISM 0x00614c76 SYMBOL
// ?OnIdle@CDocTemplate@@UAEXXZ
// name: CDocTemplate::OnIdle
// prototype: public: virtual void __thiscall CDocTemplate::OnIdle(void)

// LIBRARY: IMPERIALISM 0x00614ca9 SYMBOL
// ?OnCmdMsg@CDocTemplate@@UAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z
// name: CDocTemplate::OnCmdMsg
// prototype: public: virtual int __thiscall CDocTemplate::OnCmdMsg(unsigned int, int, void *, struct AFX_CMDHANDLERINFO *)

// LIBRARY: IMPERIALISM 0x00614cfa SYMBOL
// ?_AfxGetMouseScrollLines@@YAIH@Z
// name: _AfxGetMouseScrollLines
// prototype: unsigned int __cdecl _AfxGetMouseScrollLines(int)

// LIBRARY: IMPERIALISM 0x00614e71 SYMBOL
// ??0CScrollView@@IAE@XZ
// name: CScrollView::CScrollView
// prototype: protected: __thiscall CScrollView::CScrollView(void)

// LIBRARY: IMPERIALISM 0x00614e98 SYMBOL
// ??_GCScrollView@@UAEPAXI@Z
// name: CScrollView::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CScrollView::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00614eb4 SYMBOL
// ??1CScrollView@@UAE@XZ
// name: CScrollView::~CScrollView
// prototype: public: virtual __thiscall CScrollView::~CScrollView(void)

// LIBRARY: IMPERIALISM 0x00614ebf SYMBOL
// ?OnPrepareDC@CScrollView@@UAEXPAVCDC@@PAUCPrintInfo@@@Z
// name: CScrollView::OnPrepareDC
// prototype: public: virtual void __thiscall CScrollView::OnPrepareDC(class CDC *, struct CPrintInfo *)

// LIBRARY: IMPERIALISM 0x00614f95 SYMBOL
// ?SetScaleToFitSize@CScrollView@@QAEXUtagSIZE@@@Z
// name: CScrollView::SetScaleToFitSize
// prototype: public: void __thiscall CScrollView::SetScaleToFitSize(struct tagSIZE)

// LIBRARY: IMPERIALISM 0x00615020 SYMBOL
// ?SetScrollSizes@CScrollView@@QAEXHUtagSIZE@@ABU2@1@Z
// name: CScrollView::SetScrollSizes
// prototype: public: void __thiscall CScrollView::SetScrollSizes(int, struct tagSIZE, struct tagSIZE const &, struct tagSIZE const &)

// LIBRARY: IMPERIALISM 0x00615152 SYMBOL
// ?GetScrollPosition@CScrollView@@QBE?AVCPoint@@XZ
// name: CScrollView::GetScrollPosition
// prototype: public: class CPoint __thiscall CScrollView::GetScrollPosition(void) const

// LIBRARY: IMPERIALISM 0x006151d6 SYMBOL
// ?ScrollToPosition@CScrollView@@QAEXUtagPOINT@@@Z
// name: CScrollView::ScrollToPosition
// prototype: public: void __thiscall CScrollView::ScrollToPosition(struct tagPOINT)

// LIBRARY: IMPERIALISM 0x00615277 SYMBOL
// ?GetDeviceScrollPosition@CScrollView@@QBE?AVCPoint@@XZ
// name: CScrollView::GetDeviceScrollPosition
// prototype: public: class CPoint __thiscall CScrollView::GetDeviceScrollPosition(void) const

// LIBRARY: IMPERIALISM 0x00615329 SYMBOL
// ?ScrollToDevicePosition@CScrollView@@IAEXUtagPOINT@@@Z
// name: CScrollView::ScrollToDevicePosition
// prototype: protected: void __thiscall CScrollView::ScrollToDevicePosition(struct tagPOINT)

// LIBRARY: IMPERIALISM 0x0061537b SYMBOL
// ?FillOutsideRect@CScrollView@@QAEXPAVCDC@@PAVCBrush@@@Z
// name: CScrollView::FillOutsideRect
// prototype: public: void __thiscall CScrollView::FillOutsideRect(class CDC *, class CBrush *)

// LIBRARY: IMPERIALISM 0x006153fe SYMBOL
// ?ResizeParentToFit@CScrollView@@QAEXH@Z
// name: CScrollView::ResizeParentToFit
// prototype: public: void __thiscall CScrollView::ResizeParentToFit(int)

// LIBRARY: IMPERIALISM 0x00615517 SYMBOL
// ?OnSize@CScrollView@@QAEXIHH@Z
// name: CScrollView::OnSize
// prototype: public: void __thiscall CScrollView::OnSize(unsigned int, int, int)

// LIBRARY: IMPERIALISM 0x0061553f SYMBOL
// ?CenterOnPoint@CScrollView@@IAEXVCPoint@@@Z
// name: CScrollView::CenterOnPoint
// prototype: protected: void __thiscall CScrollView::CenterOnPoint(class CPoint)

// LIBRARY: IMPERIALISM 0x006155ed SYMBOL
// ?GetScrollBarSizes@CScrollView@@IAEXAAVCSize@@@Z
// name: CScrollView::GetScrollBarSizes
// prototype: protected: void __thiscall CScrollView::GetScrollBarSizes(class CSize &)

// LIBRARY: IMPERIALISM 0x00615647 SYMBOL
// ?GetTrueClientSize@CScrollView@@IAEHAAVCSize@@0@Z
// name: CScrollView::GetTrueClientSize
// prototype: protected: int __thiscall CScrollView::GetTrueClientSize(class CSize &, class CSize &)

// LIBRARY: IMPERIALISM 0x006156bc SYMBOL
// ?GetScrollBarState@CScrollView@@IAEXVCSize@@AAV2@1AAVCPoint@@H@Z
// name: CScrollView::GetScrollBarState
// prototype: protected: void __thiscall CScrollView::GetScrollBarState(class CSize, class CSize &, class CSize &, class CPoint &, int)

// LIBRARY: IMPERIALISM 0x00615778 SYMBOL
// ?UpdateBars@CScrollView@@IAEXXZ
// name: CScrollView::UpdateBars
// prototype: protected: void __thiscall CScrollView::UpdateBars(void)

// LIBRARY: IMPERIALISM 0x006158ee SYMBOL
// ?CalcWindowRect@CScrollView@@UAEXPAUtagRECT@@I@Z
// name: CScrollView::CalcWindowRect
// prototype: public: virtual void __thiscall CScrollView::CalcWindowRect(struct tagRECT *, unsigned int)

// LIBRARY: IMPERIALISM 0x00615975 SYMBOL
// ?OnHScroll@CScrollView@@QAEXIIPAVCScrollBar@@@Z
// name: CScrollView::OnHScroll
// prototype: public: void __thiscall CScrollView::OnHScroll(unsigned int, unsigned int, class CScrollBar *)

// LIBRARY: IMPERIALISM 0x006159b9 SYMBOL
// ?OnVScroll@CScrollView@@QAEXIIPAVCScrollBar@@@Z
// name: CScrollView::OnVScroll
// prototype: public: void __thiscall CScrollView::OnVScroll(unsigned int, unsigned int, class CScrollBar *)

// LIBRARY: IMPERIALISM 0x00615a00 SYMBOL
// ?OnMouseWheel@CScrollView@@QAEHIFVCPoint@@@Z
// name: CScrollView::OnMouseWheel
// prototype: public: int __thiscall CScrollView::OnMouseWheel(unsigned int, short, class CPoint)

// LIBRARY: IMPERIALISM 0x00615a34 SYMBOL
// ?DoMouseWheel@CScrollView@@QAEHIFVCPoint@@@Z
// name: CScrollView::DoMouseWheel
// prototype: public: int __thiscall CScrollView::DoMouseWheel(unsigned int, short, class CPoint)

// LIBRARY: IMPERIALISM 0x00615b58 SYMBOL
// ?OnScroll@CScrollView@@UAEHIIH@Z
// name: CScrollView::OnScroll
// prototype: public: virtual int __thiscall CScrollView::OnScroll(unsigned int, unsigned int, int)

// LIBRARY: IMPERIALISM 0x00615c28 SYMBOL
// ?OnScrollBy@CScrollView@@UAEHVCSize@@H@Z
// name: CScrollView::OnScrollBy
// prototype: public: virtual int __thiscall CScrollView::OnScrollBy(class CSize, int)

// LIBRARY: IMPERIALISM 0x00615d2b SYMBOL
// ?GetErrorMessage@CArchiveException@@UAEHPADIPAI@Z
// name: CArchiveException::GetErrorMessage
// prototype: public: virtual int __thiscall CArchiveException::GetErrorMessage(char *, unsigned int, unsigned int *)

// LIBRARY: IMPERIALISM 0x00615dcb SYMBOL
// ?AfxThrowArchiveException@@YGXHPBD@Z
// name: AfxThrowArchiveException
// prototype: void __stdcall AfxThrowArchiveException(int, char const *)

// LIBRARY: IMPERIALISM 0x0061842f SYMBOL
// ?OnFileNew@CWinApp@@IAEXXZ
// name: CWinApp::OnFileNew
// prototype: protected: void __thiscall CWinApp::OnFileNew(void)

// LIBRARY: IMPERIALISM 0x0061843f
// MFC nafxcw handler in message map 0x63e068 (base 0x66fd60), ON_COMMAND
// 0xe101: `mov ecx,[ecx+0x80]; jmp [eax+0x40]` inner-object forwarder.

// LIBRARY: IMPERIALISM 0x0061844a SYMBOL
// ?DoPromptFileName@CWinApp@@QAEHAAVCString@@IKHPAVCDocTemplate@@@Z
// name: CWinApp::DoPromptFileName
// prototype: public: int __thiscall CWinApp::DoPromptFileName(class CString &, unsigned int, unsigned long, int, class CDocTemplate *)

// LIBRARY: IMPERIALISM 0x0061846b SYMBOL
// ?HideApplication@CWinApp@@QAEXXZ
// name: CWinApp::HideApplication
// prototype: public: void __thiscall CWinApp::HideApplication(void)

// LIBRARY: IMPERIALISM 0x0061849d SYMBOL
// ?DoWaitCursor@CWinApp@@UAEXH@Z
// name: CWinApp::DoWaitCursor
// prototype: public: virtual void __thiscall CWinApp::DoWaitCursor(int)

// LIBRARY: IMPERIALISM 0x006184fc SYMBOL
// ?EnableModeless@CWinApp@@QAEXH@Z
// name: CWinApp::EnableModeless
// prototype: public: void __thiscall CWinApp::EnableModeless(int)

// LIBRARY: IMPERIALISM 0x0061852a SYMBOL
// ?DoMessageBox@CWinApp@@UAEHPBDII@Z
// name: CWinApp::DoMessageBox
// prototype: public: virtual int __thiscall CWinApp::DoMessageBox(char const *, unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x006185e4 SYMBOL
// ?AfxMessageBox@@YGHPBDII@Z
// name: AfxMessageBox
// prototype: int __stdcall AfxMessageBox(char const *, unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x00618605 SYMBOL
// ?AfxMessageBox@@YGHIII@Z
// name: AfxMessageBox
// prototype: int __stdcall AfxMessageBox(unsigned int, unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x006186a4 SYMBOL
// ?SaveAllModified@CWinApp@@UAEHXZ
// name: CWinApp::SaveAllModified
// prototype: public: virtual int __thiscall CWinApp::SaveAllModified(void)

// LIBRARY: IMPERIALISM 0x006186b7 SYMBOL
// ?AddToRecentFileList@CWinApp@@UAEXPBD@Z
// name: CWinApp::AddToRecentFileList
// prototype: public: virtual void __thiscall CWinApp::AddToRecentFileList(char const *)

// LIBRARY: IMPERIALISM 0x006186f2 SYMBOL
// ?OpenDocumentFile@CWinApp@@UAEPAVCDocument@@PBD@Z
// name: CWinApp::OpenDocumentFile
// prototype: public: virtual class CDocument * __thiscall CWinApp::OpenDocumentFile(char const *)

// LIBRARY: IMPERIALISM 0x00618704 SYMBOL
// ?CloseAllDocuments@CWinApp@@QAEXH@Z
// name: CWinApp::CloseAllDocuments
// prototype: public: void __thiscall CWinApp::CloseAllDocuments(int)

// LIBRARY: IMPERIALISM 0x0061871a
// MFC nafxcw handler in message map 0x66fd60 (base CCmdTarget), ON_COMMAND
// 0xe110: control-site check via [ecx+0xa8] then command forward.

// LIBRARY: IMPERIALISM 0x0061873c SYMBOL
// ?OnDDECommand@CWinApp@@UAEHPAD@Z
// name: CWinApp::OnDDECommand
// prototype: public: virtual int __thiscall CWinApp::OnDDECommand(char *)

// LIBRARY: IMPERIALISM 0x00618756
// MFC nafxcw handler in message map 0x66fd60 (base CCmdTarget), ON_COMMAND
// 0xe110: id-range 0xe110 decode via [ecx+0xa8] control-site.

// LIBRARY: IMPERIALISM 0x0061878f SYMBOL
// ?AddDocTemplate@CWinApp@@QAEXPAVCDocTemplate@@@Z
// name: CWinApp::AddDocTemplate
// prototype: public: void __thiscall CWinApp::AddDocTemplate(class CDocTemplate *)

// LIBRARY: IMPERIALISM 0x006187eb SYMBOL
// ?GetFirstDocTemplatePosition@CWinApp@@QBEPAU__POSITION@@XZ
// name: CWinApp::GetFirstDocTemplatePosition
// prototype: public: struct __POSITION * __thiscall CWinApp::GetFirstDocTemplatePosition(void) const

// LIBRARY: IMPERIALISM 0x006187fd SYMBOL
// ?GetNextDocTemplate@CWinApp@@QBEPAVCDocTemplate@@AAPAU__POSITION@@@Z
// name: CWinApp::GetNextDocTemplate
// prototype: public: class CDocTemplate * __thiscall CWinApp::GetNextDocTemplate(struct __POSITION *&) const

// LIBRARY: IMPERIALISM 0x0061880f SYMBOL
// ?WriteProfileInt@CWinApp@@QAEHPBD0H@Z
// name: CWinApp::WriteProfileInt
// prototype: public: int __thiscall CWinApp::WriteProfileInt(char const *, char const *, int)

// LIBRARY: IMPERIALISM 0x00618884 SYMBOL
// ?WriteProfileStringA@CWinApp@@QAEHPBD00@Z
// name: CWinApp::WriteProfileStringA
// prototype: public: int __thiscall CWinApp::WriteProfileStringA(char const *, char const *, char const *)

// LIBRARY: IMPERIALISM 0x00618924 SYMBOL
// ?WriteProfileBinary@CWinApp@@QAEHPBD0PAEI@Z
// name: CWinApp::WriteProfileBinary
// prototype: public: int __thiscall CWinApp::WriteProfileBinary(char const *, char const *, unsigned char *, unsigned int)

// LIBRARY: IMPERIALISM 0x006189c5 SYMBOL
// ?PrepareEditCtrl@CDataExchange@@QAEPAUHWND__@@H@Z
// name: CDataExchange::PrepareEditCtrl
// prototype: public: struct HWND__* __thiscall CDataExchange::PrepareEditCtrl(int)

// LIBRARY: IMPERIALISM 0x006189dc SYMBOL
// ?PrepareCtrl@CDataExchange@@QAEPAUHWND__@@H@Z
// name: CDataExchange::PrepareCtrl
// prototype: public: struct HWND__* __thiscall CDataExchange::PrepareCtrl(int)

// LIBRARY: IMPERIALISM 0x00618a0b SYMBOL
// ?Fail@CDataExchange@@QAEXXZ
// name: CDataExchange::Fail
// prototype: public: void __thiscall CDataExchange::Fail(void)

// LIBRARY: IMPERIALISM 0x00618a40 SYMBOL
// ?DDX_Text@@YGXPAVCDataExchange@@HAAE@Z
// name: DDX_Text
// prototype: void __stdcall DDX_Text(class CDataExchange *, int, unsigned char &)

// LIBRARY: IMPERIALISM 0x00618ab1 SYMBOL
// ?DDX_TextWithFormat@@YAXPAVCDataExchange@@HPBDIZZ

// LIBRARY: IMPERIALISM 0x00618b21 SYMBOL
// ?AfxSimpleScanf@@YGHPBD0PAD@Z

// LIBRARY: IMPERIALISM 0x00618bc6 SYMBOL
// ?DDX_Text@@YGXPAVCDataExchange@@HAAF@Z
// name: DDX_Text
// prototype: void __stdcall DDX_Text(class CDataExchange *, int, short &)

// LIBRARY: IMPERIALISM 0x00618c01 SYMBOL
// ?DDX_Text@@YGXPAVCDataExchange@@HAAJ@Z

// LIBRARY: IMPERIALISM 0x00618c30 SYMBOL
// ?DDX_Text@@YGXPAVCDataExchange@@HAAK@Z

// LIBRARY: IMPERIALISM 0x00618c5f SYMBOL
// ?DDX_Text@@YGXPAVCDataExchange@@HAAH@Z

// LIBRARY: IMPERIALISM 0x00618c8e SYMBOL
// ?DDX_Text@@YGXPAVCDataExchange@@HAAI@Z

// LIBRARY: IMPERIALISM 0x00618cbd SYMBOL
// ?DDX_Text@@YGXPAVCDataExchange@@HAAVCString@@@Z
// name: DDX_Text
// prototype: void __stdcall DDX_Text(class CDataExchange *, int, class CString &)

// LIBRARY: IMPERIALISM 0x00618d0f SYMBOL
// ?DDX_Check@@YGXPAVCDataExchange@@HAAH@Z
// name: DDX_Check
// prototype: void __stdcall DDX_Check(class CDataExchange *, int, int &)

// LIBRARY: IMPERIALISM 0x00618d61 SYMBOL
// ?DDX_Radio@@YGXPAVCDataExchange@@HAAH@Z
// name: DDX_Radio
// prototype: void __stdcall DDX_Radio(class CDataExchange *, int, int &)

// LIBRARY: IMPERIALISM 0x00618df2
// DDX_LBString

// LIBRARY: IMPERIALISM 0x00618e72
// DDX_LBStringExact

// LIBRARY: IMPERIALISM 0x00618ec3 SYMBOL
// ?DDX_CBString@@YGXPAVCDataExchange@@HAAVCString@@@Z
// name: DDX_CBString
// prototype: void __stdcall DDX_CBString(class CDataExchange *, int, class CString &)

// LIBRARY: IMPERIALISM 0x00618f43 SYMBOL
// ?DDX_CBStringExact@@YGXPAVCDataExchange@@HAAVCString@@@Z
// name: DDX_CBStringExact
// prototype: void __stdcall DDX_CBStringExact(class CDataExchange *, int, class CString &)

// LIBRARY: IMPERIALISM 0x00618f94 SYMBOL
// ?DDX_LBIndex@@YGXPAVCDataExchange@@HAAH@Z
// name: DDX_LBIndex
// prototype: void __stdcall DDX_LBIndex(class CDataExchange *, int, int &)

// LIBRARY: IMPERIALISM 0x00618fd6 SYMBOL
// ?DDX_CBIndex@@YGXPAVCDataExchange@@HAAH@Z
// name: DDX_CBIndex
// prototype: void __stdcall DDX_CBIndex(class CDataExchange *, int, int &)

// LIBRARY: IMPERIALISM 0x00619018 SYMBOL
// ?DDX_Scroll@@YGXPAVCDataExchange@@HAAH@Z
// name: DDX_Scroll
// prototype: void __stdcall DDX_Scroll(class CDataExchange *, int, int &)

// LIBRARY: IMPERIALISM 0x00619053 SYMBOL
// ?DDV_MinMaxByte@@YGXPAVCDataExchange@@EEE@Z
// name: DDV_MinMaxByte
// prototype: void __stdcall DDV_MinMaxByte(class CDataExchange *, unsigned char, unsigned char, unsigned char)

// LIBRARY: IMPERIALISM 0x00619083 SYMBOL
// ?FailMinMaxWithFormat@@YGXPAVCDataExchange@@JJPBDI@Z

// LIBRARY: IMPERIALISM 0x00619116 SYMBOL
// ?DDV_MinMaxShort@@YGXPAVCDataExchange@@FFF@Z
// name: DDV_MinMaxShort
// prototype: void __stdcall DDV_MinMaxShort(class CDataExchange *, short, short, short)

// LIBRARY: IMPERIALISM 0x00619149 SYMBOL
// ?DDV_MinMaxLong@@YGXPAVCDataExchange@@JJJ@Z

// LIBRARY: IMPERIALISM 0x00619175 SYMBOL
// ?DDV_MinMaxLong@@YGXPAVCDataExchange@@JJJ@Z

// LIBRARY: IMPERIALISM 0x006191a1 SYMBOL
// ?DDV_MinMaxUInt@@YGXPAVCDataExchange@@III@Z

// LIBRARY: IMPERIALISM 0x006191cd SYMBOL
// ?DDV_MinMaxUInt@@YGXPAVCDataExchange@@III@Z

// LIBRARY: IMPERIALISM 0x006191f9 SYMBOL
// ?DDV_MaxChars@@YGXPAVCDataExchange@@ABVCString@@H@Z
// name: DDV_MaxChars
// prototype: void __stdcall DDV_MaxChars(class CDataExchange *, class CString const &, int)

// LIBRARY: IMPERIALISM 0x006192a1 SYMBOL
// ?DDX_Control@@YGXPAVCDataExchange@@HAAVCWnd@@@Z
// name: DDX_Control
// prototype: void __stdcall DDX_Control(class CDataExchange *, int, class CWnd &)

// LIBRARY: IMPERIALISM 0x006192ed SYMBOL
// ?AfxFailMaxChars@@YGXPAVCDataExchange@@H@Z
// name: AfxFailMaxChars
// prototype: void __stdcall AfxFailMaxChars(class CDataExchange *, int)

// LIBRARY: IMPERIALISM 0x00619365 SYMBOL
// ?AfxFailRadio@@YGXPAVCDataExchange@@@Z
// name: AfxFailRadio
// prototype: void __stdcall AfxFailRadio(class CDataExchange *)

// LIBRARY: IMPERIALISM 0x006193c5 SYMBOL
// ?OnHelp@CWnd@@QAEXXZ
// name: CWnd::OnHelp
// prototype: public: void __thiscall CWnd::OnHelp(void)

// LIBRARY: IMPERIALISM 0x00619467 SYMBOL
// ?OnHelp@CFrameWnd@@IAEXXZ
// name: CFrameWnd::OnHelp
// prototype: protected: void __thiscall CFrameWnd::OnHelp(void)

// LIBRARY: IMPERIALISM 0x006194b1
// MFC nafxcw handler in CMainFrame's message map 0x648640, ON_COMMAND
// 0xe143/0xe147: AfxGetModuleState() + [eax+4] vcall 0xa0 dispatch forwarder
// (entities name it TMacViewMgr_OnCommand_ID_E143_E147 from the map; the body
// is stock MFC dispatch machinery, not game code).

// LIBRARY: IMPERIALISM 0x006194df SYMBOL
// ?CanEnterHelpMode@CFrameWnd@@QAEHXZ

// LIBRARY: IMPERIALISM 0x00619539 SYMBOL
// ?OnContextHelp@CFrameWnd@@QAEXXZ
// name: CFrameWnd::OnContextHelp
// prototype: public: void __thiscall CFrameWnd::OnContextHelp(void)

// LIBRARY: IMPERIALISM 0x006196e1 SYMBOL
// ?SetHelpCapture@CFrameWnd@@IAEPAUHWND__@@UtagPOINT@@PAH@Z
// name: CFrameWnd::SetHelpCapture
// prototype: protected: struct HWND__* __thiscall CFrameWnd::SetHelpCapture(struct tagPOINT, int *)

// LIBRARY: IMPERIALISM 0x006197f7 SYMBOL
// ?ProcessHelpMsg@CFrameWnd@@IAEHAAUtagMSG@@PAK@Z
// name: CFrameWnd::ProcessHelpMsg
// prototype: protected: int __thiscall CFrameWnd::ProcessHelpMsg(struct tagMSG &, unsigned long *)

// LIBRARY: IMPERIALISM 0x006199fd SYMBOL
// ?MapClientArea@@YGKPAUHWND__@@UtagPOINT@@@Z

// LIBRARY: IMPERIALISM 0x00619a92 SYMBOL
// ?MapNonClientArea@@YGKH@Z

// LIBRARY: IMPERIALISM 0x00619aac SYMBOL
// ??0CMemFile@@QAE@I@Z
// name: CMemFile::CMemFile
// prototype: public: __thiscall CMemFile::CMemFile(unsigned int)

// LIBRARY: IMPERIALISM 0x00619adc SYMBOL
// ??_GCMemFile@@UAEPAXI@Z
// name: CMemFile::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CMemFile::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00619af8 SYMBOL
// ??0CMemFile@@QAE@PAEII@Z
// name: CMemFile::CMemFile
// prototype: public: __thiscall CMemFile::CMemFile(unsigned char *, unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x00619b34 SYMBOL
// ?Attach@CMemFile@@QAEXPAEII@Z
// name: CMemFile::Attach
// prototype: public: void __thiscall CMemFile::Attach(unsigned char *, unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x00619b71 SYMBOL
// ??1CMemFile@@UAE@XZ
// name: CMemFile::~CMemFile
// prototype: public: virtual __thiscall CMemFile::~CMemFile(void)

// LIBRARY: IMPERIALISM 0x00619bbd SYMBOL
// ?Alloc@CMemFile@@MAEPAEK@Z
// name: CMemFile::Alloc
// prototype: protected: virtual unsigned char * __thiscall CMemFile::Alloc(unsigned long)

// LIBRARY: IMPERIALISM 0x00619bca SYMBOL
// ?Realloc@CMemFile@@MAEPAEPAEK@Z
// name: CMemFile::Realloc
// prototype: protected: virtual unsigned char * __thiscall CMemFile::Realloc(unsigned char *, unsigned long)

// LIBRARY: IMPERIALISM 0x00619bdc SYMBOL
// ?Memcpy@CMemFile@@MAEPAEPAEPBEI@Z
// name: CMemFile::Memcpy
// prototype: protected: virtual unsigned char * __thiscall CMemFile::Memcpy(unsigned char *, unsigned char const *, unsigned int)

// LIBRARY: IMPERIALISM 0x00619c01 SYMBOL
// ?Free@CMemFile@@MAEXPAE@Z
// name: CMemFile::Free
// prototype: protected: virtual void __thiscall CMemFile::Free(unsigned char *)

// LIBRARY: IMPERIALISM 0x00619c0e SYMBOL
// ?GetPosition@CMemFile@@UBEKXZ
// name: CMemFile::GetPosition
// prototype: public: virtual unsigned long __thiscall CMemFile::GetPosition(void) const

// LIBRARY: IMPERIALISM 0x00619c12 SYMBOL
// ?GrowFile@CMemFile@@MAEXK@Z
// name: CMemFile::GrowFile
// prototype: protected: virtual void __thiscall CMemFile::GrowFile(unsigned long)

// LIBRARY: IMPERIALISM 0x00619c6b SYMBOL
// ?SetLength@CMemFile@@UAEXK@Z
// name: CMemFile::SetLength
// prototype: public: virtual void __thiscall CMemFile::SetLength(unsigned long)

// LIBRARY: IMPERIALISM 0x00619c8e SYMBOL
// ?Read@CMemFile@@UAEIPAXI@Z
// name: CMemFile::Read
// prototype: public: virtual unsigned int __thiscall CMemFile::Read(void *, unsigned int)

// LIBRARY: IMPERIALISM 0x00619ccf SYMBOL
// ?Write@CMemFile@@UAEXPBXI@Z
// name: CMemFile::Write
// prototype: public: virtual void __thiscall CMemFile::Write(void const *, unsigned int)

// LIBRARY: IMPERIALISM 0x00619d11 SYMBOL
// ?Seek@CMemFile@@UAEJJI@Z
// name: CMemFile::Seek
// prototype: public: virtual long __thiscall CMemFile::Seek(long, unsigned int)

// LIBRARY: IMPERIALISM 0x00619d57 SYMBOL
// ?Flush@CMemFile@@UAEXXZ
// name: CMemFile::Flush
// prototype: public: virtual void __thiscall CMemFile::Flush(void)

// LIBRARY: IMPERIALISM 0x00619d58 SYMBOL
// ?Close@CMemFile@@UAEXXZ
// name: CMemFile::Close
// prototype: public: virtual void __thiscall CMemFile::Close(void)

// LIBRARY: IMPERIALISM 0x00619d82 SYMBOL
// ?Abort@CMemFile@@UAEXXZ
// name: CMemFile::Abort
// prototype: public: virtual void __thiscall CMemFile::Abort(void)

// LIBRARY: IMPERIALISM 0x00619d87 SYMBOL
// ?LockRange@CMemFile@@UAEXKK@Z
// name: CMemFile::LockRange
// prototype: public: virtual void __thiscall CMemFile::LockRange(unsigned long, unsigned long)

// LIBRARY: IMPERIALISM 0x00619d8f SYMBOL
// ?UnlockRange@CMemFile@@UAEXKK@Z
// name: CMemFile::UnlockRange
// prototype: public: virtual void __thiscall CMemFile::UnlockRange(unsigned long, unsigned long)

// LIBRARY: IMPERIALISM 0x00619d97 SYMBOL
// ?Duplicate@CMemFile@@UBEPAVCFile@@XZ
// name: CMemFile::Duplicate
// prototype: public: virtual class CFile * __thiscall CMemFile::Duplicate(void) const

// LIBRARY: IMPERIALISM 0x00619d9f SYMBOL
// ?GetBufferPtr@CMemFile@@UAEIIIPAPAX0@Z
// name: CMemFile::GetBufferPtr
// prototype: public: virtual unsigned int __thiscall CMemFile::GetBufferPtr(unsigned int, unsigned int, void **, void **)

// LIBRARY: IMPERIALISM 0x00619e4e SYMBOL
// ?OnInitDialog@CNewTypeDlg@@MAEHXZ
// name: CNewTypeDlg::OnInitDialog
// prototype: protected: virtual int __thiscall CNewTypeDlg::OnInitDialog(void)

// LIBRARY: IMPERIALISM 0x00619f62 SYMBOL
// ?OnOK@CNewTypeDlg@@MAEXXZ
// name: CNewTypeDlg::OnOK
// prototype: protected: virtual void __thiscall CNewTypeDlg::OnOK(void)

// LIBRARY: IMPERIALISM 0x00619faa SYMBOL
// ?AddDocTemplate@CDocManager@@UAEXPAVCDocTemplate@@@Z
// name: CDocManager::AddDocTemplate
// prototype: public: virtual void __thiscall CDocManager::AddDocTemplate(class CDocTemplate *)

// LIBRARY: IMPERIALISM 0x0061a027 SYMBOL
// ?SaveAllModified@CDocManager@@UAEHXZ
// name: CDocManager::SaveAllModified
// prototype: public: virtual int __thiscall CDocManager::SaveAllModified(void)

// LIBRARY: IMPERIALISM 0x0061a049 SYMBOL
// ?CloseAllDocuments@CDocManager@@UAEXH@Z
// name: CDocManager::CloseAllDocuments
// prototype: public: virtual void __thiscall CDocManager::CloseAllDocuments(int)

// LIBRARY: IMPERIALISM 0x0061a06a SYMBOL
// ?DoPromptFileName@CDocManager@@UAEHAAVCString@@IKHPAVCDocTemplate@@@Z
// name: CDocManager::DoPromptFileName
// prototype: public: virtual int __thiscall CDocManager::DoPromptFileName(class CString &, unsigned int, unsigned long, int, class CDocTemplate *)

// LIBRARY: IMPERIALISM 0x0061a216 SYMBOL
// ?AppendFilterSuffix@@YAXAAVCString@@AAUtagOFNA@@PAVCDocTemplate@@PAV1@@Z

// LIBRARY: IMPERIALISM 0x0061a2ef SYMBOL
// ?OnDDECommand@CDocManager@@UAEHPAD@Z
// name: CDocManager::OnDDECommand
// prototype: public: virtual int __thiscall CDocManager::OnDDECommand(char *)

// LIBRARY: IMPERIALISM 0x0061a8dd SYMBOL
// ?OnFileNew@CDocManager@@UAEXXZ
// name: CDocManager::OnFileNew
// prototype: public: virtual void __thiscall CDocManager::OnFileNew(void)

// LIBRARY: IMPERIALISM 0x0061a982 SYMBOL
// ??1CNewTypeDlg@@UAE@XZ
// name: CNewTypeDlg::~CNewTypeDlg
// prototype: public: virtual __thiscall CNewTypeDlg::~CNewTypeDlg(void)

// LIBRARY: IMPERIALISM 0x0061a98d SYMBOL
// ??_GCNewTypeDlg@@UAEPAXI@Z
// name: CNewTypeDlg::`scalar deleting destructor'
// prototype: public: virtual void * __thiscall CNewTypeDlg::`scalar deleting destructor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0061a9a9 SYMBOL
// ?OnFileOpen@CDocManager@@UAEXXZ
// name: CDocManager::OnFileOpen
// prototype: public: virtual void __thiscall CDocManager::OnFileOpen(void)

// LIBRARY: IMPERIALISM 0x0061aa0e SYMBOL
// ?AfxFormatStrings@@YGXAAVCString@@IPBQBDH@Z
// name: AfxFormatStrings
// prototype: void __stdcall AfxFormatStrings(class CString &, unsigned int, char const *const *, int)

// LIBRARY: IMPERIALISM 0x0061aa48 SYMBOL
// ?AfxFormatStrings@@YGXAAVCString@@PBDPBQBDH@Z
// name: AfxFormatStrings
// prototype: void __stdcall AfxFormatStrings(class CString &, char const *, char const *const *, int)

// LIBRARY: IMPERIALISM 0x0061ab47 SYMBOL
// ?AfxFormatString1@@YGXAAVCString@@IPBD@Z
// name: AfxFormatString1
// prototype: void __stdcall AfxFormatString1(class CString &, unsigned int, char const *)

// LIBRARY: IMPERIALISM 0x0061ab5e SYMBOL
// ?AfxFormatString2@@YGXAAVCString@@IPBD1@Z
// name: AfxFormatString2
// prototype: void __stdcall AfxFormatString2(class CString &, unsigned int, char const *, char const *)

// LIBRARY: IMPERIALISM 0x0061c55e
// ResetMouseWheelTrackingGlobals
// prototype: void __cdecl ResetMouseWheelTrackingGlobals(void)

// LIBRARY: IMPERIALISM 0x0061c581
// RegisterMouseWheelRollMessageForLegacyWindows
// prototype: void __cdecl RegisterMouseWheelRollMessageForLegacyWindows(void)

// LIBRARY: IMPERIALISM 0x0061c5dc SYMBOL
// ??0CFrameWnd@@QAE@XZ
// name: CFrameWnd::CFrameWnd
// prototype: public: __thiscall CFrameWnd::CFrameWnd(void)

// LIBRARY: IMPERIALISM 0x0061c6a2 SYMBOL
// ??_GCFrameWnd@@UAEPAXI@Z
// name: CFrameWnd::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CFrameWnd::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0061c6be SYMBOL
// ??1CFrameWnd@@UAE@XZ
// name: CFrameWnd::~CFrameWnd
// prototype: public: virtual __thiscall CFrameWnd::~CFrameWnd(void)

// LIBRARY: IMPERIALISM 0x0061c725 SYMBOL
// ?AddFrameWnd@CFrameWnd@@IAEXXZ
// name: CFrameWnd::AddFrameWnd
// prototype: protected: void __thiscall CFrameWnd::AddFrameWnd(void)

// LIBRARY: IMPERIALISM 0x0061c749 SYMBOL
// ?RemoveFrameWnd@CFrameWnd@@IAEXXZ
// name: CFrameWnd::RemoveFrameWnd
// prototype: protected: void __thiscall CFrameWnd::RemoveFrameWnd(void)

// LIBRARY: IMPERIALISM 0x0061c76d SYMBOL
// ?LoadAccelTable@CFrameWnd@@QAEHPBD@Z
// name: CFrameWnd::LoadAccelTable
// prototype: public: int __thiscall CFrameWnd::LoadAccelTable(char const *)

// LIBRARY: IMPERIALISM 0x0061c793 SYMBOL
// ?GetDefaultAccelerator@CFrameWnd@@UAEPAUHACCEL__@@XZ
// name: CFrameWnd::GetDefaultAccelerator
// prototype: public: virtual struct HACCEL__* __thiscall CFrameWnd::GetDefaultAccelerator(void)

// LIBRARY: IMPERIALISM 0x0061c7b7 SYMBOL
// ?PreTranslateMessage@CFrameWnd@@UAEHPAUtagMSG@@@Z
// name: CFrameWnd::PreTranslateMessage
// prototype: public: virtual int __thiscall CFrameWnd::PreTranslateMessage(struct tagMSG *)

// LIBRARY: IMPERIALISM 0x0061c82e SYMBOL
// ?PostNcDestroy@CFrameWnd@@MAEXXZ
// name: CFrameWnd::PostNcDestroy
// prototype: protected: virtual void __thiscall CFrameWnd::PostNcDestroy(void)

// LIBRARY: IMPERIALISM 0x0061c83a SYMBOL
// ?OnPaletteChanged@CFrameWnd@@IAEXPAVCWnd@@@Z
// name: CFrameWnd::OnPaletteChanged
// prototype: protected: void __thiscall CFrameWnd::OnPaletteChanged(class CWnd *)

// LIBRARY: IMPERIALISM 0x0061c856 SYMBOL
// ?OnQueryNewPalette@CFrameWnd@@IAEHXZ
// name: CFrameWnd::OnQueryNewPalette
// prototype: protected: int __thiscall CFrameWnd::OnQueryNewPalette(void)

// LIBRARY: IMPERIALISM 0x0061c877 SYMBOL
// ?ExitHelpMode@CFrameWnd@@UAEXXZ
// name: CFrameWnd::ExitHelpMode
// prototype: public: virtual void __thiscall CFrameWnd::ExitHelpMode(void)

// LIBRARY: IMPERIALISM 0x0061c8e2 SYMBOL
// ?OnSetCursor@CFrameWnd@@IAEHPAVCWnd@@II@Z
// name: CFrameWnd::OnSetCursor
// prototype: protected: int __thiscall CFrameWnd::OnSetCursor(class CWnd *, unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x0061c90c SYMBOL
// ?OnCommandHelp@CFrameWnd@@IAEJIJ@Z
// name: CFrameWnd::OnCommandHelp
// prototype: protected: long __thiscall CFrameWnd::OnCommandHelp(unsigned int, long)

// LIBRARY: IMPERIALISM 0x0061c976 SYMBOL
// ?OnCommand@CFrameWnd@@MAEHIJ@Z
// name: CFrameWnd::OnCommand
// prototype: protected: virtual int __thiscall CFrameWnd::OnCommand(unsigned int, long)

// LIBRARY: IMPERIALISM 0x0061c9ed SYMBOL
// ?AfxIsDescendant@@YGHPAUHWND__@@0@Z
// name: AfxIsDescendant
// prototype: int __stdcall AfxIsDescendant(struct HWND__*, struct HWND__*)

// LIBRARY: IMPERIALISM 0x0061ca0d SYMBOL
// ?BeginModalState@CFrameWnd@@UAEXXZ
// name: CFrameWnd::BeginModalState
// prototype: public: virtual void __thiscall CFrameWnd::BeginModalState(void)

// LIBRARY: IMPERIALISM 0x0061cb3a SYMBOL
// ?EndModalState@CFrameWnd@@UAEXXZ
// name: CFrameWnd::EndModalState
// prototype: public: virtual void __thiscall CFrameWnd::EndModalState(void)

// LIBRARY: IMPERIALISM 0x0061cba9 SYMBOL
// ?ShowOwnedWindows@CFrameWnd@@QAEXH@Z
// name: CFrameWnd::ShowOwnedWindows
// prototype: public: void __thiscall CFrameWnd::ShowOwnedWindows(int)

// LIBRARY: IMPERIALISM 0x0061cc4b SYMBOL
// ?OnEnable@CFrameWnd@@IAEXH@Z
// name: CFrameWnd::OnEnable
// prototype: protected: void __thiscall CFrameWnd::OnEnable(int)

// LIBRARY: IMPERIALISM 0x0061cd09 SYMBOL
// ?NotifyFloatingWindows@CFrameWnd@@QAEXK@Z
// name: CFrameWnd::NotifyFloatingWindows
// prototype: public: void __thiscall CFrameWnd::NotifyFloatingWindows(unsigned long)

// LIBRARY: IMPERIALISM 0x0061cdb3 SYMBOL
// ?PreCreateWindow@CFrameWnd@@MAEHAAUtagCREATESTRUCTA@@@Z
// name: CFrameWnd::PreCreateWindow
// prototype: protected: virtual int __thiscall CFrameWnd::PreCreateWindow(struct tagCREATESTRUCTA &)

// LIBRARY: IMPERIALISM 0x0061ce0b SYMBOL
// ?Create@CFrameWnd@@QAEHPBD0KABUtagRECT@@PAVCWnd@@0KPAUCCreateContext@@@Z
// name: CFrameWnd::Create
// prototype: public: int __thiscall CFrameWnd::Create(char const *, char const *, unsigned long, struct tagRECT const &, class CWnd *, char const *, unsigned long, struct CCreateContext *)

// LIBRARY: IMPERIALISM 0x0061cea3 SYMBOL
// ?CreateView@CFrameWnd@@QAEPAVCWnd@@PAUCCreateContext@@I@Z
// name: CFrameWnd::CreateView
// prototype: public: class CWnd * __thiscall CFrameWnd::CreateView(struct CCreateContext *, unsigned int)

// LIBRARY: IMPERIALISM 0x0061cf1b SYMBOL
// ?OnCreateClient@CFrameWnd@@MAEHPAUtagCREATESTRUCTA@@PAUCCreateContext@@@Z
// name: CFrameWnd::OnCreateClient
// prototype: protected: virtual int __thiscall CFrameWnd::OnCreateClient(struct tagCREATESTRUCTA *, struct CCreateContext *)

// LIBRARY: IMPERIALISM 0x0061cf3d SYMBOL
// ?OnCreate@CFrameWnd@@IAEHPAUtagCREATESTRUCTA@@@Z
// name: CFrameWnd::OnCreate
// prototype: protected: int __thiscall CFrameWnd::OnCreate(struct tagCREATESTRUCTA *)

// LIBRARY: IMPERIALISM 0x0061cf4c SYMBOL
// ?OnCreateHelper@CFrameWnd@@IAEHPAUtagCREATESTRUCTA@@PAUCCreateContext@@@Z
// name: CFrameWnd::OnCreateHelper
// prototype: protected: int __thiscall CFrameWnd::OnCreateHelper(struct tagCREATESTRUCTA *, struct CCreateContext *)

// LIBRARY: IMPERIALISM 0x0061cf9b SYMBOL
// ?GetIconWndClass@CFrameWnd@@IAEPBDKI@Z
// name: CFrameWnd::GetIconWndClass
// prototype: protected: char const * __thiscall CFrameWnd::GetIconWndClass(unsigned long, unsigned int)

// LIBRARY: IMPERIALISM 0x0061d01e SYMBOL
// ?LoadFrame@CFrameWnd@@UAEHIKPAVCWnd@@PAUCCreateContext@@@Z
// name: CFrameWnd::LoadFrame
// prototype: public: virtual int __thiscall CFrameWnd::LoadFrame(unsigned int, unsigned long, class CWnd *, struct CCreateContext *)

// LIBRARY: IMPERIALISM 0x0061d109 SYMBOL
// ?OnUpdateFrameMenu@CFrameWnd@@UAEXPAUHMENU__@@@Z
// name: CFrameWnd::OnUpdateFrameMenu
// prototype: public: virtual void __thiscall CFrameWnd::OnUpdateFrameMenu(struct HMENU__*)

// LIBRARY: IMPERIALISM 0x0061d143 SYMBOL
// ?InitialUpdateFrame@CFrameWnd@@QAEXPAVCDocument@@H@Z
// name: CFrameWnd::InitialUpdateFrame
// prototype: public: void __thiscall CFrameWnd::InitialUpdateFrame(class CDocument *, int)

// LIBRARY: IMPERIALISM 0x0061d205 SYMBOL
// ?OnClose@CFrameWnd@@IAEXXZ
// name: CFrameWnd::OnClose
// prototype: protected: void __thiscall CFrameWnd::OnClose(void)

// LIBRARY: IMPERIALISM 0x0061d30e SYMBOL
// ?OnDestroy@CFrameWnd@@IAEXXZ
// name: CFrameWnd::OnDestroy
// prototype: protected: void __thiscall CFrameWnd::OnDestroy(void)

// LIBRARY: IMPERIALISM 0x0061d37e SYMBOL
// ?OnCmdMsg@CFrameWnd@@UAEHIHPAXPAUAFX_CMDHANDLERINFO@@@Z
// name: CFrameWnd::OnCmdMsg
// prototype: public: virtual int __thiscall CFrameWnd::OnCmdMsg(unsigned int, int, void *, struct AFX_CMDHANDLERINFO *)

// LIBRARY: IMPERIALISM 0x0061d4b8 SYMBOL
// ?OnActivate@CFrameWnd@@IAEXIPAVCWnd@@H@Z
// name: CFrameWnd::OnActivate
// prototype: protected: void __thiscall CFrameWnd::OnActivate(unsigned int, class CWnd *, int)

// LIBRARY: IMPERIALISM 0x0061d58c SYMBOL
// ?OnNcActivate@CFrameWnd@@IAEHH@Z
// name: CFrameWnd::OnNcActivate
// prototype: protected: int __thiscall CFrameWnd::OnNcActivate(int)

// LIBRARY: IMPERIALISM 0x0061d5c3 SYMBOL
// ?OnSysCommand@CFrameWnd@@IAEXIJ@Z
// name: CFrameWnd::OnSysCommand
// prototype: protected: void __thiscall CFrameWnd::OnSysCommand(unsigned int, long)

// LIBRARY: IMPERIALISM 0x0061d65a SYMBOL
// ?OnDropFiles@CFrameWnd@@IAEXPAUHDROP__@@@Z
// name: CFrameWnd::OnDropFiles
// prototype: protected: void __thiscall CFrameWnd::OnDropFiles(struct HDROP__*)

// LIBRARY: IMPERIALISM 0x0061d6d5 SYMBOL
// ?OnQueryEndSession@CFrameWnd@@IAEHXZ
// name: CFrameWnd::OnQueryEndSession
// prototype: protected: int __thiscall CFrameWnd::OnQueryEndSession(void)

// LIBRARY: IMPERIALISM 0x0061d6f6 SYMBOL
// ?OnEndSession@CFrameWnd@@IAEXH@Z
// name: CFrameWnd::OnEndSession
// prototype: protected: void __thiscall CFrameWnd::OnEndSession(int)

// LIBRARY: IMPERIALISM 0x0061d72a SYMBOL
// ?OnDDEInitiate@CFrameWnd@@IAEJIJ@Z
// name: CFrameWnd::OnDDEInitiate
// prototype: protected: long __thiscall CFrameWnd::OnDDEInitiate(unsigned int, long)

// LIBRARY: IMPERIALISM 0x0061d7e5 SYMBOL
// ?OnDDEExecute@CFrameWnd@@IAEJIJ@Z
// name: CFrameWnd::OnDDEExecute
// prototype: protected: long __thiscall CFrameWnd::OnDDEExecute(unsigned int, long)

// LIBRARY: IMPERIALISM 0x0061d89b SYMBOL
// ?GetActiveView@CFrameWnd@@QBEPAVCView@@XZ
// name: CFrameWnd::GetActiveView
// prototype: public: class CView * __thiscall CFrameWnd::GetActiveView(void) const

// LIBRARY: IMPERIALISM 0x0061d8a2 SYMBOL
// ?SetActiveView@CFrameWnd@@QAEXPAVCView@@H@Z
// name: CFrameWnd::SetActiveView
// prototype: public: void __thiscall CFrameWnd::SetActiveView(class CView *, int)

// LIBRARY: IMPERIALISM 0x0061d917 SYMBOL
// ?GetActiveDocument@CFrameWnd@@UAEPAVCDocument@@XZ
// name: CFrameWnd::GetActiveDocument
// prototype: public: virtual class CDocument * __thiscall CFrameWnd::GetActiveDocument(void)

// LIBRARY: IMPERIALISM 0x0061d927 SYMBOL
// ?ShowControlBar@CFrameWnd@@QAEXPAVCControlBar@@HH@Z
// name: CFrameWnd::ShowControlBar
// prototype: public: void __thiscall CFrameWnd::ShowControlBar(class CControlBar *, int, int)

// LIBRARY: IMPERIALISM 0x0061da22 SYMBOL
// ?OnInitMenuPopup@CFrameWnd@@IAEXPAVCMenu@@IH@Z
// name: CFrameWnd::OnInitMenuPopup
// prototype: protected: void __thiscall CFrameWnd::OnInitMenuPopup(class CMenu *, unsigned int, int)

// LIBRARY: IMPERIALISM 0x0061db87 SYMBOL
// ?OnMenuSelect@CFrameWnd@@IAEXIIPAUHMENU__@@@Z
// name: CFrameWnd::OnMenuSelect
// prototype: protected: void __thiscall CFrameWnd::OnMenuSelect(unsigned int, unsigned int, struct HMENU__*)

// LIBRARY: IMPERIALISM 0x0061dc76 SYMBOL
// ?GetMessageString@CFrameWnd@@UBEXIAAVCString@@@Z
// name: CFrameWnd::GetMessageString
// prototype: public: virtual void __thiscall CFrameWnd::GetMessageString(unsigned int, class CString &) const

// LIBRARY: IMPERIALISM 0x0061dcdd SYMBOL
// ?OnSetMessageString@CFrameWnd@@IAEJIJ@Z
// name: CFrameWnd::OnSetMessageString
// prototype: protected: long __thiscall CFrameWnd::OnSetMessageString(unsigned int, long)

// LIBRARY: IMPERIALISM 0x0061ddb2 SYMBOL
// ?GetMessageBar@CFrameWnd@@UAEPAVCWnd@@XZ
// name: CFrameWnd::GetMessageBar
// prototype: public: virtual class CWnd * __thiscall CFrameWnd::GetMessageBar(void)

// LIBRARY: IMPERIALISM 0x0061ddc2 SYMBOL
// ?OnEnterIdle@CFrameWnd@@IAEXIPAVCWnd@@@Z
// name: CFrameWnd::OnEnterIdle
// prototype: protected: void __thiscall CFrameWnd::OnEnterIdle(unsigned int, class CWnd *)

// LIBRARY: IMPERIALISM 0x0061de0a SYMBOL
// ?SetMessageText@CFrameWnd@@QAEXI@Z
// name: CFrameWnd::SetMessageText
// prototype: public: void __thiscall CFrameWnd::SetMessageText(unsigned int)

// LIBRARY: IMPERIALISM 0x0061de21 SYMBOL
// ?DestroyDockBars@CFrameWnd@@QAEXXZ
// name: CFrameWnd::DestroyDockBars
// prototype: public: void __thiscall CFrameWnd::DestroyDockBars(void)

// LIBRARY: IMPERIALISM 0x0061df4c SYMBOL
// ?OnToolTipText@CFrameWnd@@IAEHIPAUtagNMHDR@@PAJ@Z
// name: CFrameWnd::OnToolTipText
// prototype: protected: int __thiscall CFrameWnd::OnToolTipText(unsigned int, struct tagNMHDR *, long *)

// LIBRARY: IMPERIALISM 0x0061e08e SYMBOL
// ?OnUpdateContextHelp@CFrameWnd@@IAEXPAVCCmdUI@@@Z
// name: CFrameWnd::OnUpdateContextHelp
// prototype: protected: void __thiscall CFrameWnd::OnUpdateContextHelp(class CCmdUI *)

// LIBRARY: IMPERIALISM 0x0061e0bd SYMBOL
// ?OnUpdateFrameTitle@CFrameWnd@@UAEXH@Z

// LIBRARY: IMPERIALISM 0x0061e101 SYMBOL
// ?UpdateFrameTitleForDocument@CFrameWnd@@IAEXPBD@Z
// name: CFrameWnd::UpdateFrameTitleForDocument
// prototype: protected: void __thiscall CFrameWnd::UpdateFrameTitleForDocument(char const *)

// LIBRARY: IMPERIALISM 0x0061e1fe SYMBOL
// ?OnSetPreviewMode@CFrameWnd@@UAEXHPAUCPrintPreviewState@@@Z
// name: CFrameWnd::OnSetPreviewMode
// prototype: public: virtual void __thiscall CFrameWnd::OnSetPreviewMode(int, struct CPrintPreviewState *)

// LIBRARY: IMPERIALISM 0x0061e419 SYMBOL
// ?DelayUpdateFrameMenu@CFrameWnd@@UAEXPAUHMENU__@@@Z
// name: CFrameWnd::DelayUpdateFrameMenu
// prototype: public: virtual void __thiscall CFrameWnd::DelayUpdateFrameMenu(struct HMENU__ *)

// LIBRARY: IMPERIALISM 0x0061e42d SYMBOL
// ?OnIdleUpdateCmdUI@CFrameWnd@@IAEXXZ
// name: CFrameWnd::OnIdleUpdateCmdUI
// prototype: protected: void __thiscall CFrameWnd::OnIdleUpdateCmdUI(void)

// LIBRARY: IMPERIALISM 0x0061e49c SYMBOL
// ?GetActiveFrame@CFrameWnd@@UAEPAV1@XZ
// name: CFrameWnd::GetActiveFrame
// prototype: public: virtual class CFrameWnd * __thiscall CFrameWnd::GetActiveFrame(void)

// LIBRARY: IMPERIALISM 0x0061e49f SYMBOL
// ?RecalcLayout@CFrameWnd@@UAEXH@Z
// name: CFrameWnd::RecalcLayout
// prototype: public: virtual void __thiscall CFrameWnd::RecalcLayout(int)

// LIBRARY: IMPERIALISM 0x0061e58c SYMBOL
// ?NegotiateBorderSpace@CFrameWnd@@UAEHIPAUtagRECT@@@Z
// name: CFrameWnd::NegotiateBorderSpace
// prototype: public: virtual int __thiscall CFrameWnd::NegotiateBorderSpace(unsigned int, struct tagRECT *)

// LIBRARY: IMPERIALISM 0x0061e606 SYMBOL
// ?OnSize@CFrameWnd@@IAEXIHH@Z
// name: CFrameWnd::OnSize
// prototype: protected: void __thiscall CFrameWnd::OnSize(unsigned int, int, int)

// LIBRARY: IMPERIALISM 0x0061e63b SYMBOL
// ?OnRegisteredMouseWheel@CFrameWnd@@IAEJIJ@Z
// name: CFrameWnd::OnRegisteredMouseWheel
// prototype: protected: long __thiscall CFrameWnd::OnRegisteredMouseWheel(unsigned int, long)

// LIBRARY: IMPERIALISM 0x0061e6e3 SYMBOL
// ?ActivateFrame@CFrameWnd@@UAEXH@Z
// name: CFrameWnd::ActivateFrame
// prototype: public: virtual void __thiscall CFrameWnd::ActivateFrame(int)

// LIBRARY: IMPERIALISM 0x0061e733 SYMBOL
// ?BringToTop@CFrameWnd@@IAEXH@Z

// LIBRARY: IMPERIALISM 0x0061e762 SYMBOL
// ?GetDockingFrame@CControlBar@@QBEPAVCFrameWnd@@XZ
// name: CControlBar::GetDockingFrame
// prototype: public: class CFrameWnd * __thiscall CControlBar::GetDockingFrame(void) const

// LIBRARY: IMPERIALISM 0x0061e773 SYMBOL
// ?IsFloating@CControlBar@@QBEHXZ
// name: CControlBar::IsFloating
// prototype: public: int __thiscall CControlBar::IsFloating(void) const

// LIBRARY: IMPERIALISM 0x0061e79d SYMBOL
// ?Create@CButton@@QAEHPBDKABUtagRECT@@PAVCWnd@@I@Z

// LIBRARY: IMPERIALISM 0x0061e7bf SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x0061e7f7 SYMBOL
// ?Create@CButton@@QAEHPBDKABUtagRECT@@PAVCWnd@@I@Z

// LIBRARY: IMPERIALISM 0x0061e819
// CProgressCtrl::~CHotKeyCtrl

// LIBRARY: IMPERIALISM 0x0061e851 SYMBOL
// ?GetCheckedRadioButton@CWnd@@QAEHHH@Z
// name: CWnd::GetCheckedRadioButton
// prototype: public: int __thiscall CWnd::GetCheckedRadioButton(int, int)

// LIBRARY: IMPERIALISM 0x0061e87c SYMBOL
// ?OnChildNotify@CListCtrl@@MAEHIIJPAJ@Z

// LIBRARY: IMPERIALISM 0x0061e8cb
// Dtor_CListBox_61e8cb

// LIBRARY: IMPERIALISM 0x0061e911 SYMBOL
// ?VKeyToItem@CListBox@@UAEHII@Z
// name: CListBox::VKeyToItem
// prototype: public: virtual int __thiscall CListBox::VKeyToItem(unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x0061e919 SYMBOL
// ?CharToItem@CListBox@@UAEHII@Z
// name: CListBox::CharToItem
// prototype: public: virtual int __thiscall CListBox::CharToItem(unsigned int, unsigned int)

// LIBRARY: IMPERIALISM 0x0061e921 SYMBOL
// ?OnChildNotify@CListBox@@MAEHIIJPAJ@Z
// name: CListBox::OnChildNotify
// prototype: protected: virtual int __thiscall CListBox::OnChildNotify(unsigned int, unsigned int, long, long *)

// LIBRARY: IMPERIALISM 0x0061e9ba SYMBOL
// ?GetText@CListBox@@QBEXHAAVCString@@@Z
// name: CListBox::GetText
// prototype: public: void __thiscall CListBox::GetText(int, class CString &) const

// LIBRARY: IMPERIALISM 0x0061ea56 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x0061ea9c SYMBOL
// ?OnChildNotify@CComboBox@@MAEHIIJPAJ@Z
// name: CComboBox::OnChildNotify
// prototype: protected: virtual int __thiscall CComboBox::OnChildNotify(unsigned int, unsigned int, long, long *)

// LIBRARY: IMPERIALISM 0x0061eb46 SYMBOL
// ?Create@CComboBox@@QAEHKABUtagRECT@@PAVCWnd@@I@Z
// name: CComboBox::Create
// prototype: public: int __thiscall CComboBox::Create(unsigned long, struct tagRECT const &, class CWnd *, unsigned int)

// LIBRARY: IMPERIALISM 0x0061eb67 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x0061ebc0 SYMBOL
// ??1CProgressCtrl@@UAE@XZ

// LIBRARY: IMPERIALISM 0x0061ebf8
// InitializeMfcDcHandleMapThreadLocal
// prototype: void __cdecl InitializeMfcDcHandleMapThreadLocal(void)

// SYNTHETIC: IMPERIALISM 0x0061ec02
// InitializeMfcDcHandleMapPointerState
// prototype: void __cdecl InitializeMfcDcHandleMapPointerState(void)

// SYNTHETIC: IMPERIALISM 0x0061ec03
// RegisterMfcGlobalCleanup_0061ec0f
// prototype: void __cdecl RegisterMfcGlobalCleanup_0061ec0f(void)

// SYNTHETIC: IMPERIALISM 0x0061ec0f
// DestroyMfcDcHandleMapPointerStateAtExit
// prototype: void __cdecl DestroyMfcDcHandleMapPointerStateAtExit(void)

// LIBRARY: IMPERIALISM 0x0061ec1a SYMBOL
// ?DPtoHIMETRIC@CDC@@QBEXPAUtagSIZE@@@Z
// name: CDC::DPtoHIMETRIC
// prototype: public: void __thiscall CDC::DPtoHIMETRIC(struct tagSIZE *) const

// LIBRARY: IMPERIALISM 0x0061ecab SYMBOL
// ?HIMETRICtoDP@CDC@@QBEXPAUtagSIZE@@@Z
// name: CDC::HIMETRICtoDP
// prototype: public: void __thiscall CDC::HIMETRICtoDP(struct tagSIZE *) const

// LIBRARY: IMPERIALISM 0x0061ed3c SYMBOL
// ?LPtoHIMETRIC@CDC@@QBEXPAUtagSIZE@@@Z
// name: CDC::LPtoHIMETRIC
// prototype: public: void __thiscall CDC::LPtoHIMETRIC(struct tagSIZE *) const

// LIBRARY: IMPERIALISM 0x0061ed57 SYMBOL
// ?HIMETRICtoLP@CDC@@QBEXPAUtagSIZE@@@Z
// name: CDC::HIMETRICtoLP
// prototype: public: void __thiscall CDC::HIMETRICtoLP(struct tagSIZE *) const

// LIBRARY: IMPERIALISM 0x0061ed72 SYMBOL
// ?GetHalftoneBrush@CDC@@SGPAVCBrush@@XZ
// name: CDC::GetHalftoneBrush
// prototype: public: static class CBrush * __stdcall CDC::GetHalftoneBrush(void)

// LIBRARY: IMPERIALISM 0x0061ede5 SYMBOL
// ?DrawDragRect@CDC@@QAEXPBUtagRECT@@UtagSIZE@@01PAVCBrush@@2@Z
// name: CDC::DrawDragRect
// prototype: public: void __thiscall CDC::DrawDragRect(struct tagRECT const *, struct tagSIZE, struct tagRECT const *, struct tagSIZE, class CBrush *, class CBrush *)

// LIBRARY: IMPERIALISM 0x0061f0fa SYMBOL
// ?FillSolidRect@CDC@@QAEXPBUtagRECT@@K@Z
// name: FillSolidRect
// prototype: void __thiscall CDC::FillSolidRect(tagRECT * param_1, ulong param_2)

// LIBRARY: IMPERIALISM 0x0061f124 SYMBOL
// ?FillSolidRect@CDC@@QAEXHHHHK@Z
// name: CDC::FillSolidRect
// prototype: public: void __thiscall CDC::FillSolidRect(int, int, int, int, unsigned long)

// LIBRARY: IMPERIALISM 0x0061f19b SYMBOL
// ?Draw3dRect@CDC@@QAEXHHHHKK@Z
// name: CDC::Draw3dRect
// prototype: public: void __thiscall CDC::Draw3dRect(int, int, int, int, unsigned long, unsigned long)

// LIBRARY: IMPERIALISM 0x0061f205 SYMBOL
// ?CreatePointFont@CFont@@QAEHHPBDPAVCDC@@@Z
// name: CFont::CreatePointFont
// prototype: public: int __thiscall CFont::CreatePointFont(int, char const *, class CDC *)

// LIBRARY: IMPERIALISM 0x0061f24a SYMBOL
// ?CreatePointFontIndirect@CFont@@QAEHPBUtagLOGFONTA@@PAVCDC@@@Z
// name: CFont::CreatePointFontIndirect
// prototype: public: int __thiscall CFont::CreatePointFontIndirect(struct tagLOGFONTA const *, class CDC *)

// LIBRARY: IMPERIALISM 0x0061f307 SYMBOL
// ?InflateRect@CRect@@QAEXPBUtagRECT@@@Z
// name: CRect::InflateRect
// prototype: public: void __thiscall CRect::InflateRect(struct tagRECT const *)

// LIBRARY: IMPERIALISM 0x0061f342 SYMBOL
// ?DeflateRect@CRect@@QAEXPBUtagRECT@@@Z
// name: CRect::DeflateRect
// prototype: public: void __thiscall CRect::DeflateRect(struct tagRECT const *)

// LIBRARY: IMPERIALISM 0x0061f37d SYMBOL
// ?MulDiv@CRect@@QBE?AV1@HH@Z
// name: CRect::MulDiv
// prototype: public: class CRect __thiscall CRect::MulDiv(int, int) const

// LIBRARY: IMPERIALISM 0x0061f423 SYMBOL
// ?AfxOleCanExitApp@@YGHXZ
// name: AfxOleCanExitApp
// prototype: int __stdcall AfxOleCanExitApp(void)

// LIBRARY: IMPERIALISM 0x0061f45c SYMBOL
// ?AfxOleSetUserCtrl@@YGXH@Z
// name: AfxOleSetUserCtrl
// prototype: void __stdcall AfxOleSetUserCtrl(int)

// LIBRARY: IMPERIALISM 0x0061f46b SYMBOL
// ?AfxOleGetUserCtrl@@YGHXZ
// name: AfxOleGetUserCtrl
// prototype: int __stdcall AfxOleGetUserCtrl(void)

// LIBRARY: IMPERIALISM 0x0062103a SYMBOL
// ?OutputString@CDumpContext@@IAEXPBD@Z
// name: CDumpContext::OutputString
// prototype: protected: void __thiscall CDumpContext::OutputString(char const *)

// LIBRARY: IMPERIALISM 0x00621089 SYMBOL
// ??6CDumpContext@@QAEAAV0@PBD@Z
// name: CDumpContext::operator<<
// prototype: public: class CDumpContext & __thiscall CDumpContext::operator<<(char const *)

// LIBRARY: IMPERIALISM 0x00621112 SYMBOL
// ??6CDumpContext@@QAEAAV0@E@Z
// name: CDumpContext::operator<<
// prototype: public: class CDumpContext & __thiscall CDumpContext::operator<<(unsigned char)

// LIBRARY: IMPERIALISM 0x00621144 SYMBOL
// ??6CDumpContext@@QAEAAV0@G@Z
// name: CDumpContext::operator<<
// prototype: public: class CDumpContext & __thiscall CDumpContext::operator<<(unsigned short)

// LIBRARY: IMPERIALISM 0x00621176 SYMBOL
// ??6CDumpContext@@QAEAAV0@H@Z

// LIBRARY: IMPERIALISM 0x006211a6 SYMBOL
// ??6CDumpContext@@QAEAAV0@I@Z

// LIBRARY: IMPERIALISM 0x006211d6 SYMBOL
// ??6CDumpContext@@QAEAAV0@J@Z

// LIBRARY: IMPERIALISM 0x00621206 SYMBOL
// ??6CDumpContext@@QAEAAV0@K@Z

// LIBRARY: IMPERIALISM 0x00621236 SYMBOL
// ??6CDumpContext@@QAEAAV0@PBVCObject@@@Z
// name: CDumpContext::operator<<
// prototype: public: class CDumpContext & __thiscall CDumpContext::operator<<(class CObject const *)

// LIBRARY: IMPERIALISM 0x00621267 SYMBOL
// ??6CDumpContext@@QAEAAV0@ABVCObject@@@Z

// LIBRARY: IMPERIALISM 0x00621297 SYMBOL
// ?HexDump@CDumpContext@@QAEXPBDPAEHH@Z
// name: CDumpContext::HexDump
// prototype: public: void __thiscall CDumpContext::HexDump(char const *, unsigned char *, int, int)

// LIBRARY: IMPERIALISM 0x0062132a SYMBOL
// ??6CDumpContext@@QAEAAV0@PBG@Z
// name: CDumpContext::operator<<
// prototype: public: class CDumpContext & __thiscall CDumpContext::operator<<(unsigned short const *)

// LIBRARY: IMPERIALISM 0x00622442 SYMBOL
// ?GetRuntimeClass@CDialog@@UBEPAUCRuntimeClass@@XZ
// name: CDialog::GetRuntimeClass
// prototype: public: virtual struct CRuntimeClass * __thiscall CDialog::GetRuntimeClass(void)const

// LIBRARY: IMPERIALISM 0x00622448 SYMBOL
// ??0_AFX_WIN_STATE@@QAE@XZ
// name: _AFX_WIN_STATE::_AFX_WIN_STATE
// prototype: public: __thiscall _AFX_WIN_STATE::_AFX_WIN_STATE(void)

// LIBRARY: IMPERIALISM 0x00622451 SYMBOL
// ??_G_AFX_WIN_STATE@@UAEPAXI@Z
// name: _AFX_WIN_STATE::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall _AFX_WIN_STATE::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0062246c SYMBOL
// ??0CWinApp@@QAE@PBD@Z
// name: CWinApp::CWinApp
// prototype: public: __thiscall CWinApp::CWinApp(char const *)

// LIBRARY: IMPERIALISM 0x00622556 SYMBOL
// ??_GCWinApp@@UAEPAXI@Z
// name: CWinApp::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CWinApp::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00622572 SYMBOL
// ?InitApplication@CWinApp@@UAEHXZ
// name: CWinApp::InitApplication
// prototype: public: virtual int __thiscall CWinApp::InitApplication(void)

// LIBRARY: IMPERIALISM 0x00622632 SYMBOL
// ?ParseCommandLine@CWinApp@@QAEXAAVCCommandLineInfo@@@Z
// name: ParseCommandLine
// prototype: public: void __thiscall CWinApp::ParseCommandLine(class CCommandLineInfo &)

// LIBRARY: IMPERIALISM 0x00622690 SYMBOL
// ??0CCommandLineInfo@@QAE@XZ
// name: CCommandLineInfo::CCommandLineInfo
// prototype: public: __thiscall CCommandLineInfo::CCommandLineInfo(void)

// LIBRARY: IMPERIALISM 0x006226ff SYMBOL
// ??_GCCommandLineInfo@@UAEPAXI@Z
// name: CCommandLineInfo::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CCommandLineInfo::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x0062271b SYMBOL
// ??1CCommandLineInfo@@UAE@XZ
// name: CCommandLineInfo::~CCommandLineInfo
// prototype: public: virtual __thiscall CCommandLineInfo::~CCommandLineInfo(void)

// LIBRARY: IMPERIALISM 0x00622778 SYMBOL
// ?ParseParam@CCommandLineInfo@@UAEXPBDHH@Z
// name: ParseParam
// prototype: public: virtual void __thiscall CCommandLineInfo::ParseParam(char const *, int, int)

// LIBRARY: IMPERIALISM 0x006227a1 SYMBOL
// ?ParseParamFlag@CCommandLineInfo@@IAEXPBD@Z
// name: CCommandLineInfo::ParseParamFlag
// prototype: protected: void __thiscall CCommandLineInfo::ParseParamFlag(char const *)

// LIBRARY: IMPERIALISM 0x0062285f SYMBOL
// ?ParseParamNotFlag@CCommandLineInfo@@IAEXPBD@Z
// name: CCommandLineInfo::ParseParamNotFlag
// prototype: protected: void __thiscall CCommandLineInfo::ParseParamNotFlag(char const *)

// LIBRARY: IMPERIALISM 0x006228af SYMBOL
// ?ParseLast@CCommandLineInfo@@IAEXH@Z
// name: CCommandLineInfo::ParseLast
// prototype: protected: void __thiscall CCommandLineInfo::ParseLast(int)

// LIBRARY: IMPERIALISM 0x006228de SYMBOL
// ??1CWinApp@@UAE@XZ
// name: CWinApp::~CWinApp
// prototype: public: virtual __thiscall CWinApp::~CWinApp(void)

// LIBRARY: IMPERIALISM 0x00622a13 SYMBOL
// ?SaveStdProfileSettings@CWinApp@@IAEXXZ
// name: CWinApp::SaveStdProfileSettings
// prototype: protected: void __thiscall CWinApp::SaveStdProfileSettings(void)

// LIBRARY: IMPERIALISM 0x00622a4f SYMBOL
// ?ExitInstance@CWinApp@@UAEHXZ
// name: CWinApp::ExitInstance
// prototype: public: virtual int __thiscall CWinApp::ExitInstance(void)

// LIBRARY: IMPERIALISM 0x00622a85 SYMBOL
// ?GetRuntimeClass@CWinApp@@UBEPAUCRuntimeClass@@XZ
// name: CWinApp::GetRuntimeClass
// prototype: public: virtual struct CRuntimeClass * __thiscall CWinApp::GetRuntimeClass(void)const

// LIBRARY: IMPERIALISM 0x00622a8b
// InitializeMfcWinAppThreadLocalGlobal
// prototype: void __cdecl InitializeMfcWinAppThreadLocalGlobal(void)

// SYNTHETIC: IMPERIALISM 0x00622a95
// InitializeMfcWinStateProcessLocalStorage
// prototype: void __cdecl InitializeMfcWinStateProcessLocalStorage(void)

// SYNTHETIC: IMPERIALISM 0x00622a96
// RegisterMfcGlobalCleanup_00622aa2
// prototype: void __cdecl RegisterMfcGlobalCleanup_00622aa2(void)

// SYNTHETIC: IMPERIALISM 0x00622aa2
// DestroyMfcWinStateProcessLocalAtExit
// prototype: void __cdecl DestroyMfcWinStateProcessLocalAtExit(void)

// LIBRARY: IMPERIALISM 0x00622b3c SYMBOL
// ??_GCWinThread@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x00622b58 SYMBOL
// ??0CWinThread@@QAE@XZ
// name: CWinThread::CWinThread
// prototype: public: __thiscall CWinThread::CWinThread(void)

// LIBRARY: IMPERIALISM 0x00622b95 SYMBOL
// ?CommonConstruct@CWinThread@@QAEXXZ
// name: CWinThread::CommonConstruct
// prototype: public: void __thiscall CWinThread::CommonConstruct(void)

// LIBRARY: IMPERIALISM 0x00622bcd SYMBOL
// ?_AfxLoadDotBitmap@@YGXXZ

// LIBRARY: IMPERIALISM 0x00622cad SYMBOL
// ?GetRuntimeClass@CCmdTarget@@UBEPAUCRuntimeClass@@XZ
// name: CCmdTarget::GetRuntimeClass
// prototype: public: virtual struct CRuntimeClass * __thiscall CCmdTarget::GetRuntimeClass(void) const

// LIBRARY: IMPERIALISM 0x00622cb3 SYMBOL
// ?ProcessShellCommand@CWinApp@@QAEHAAVCCommandLineInfo@@@Z
// name: CWinApp::ProcessShellCommand
// prototype: public: int __thiscall CWinApp::ProcessShellCommand(class CCommandLineInfo &)

// LIBRARY: IMPERIALISM 0x00622dfc SYMBOL
// ?Unregister@CWinApp@@QAEHXZ
// name: CWinApp::Unregister
// prototype: public: int __thiscall CWinApp::Unregister(void)

// LIBRARY: IMPERIALISM 0x00622f2b SYMBOL
// ?DelRegTree@CWinApp@@QAEJPAUHKEY__@@ABVCString@@@Z
// name: CWinApp::DelRegTree
// prototype: public: long __thiscall CWinApp::DelRegTree(struct HKEY__*, class CString const &)

// LIBRARY: IMPERIALISM 0x00623006 SYMBOL
// ?EnableShellOpen@CWinApp@@IAEXXZ
// name: CWinApp::EnableShellOpen
// prototype: protected: void __thiscall CWinApp::EnableShellOpen(void)

// LIBRARY: IMPERIALISM 0x00623050 SYMBOL
// ?UnregisterShellFileTypes@CWinApp@@IAEXXZ
// name: CWinApp::UnregisterShellFileTypes
// prototype: protected: void __thiscall CWinApp::UnregisterShellFileTypes(void)

// LIBRARY: IMPERIALISM 0x00623061 SYMBOL
// ?SetRegistryKey@CWinApp@@IAEXPBD@Z
// name: CWinApp::SetRegistryKey
// prototype: protected: void __thiscall CWinApp::SetRegistryKey(char const *)

// LIBRARY: IMPERIALISM 0x00623099 SYMBOL
// ?SetRegistryKey@CWinApp@@IAEXI@Z
// name: CWinApp::SetRegistryKey
// prototype: protected: void __thiscall CWinApp::SetRegistryKey(unsigned int)

// LIBRARY: IMPERIALISM 0x006230cc SYMBOL
// ?GetAppRegistryKey@CWinApp@@QAEPAUHKEY__@@XZ
// name: CWinApp::GetAppRegistryKey
// prototype: public: struct HKEY__* __thiscall CWinApp::GetAppRegistryKey(void)

// LIBRARY: IMPERIALISM 0x00623160 SYMBOL
// ?GetSectionKey@CWinApp@@QAEPAUHKEY__@@PBD@Z
// name: GetSectionKey
// prototype: public: struct HKEY__* __thiscall CWinApp::GetSectionKey(char const *)

// LIBRARY: IMPERIALISM 0x006231a6 SYMBOL
// ?GetProfileIntA@CWinApp@@QAEIPBD0H@Z
// name: CWinApp::GetProfileIntA
// prototype: public: unsigned int __thiscall CWinApp::GetProfileIntA(char const *, char const *, int)

// LIBRARY: IMPERIALISM 0x00623212 SYMBOL
// ?GetProfileStringA@CWinApp@@QAE?AVCString@@PBD00@Z
// name: CWinApp::GetProfileStringA
// prototype: public: class CString __thiscall CWinApp::GetProfileStringA(char const *, char const *, char const *)

// LIBRARY: IMPERIALISM 0x00623324 SYMBOL
// ?GetProfileBinary@CWinApp@@QAEHPBD0PAPAEPAI@Z
// name: CWinApp::GetProfileBinary
// prototype: public: int __thiscall CWinApp::GetProfileBinary(char const *, char const *, unsigned char **, unsigned int *)

// LIBRARY: IMPERIALISM 0x0062343f SYMBOL
// ?CreateObject@CWnd@@SGPAVCObject@@XZ
// name: CWnd::CreateObject
// prototype: public: static class CObject * __stdcall CWnd::CreateObject(void)

// LIBRARY: IMPERIALISM 0x00623471 SYMBOL
// ?GetRuntimeClass@CWnd@@UBEPAUCRuntimeClass@@XZ
// name: CWnd::GetRuntimeClass
// prototype: public: virtual CRuntimeClass * __thiscall CWnd::GetRuntimeClass(void) const

// LIBRARY: IMPERIALISM 0x00623477 SYMBOL
// ??0_AFX_THREAD_STATE@@QAE@XZ
// name: _AFX_THREAD_STATE::_AFX_THREAD_STATE
// prototype: public: __thiscall _AFX_THREAD_STATE::_AFX_THREAD_STATE(void)

// LIBRARY: IMPERIALISM 0x0062348e SYMBOL
// ??_G_AFX_THREAD_STATE@@UAEPAXI@Z
// name: _AFX_THREAD_STATE::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall _AFX_THREAD_STATE::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x006234a9 SYMBOL
// ??1_AFX_THREAD_STATE@@UAE@XZ
// name: _AFX_THREAD_STATE::~_AFX_THREAD_STATE
// prototype: public: virtual __thiscall _AFX_THREAD_STATE::~_AFX_THREAD_STATE(void)

// LIBRARY: IMPERIALISM 0x00623523 SYMBOL
// ?AfxGetThreadState@@YGPAV_AFX_THREAD_STATE@@XZ
// name: AfxGetThreadState
// prototype: class _AFX_THREAD_STATE * __stdcall AfxGetThreadState(void)

// LIBRARY: IMPERIALISM 0x00623559 SYMBOL
// ??0AFX_MODULE_STATE@@QAE@H@Z
// name: AFX_MODULE_STATE::AFX_MODULE_STATE
// prototype: public: __thiscall AFX_MODULE_STATE::AFX_MODULE_STATE(int)

// LIBRARY: IMPERIALISM 0x006235bd SYMBOL
// ??_G_AFX_BASE_MODULE_STATE@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x006235d8 SYMBOL
// ??1AFX_MODULE_STATE@@UAE@XZ
// name: AFX_MODULE_STATE::~AFX_MODULE_STATE
// prototype: public: virtual __thiscall AFX_MODULE_STATE::~AFX_MODULE_STATE(void)

// LIBRARY: IMPERIALISM 0x0062368b SYMBOL
// ??0AFX_MODULE_THREAD_STATE@@QAE@XZ
// name: AFX_MODULE_THREAD_STATE::AFX_MODULE_THREAD_STATE
// prototype: public: __thiscall AFX_MODULE_THREAD_STATE::AFX_MODULE_THREAD_STATE(void)

// LIBRARY: IMPERIALISM 0x006236f6 SYMBOL
// ??_GAFX_MODULE_THREAD_STATE@@UAEPAXI@Z
// name: AFX_MODULE_THREAD_STATE::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall AFX_MODULE_THREAD_STATE::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00623711 SYMBOL
// ??1AFX_MODULE_THREAD_STATE@@UAE@XZ
// name: AFX_MODULE_THREAD_STATE::~AFX_MODULE_THREAD_STATE
// prototype: public: virtual __thiscall AFX_MODULE_THREAD_STATE::~AFX_MODULE_THREAD_STATE(void)

// LIBRARY: IMPERIALISM 0x00623824 SYMBOL
// ?CreateObject@?$CProcessLocal@V_AFX_BASE_MODULE_STATE@@@@SGPAVCNoTrackObject@@XZ
// name: _AFX_BASE_MODULE_STATE>::CreateObject
// prototype: public: static class CNoTrackObject * __stdcall CProcessLocal<class _AFX_BASE_MODULE_STATE>::CreateObject(void)

// LIBRARY: IMPERIALISM 0x00623866 SYMBOL
// ??_G_AFX_BASE_MODULE_STATE@@UAEPAXI@Z

// LIBRARY: IMPERIALISM 0x00623886 SYMBOL
// ?AfxGetModuleState@@YGPAVAFX_MODULE_STATE@@XZ
// name: AfxGetModuleState
// prototype: class AFX_MODULE_STATE * __stdcall AfxGetModuleState(void)

// LIBRARY: IMPERIALISM 0x006238ac SYMBOL
// ?AfxGetModuleThreadState@@YGPAVAFX_MODULE_THREAD_STATE@@XZ
// name: AfxGetModuleThreadState
// prototype: AFX_MODULE_THREAD_STATE * __stdcall ?AfxGetModuleThreadState@@YGPAVAFX_MODULE_THREAD_STATE@@XZ@006238ac(void)

// LIBRARY: IMPERIALISM 0x006238c3 SYMBOL
// ?Unlock@CTypeLibCache@@QAEXXZ

// LIBRARY: IMPERIALISM 0x00623996 SYMBOL
// ?GetRuntimeClass@CEdit@@UBEPAUCRuntimeClass@@XZ
// name: CEdit::GetRuntimeClass
// prototype: public: virtual struct CRuntimeClass * __thiscall CEdit::GetRuntimeClass(void)const

// LIBRARY: IMPERIALISM 0x006239a2 SYMBOL
// ?GetRuntimeClass@CDocument@@UBEPAUCRuntimeClass@@XZ
// name: CDocument::GetRuntimeClass
// prototype: public: virtual struct CRuntimeClass * __thiscall CDocument::GetRuntimeClass(void) const

// LIBRARY: IMPERIALISM 0x006239ae
// InitializeMfcGlobalExceptionObjectA
// prototype: void __cdecl InitializeMfcGlobalExceptionObjectA(void)

// LIBRARY: IMPERIALISM 0x006239b8
// ownership-only

// SYNTHETIC: IMPERIALISM 0x006239ca
// RegisterMfcGlobalCleanup_006239d6
// prototype: void __cdecl RegisterMfcGlobalCleanup_006239d6(void)

// LIBRARY: IMPERIALISM 0x006239e6
// InitializeMfcGlobalExceptionObjectB
// prototype: void __cdecl InitializeMfcGlobalExceptionObjectB(void)

// LIBRARY: IMPERIALISM 0x006239f0
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00623a02
// RegisterMfcGlobalCleanup_00623a0e
// prototype: void __cdecl RegisterMfcGlobalCleanup_00623a0e(void)

// LIBRARY: IMPERIALISM 0x00623a82 SYMBOL
// ?GetRuntimeClass@CPen@@UBEPAUCRuntimeClass@@XZ
// name: CPen::GetRuntimeClass
// prototype: public: virtual struct CRuntimeClass * __thiscall CPen::GetRuntimeClass(void) const

// LIBRARY: IMPERIALISM 0x00623a9a
// CPalette::GetRuntimeClass

// LIBRARY: IMPERIALISM 0x00623ab2
// InitializeMfcGlobalExceptionObjectC
// prototype: void __cdecl InitializeMfcGlobalExceptionObjectC(void)

// LIBRARY: IMPERIALISM 0x00623abc
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00623ace
// RegisterMfcGlobalCleanup_00623ada
// prototype: void __cdecl RegisterMfcGlobalCleanup_00623ada(void)

// LIBRARY: IMPERIALISM 0x00623aea
// InitializeMfcGlobalExceptionObjectD
// prototype: void __cdecl InitializeMfcGlobalExceptionObjectD(void)

// LIBRARY: IMPERIALISM 0x00623af4
// ownership-only

// SYNTHETIC: IMPERIALISM 0x00623b06
// RegisterMfcGlobalCleanup_00623b12
// prototype: void __cdecl RegisterMfcGlobalCleanup_00623b12(void)

// LIBRARY: IMPERIALISM 0x00623b3a
// CPtrList::GetRuntimeClass

// LIBRARY: IMPERIALISM 0x00623b40 SYMBOL
// ?GetRuntimeClass@CFileException@@UBEPAUCRuntimeClass@@XZ
// name: CFileException::GetRuntimeClass
// prototype: public: virtual struct CRuntimeClass * __thiscall CFileException::GetRuntimeClass(void) const

// LIBRARY: IMPERIALISM 0x00623b46 SYMBOL
// ?GetRuntimeClass@CMemFile@@UBEPAUCRuntimeClass@@XZ
// name: CMemFile::GetRuntimeClass
// prototype: public: virtual struct CRuntimeClass * __thiscall CMemFile::GetRuntimeClass(void) const

// LIBRARY: IMPERIALISM 0x00623b4c SYMBOL
// ?AddHead@CSimpleList@@QAEXPAX@Z
// name: CSimpleList::AddHead
// prototype: public: void __thiscall CSimpleList::AddHead(void *)

// LIBRARY: IMPERIALISM 0x00623b5f SYMBOL
// ?Remove@CSimpleList@@QAEHPAX@Z
// name: CSimpleList::Remove
// prototype: public: int __thiscall CSimpleList::Remove(void *)

// LIBRARY: IMPERIALISM 0x00623baa SYMBOL
// ??2CNoTrackObject@@SGPAXI@Z
// name: new
// prototype: public: static void * __stdcall CNoTrackObject::operator new(unsigned int)

// LIBRARY: IMPERIALISM 0x00623bc8 SYMBOL
// ??3CNoTrackObject@@SGXPAX@Z
// name: delete
// prototype: public: static void __stdcall CNoTrackObject::operator delete(void *)

// LIBRARY: IMPERIALISM 0x00623bdc SYMBOL
// ??0CThreadSlotData@@QAE@XZ
// name: CThreadSlotData::CThreadSlotData
// prototype: public: __thiscall CThreadSlotData::CThreadSlotData(void)

// LIBRARY: IMPERIALISM 0x00623c1e SYMBOL
// ??1CThreadSlotData@@QAE@XZ
// name: CThreadSlotData::~CThreadSlotData
// prototype: public: __thiscall CThreadSlotData::~CThreadSlotData(void)

// LIBRARY: IMPERIALISM 0x00623c75 SYMBOL
// ?AllocSlot@CThreadSlotData@@QAEHXZ
// name: CThreadSlotData::AllocSlot
// prototype: public: int __thiscall CThreadSlotData::AllocSlot(void)

// LIBRARY: IMPERIALISM 0x00623d87 SYMBOL
// ?FreeSlot@CThreadSlotData@@QAEXH@Z
// name: CThreadSlotData::FreeSlot
// prototype: public: void __thiscall CThreadSlotData::FreeSlot(int)

// LIBRARY: IMPERIALISM 0x00623de4 SYMBOL
// ?SetValue@CThreadSlotData@@QAEXHPAX@Z
// name: CThreadSlotData::SetValue
// prototype: public: void __thiscall CThreadSlotData::SetValue(int, void *)

// LIBRARY: IMPERIALISM 0x00623eb2 SYMBOL
// ??_GCNoTrackObject@@UAEPAXI@Z
// name: CNoTrackObject::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CNoTrackObject::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x00623ecd SYMBOL
// ??1CNoTrackObject@@UAE@XZ
// name: CNoTrackObject::~CNoTrackObject
// prototype: public: virtual __thiscall CNoTrackObject::~CNoTrackObject(void)

// LIBRARY: IMPERIALISM 0x00623ed4 SYMBOL
// ?AssignInstance@CThreadSlotData@@QAEXPAUHINSTANCE__@@@Z
// name: CThreadSlotData::AssignInstance
// prototype: public: void __thiscall CThreadSlotData::AssignInstance(struct HINSTANCE__*)

// LIBRARY: IMPERIALISM 0x00623f15 SYMBOL
// ?DeleteValues@CThreadSlotData@@QAEXPAUCThreadData@@PAUHINSTANCE__@@@Z
// name: CThreadSlotData::DeleteValues
// prototype: public: void __thiscall CThreadSlotData::DeleteValues(struct CThreadData *, struct HINSTANCE__*)

// LIBRARY: IMPERIALISM 0x00623f9d SYMBOL
// ?DeleteValues@CThreadSlotData@@QAEXPAUHINSTANCE__@@H@Z
// name: CThreadSlotData::DeleteValues
// prototype: public: void __thiscall CThreadSlotData::DeleteValues(struct HINSTANCE__*, int)

// LIBRARY: IMPERIALISM 0x00623ff6 SYMBOL
// ?GetData@CThreadLocalObject@@QAEPAVCNoTrackObject@@P6GPAV2@XZ@Z
// name: CThreadLocalObject::GetData
// prototype: public: class CNoTrackObject * __thiscall CThreadLocalObject::GetData(class CNoTrackObject * (__stdcall *)(void))

// LIBRARY: IMPERIALISM 0x0062406d SYMBOL
// ?GetDataNA@CThreadLocalObject@@QAEPAVCNoTrackObject@@XZ
// name: CThreadLocalObject::GetDataNA
// prototype: public: class CNoTrackObject * __thiscall CThreadLocalObject::GetDataNA(void)

// LIBRARY: IMPERIALISM 0x0062409a SYMBOL
// ??1CThreadLocalObject@@QAE@XZ
// name: CThreadLocalObject::~CThreadLocalObject
// prototype: public: __thiscall CThreadLocalObject::~CThreadLocalObject(void)

// LIBRARY: IMPERIALISM 0x006240b8 SYMBOL
// ?GetData@CProcessLocalObject@@QAEPAVCNoTrackObject@@P6GPAV2@XZ@Z

// LIBRARY: IMPERIALISM 0x00624123 SYMBOL
// ??1CProcessLocalObject@@QAE@XZ

// LIBRARY: IMPERIALISM 0x0062415e SYMBOL
// ?AfxTermLocalData@@YGXPAUHINSTANCE__@@H@Z
// name: AfxTermLocalData
// prototype: void __stdcall AfxTermLocalData(struct HINSTANCE__*, int)

// LIBRARY: IMPERIALISM 0x006241a7
// InitializeMfcAuxDataGlobal
// prototype: void __cdecl InitializeMfcAuxDataGlobal(void)

// SYNTHETIC: IMPERIALISM 0x006241b1
// ConstructMfcAuxDataGlobal
// prototype: void __cdecl ConstructMfcAuxDataGlobal(void)

// SYNTHETIC: IMPERIALISM 0x006241bb
// RegisterMfcGlobalCleanup_006241c7
// prototype: void __cdecl RegisterMfcGlobalCleanup_006241c7(void)

// LIBRARY: IMPERIALISM 0x006241d1 SYMBOL
// ?AfxEnableWin40Compatibility@@YGXXZ
// name: AfxEnableWin40Compatibility
// prototype: void __stdcall AfxEnableWin40Compatibility(void)

// LIBRARY: IMPERIALISM 0x00624201 SYMBOL
// ?AfxEnableWin31Compatibility@@YGXXZ
// name: AfxEnableWin31Compatibility
// prototype: void __stdcall AfxEnableWin31Compatibility(void)

// LIBRARY: IMPERIALISM 0x00624223 SYMBOL
// ??0AUX_DATA@@QAE@XZ
// name: AUX_DATA::AUX_DATA
// prototype: public: __thiscall AUX_DATA::AUX_DATA(void)

// LIBRARY: IMPERIALISM 0x006242de SYMBOL
// ??1_AFX_CTL3D_STATE@@UAE@XZ
// name: _AFX_CTL3D_STATE::~_AFX_CTL3D_STATE
// prototype: public: virtual __thiscall _AFX_CTL3D_STATE::~_AFX_CTL3D_STATE(void)

// LIBRARY: IMPERIALISM 0x00624325 SYMBOL
// ??1_AFX_CTL3D_THREAD@@UAE@XZ
// name: _AFX_CTL3D_THREAD::~_AFX_CTL3D_THREAD
// prototype: public: virtual __thiscall _AFX_CTL3D_THREAD::~_AFX_CTL3D_THREAD(void)

// LIBRARY: IMPERIALISM 0x00624487
// InitializeMfcThreadLocalGlobal_006a7d70
// prototype: void __cdecl InitializeMfcThreadLocalGlobal_006a7d70(void)

// SYNTHETIC: IMPERIALISM 0x00624491
// InitializeMfcThreadLocalStorage006a7d70
// prototype: void __cdecl InitializeMfcThreadLocalStorage006a7d70(void)

// SYNTHETIC: IMPERIALISM 0x00624492
// RegisterMfcGlobalCleanup_0062449e
// prototype: void __cdecl RegisterMfcGlobalCleanup_0062449e(void)

// SYNTHETIC: IMPERIALISM 0x0062449e
// DestroyMfcThreadLocalGlobal_006a7d70
// prototype: void __cdecl DestroyMfcThreadLocalGlobal_006a7d70(void)

// SYNTHETIC: IMPERIALISM 0x006244b7
// InitializeMfcCtl3dProcessLocalStorage
// prototype: void __cdecl InitializeMfcCtl3dProcessLocalStorage(void)

// SYNTHETIC: IMPERIALISM 0x006244b8
// RegisterMfcGlobalCleanup_006244c4
// prototype: void __cdecl RegisterMfcGlobalCleanup_006244c4(void)

// SYNTHETIC: IMPERIALISM 0x006244c4
// DestroyMfcCtl3dProcessLocalAtExit
// prototype: void __cdecl DestroyMfcCtl3dProcessLocalAtExit(void)

// LIBRARY: IMPERIALISM 0x006244d3 SYMBOL
// ?AfxCriticalInit@@YGHXZ
// name: AfxCriticalInit
// prototype: int __stdcall AfxCriticalInit(void)

// LIBRARY: IMPERIALISM 0x0062456f SYMBOL
// ?AfxLockGlobals@@YGXH@Z
// name: AfxLockGlobals
// prototype: void __stdcall AfxLockGlobals(int)

// LIBRARY: IMPERIALISM 0x006245df SYMBOL
// ?AfxUnlockGlobals@@YGXH@Z
// name: AfxUnlockGlobals
// prototype: void __stdcall AfxUnlockGlobals(int)

// LIBRARY: IMPERIALISM 0x00624606 SYMBOL
// ?_AfxDeleteRegKey@@YGHPBD@Z
// name: _AfxDeleteRegKey
// prototype: int __stdcall _AfxDeleteRegKey(char const *)

// LIBRARY: IMPERIALISM 0x00624693 SYMBOL
// ??0CDocManager@@QAE@XZ
// name: CDocManager::CDocManager
// prototype: public: __thiscall CDocManager::CDocManager(void)

// LIBRARY: IMPERIALISM 0x006246cd SYMBOL
// ??_GCDocManager@@UAEPAXI@Z
// name: CDocManager::`scalar deleting dtor'
// prototype: public: virtual void * __thiscall CDocManager::`scalar deleting dtor'(unsigned int)

// LIBRARY: IMPERIALISM 0x006246e9 SYMBOL
// ?UnregisterShellFileTypes@CDocManager@@QAEXXZ
// name: CDocManager::UnregisterShellFileTypes
// prototype: public: void __thiscall CDocManager::UnregisterShellFileTypes(void)

// LIBRARY: IMPERIALISM 0x0062496b SYMBOL
// ?RegisterShellFileTypes@CDocManager@@UAEXH@Z
// name: CDocManager::RegisterShellFileTypes
// prototype: public: virtual void __thiscall CDocManager::RegisterShellFileTypes(int)

// LIBRARY: IMPERIALISM 0x00624dda SYMBOL
// ?SetRegKey@@YGHPBD00@Z

// LIBRARY: IMPERIALISM 0x00624e73 SYMBOL
// ?AfxWinInit@@YGHPAUHINSTANCE__@@0PADH@Z
// name: AfxWinInit
// prototype: int __stdcall AfxWinInit(struct HINSTANCE__*, struct HINSTANCE__*, char *, int)

// LIBRARY: IMPERIALISM 0x00624ed6 SYMBOL
// ?SetCurrentHandles@CWinApp@@QAEXXZ
// name: CWinApp::SetCurrentHandles
// prototype: public: void __thiscall CWinApp::SetCurrentHandles(void)

// LIBRARY: IMPERIALISM 0x00624ff3 SYMBOL
// ?AfxGetFileName@@YGIPBDPADI@Z
// name: AfxGetFileName
// prototype: unsigned int __stdcall AfxGetFileName(char const *, char *, unsigned int)

// LIBRARY: IMPERIALISM 0x00626b59 SYMBOL
// ??1_AFX_WIN_STATE@@UAE@XZ
// name: _AFX_WIN_STATE::~_AFX_WIN_STATE
// prototype: public: virtual __thiscall _AFX_WIN_STATE::~_AFX_WIN_STATE(void)

// LIBRARY: IMPERIALISM 0x00626b90 SYMBOL
// ?AfxPostQuitMessage@@YGXH@Z
// name: AfxPostQuitMessage
// prototype: void __stdcall ?AfxPostQuitMessage@@YGXH@Z@00626b90(int param_1)

// LIBRARY: IMPERIALISM 0x00626bb3 SYMBOL
// ??1CWinThread@@UAE@XZ

// LIBRARY: IMPERIALISM 0x00626c02 SYMBOL
// ??1AUX_DATA@@QAE@XZ
// name: AUX_DATA::~AUX_DATA
// prototype: public: __thiscall AUX_DATA::~AUX_DATA(void)

// LIBRARY: IMPERIALISM 0x00626c0c SYMBOL
// ??1CDocManager@@UAE@XZ
// name: CDocManager::~CDocManager
// prototype: public: virtual __thiscall CDocManager::~CDocManager(void)

// LIBRARY: IMPERIALISM 0x00626c7d SYMBOL
// ?AfxWinTerm@@YGXXZ
// name: AfxWinTerm
// prototype: void __stdcall AfxWinTerm(void)

// Called from _WinMainCRTStartup (0x5e9974) before main: LoadLibrary's the bundled
// wav-winmm.dll forwarder and binds mciSendCommandA, auxGetNumDevs, auxGetDevCapsA,
// auxGetVolume and auxSetVolume into the 0x6ab5xx import table, continuing startup
// even on failure. Vendor/toolchain glue, not game source.
// LIBRARY: IMPERIALISM 0x00707081
// InitializeWinmmImportBindings
// prototype: void InitializeWinmmImportBindings(void)
