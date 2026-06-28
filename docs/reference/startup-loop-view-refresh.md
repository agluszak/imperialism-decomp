# Startup Loop View Refresh Findings

## Observed runtime path

`just debug-timeout` with breakpoints on startup and turn-event methods shows the
message loop is not dead. Startup reaches this chain:

```text
WinMain
  -> ImperialismApp::InitInstance
  -> CWinThread::Run / CWinApp::Run
  -> CMainFrame::OnStartupCommand100
  -> ImperialismApp::HandleStartupCommand100
  -> TSimMgr::AdvanceGlobalTurnStateMachine
  -> TViewMgr::DispatchTurnEventSlot4C(0, 0)
```

At `TSimMgr::AdvanceGlobalTurnStateMachine`, the live object state was:

| Field | Offset | Value |
| --- | ---: | ---: |
| `turnStateCode` | `+0x00` | `1` |
| `mode` | `+0x04` | `1` |
| `quarterGateTick2c` | `+0x2c` | `0` |
| `field30` | `+0x30` | `7` |
| `redrawEnabled` | `+0x40` | `0` |

The state machine case for code `1` advances `turnStateCode` to `3` and dispatches
`g_pUiRuntimeContext->DispatchTurnEventSlot4C(0, 0)`. It does not post a second
startup command on this path.

## Why the loop looked idle

`TViewMgr::DispatchTurnEventSlot4C(0, 0)` takes the code-0 full-refresh path:

```text
mainView->CallVoidSlotA0()
CWMgrIterator::FirstWindow()
while (iter.More()) {
  if (node->controlTag == 'Wpam' || node->controlTag == 'Wnrt')
    node->RebuildWindowContentSlot1D0()
}
```

The debugger shows `CWMgrIterator::FirstWindow()` returns `0`, so
`g_LiveViewRegistry` is empty. The message loop is still running; the first
refresh sweep has no registered windows to rebuild, then the app waits for more
messages.

After recovering the `TWindow` construction path, the same breakpoint sequence now
returns a live registry node:

| Probe | Value |
| --- | ---: |
| `CWMgrIterator::FirstWindow()` return | `0x1521118` |
| first node vtable | `0x0049d958` |
| first node `controlTag` | `0x57494e44` (`'WIND'`) |

The code-0 refresh path is therefore no longer empty. The first registered node is
not one of the two rebuild tags (`'Wpam'` / `'Wnrt'`), so the next advancement work
is to recover the concrete window/dialog factory path that creates those tagged
nodes and the follow-up turn-event handlers that populate them.

## Source-model evidence

The source used to be asymmetric:

| Class | Constructor behavior | Destructor behavior |
| --- | --- | --- |
| `TWindow` | `TWindow::TWindow() : TView() {}` | removes `this` from `g_LiveViewRegistry` |
| `TFloatWindow` | calls `TWindow()`, then `g_LiveViewRegistry.AddTail(this)` | inherits the `TWindow` unlink path |

Original evidence for `0x0048d500` shows the real `TWindow` construction body is
not empty. It builds the `TView` base, constructs the embedded `TDialogBehavior`
region at `+0x74`, links `this` into the live-view registry, initializes the gold
color descriptor, and writes self pointers into the `+0x64` / dialog-behavior
owner fields.

The current source now models that direction directly:

- `TWindow` owns a real `TDialogBehavior` member at `+0x74`.
- `TWindow::TWindow` inserts `this` into `g_LiveViewRegistry` with `CPtrList::AddHead`.
- `TFloatWindow::TFloatWindow` no longer re-adds itself to the registry; the derived
  constructor relies on the base constructor, matching the original sequence.

## Advancement plan

1. Continue replacing generic turn-event stubs with real `TViewMgr` / `TMacViewMgr`
   methods.
   - Start with the dispatch methods reached from `DispatchTurnEventSlot4C`:
     `0x005d6bf0`, `0x005d6c10`, `0x005d6c30`, `0x005d6cd0`..`0x005d71b0`,
     and `0x005d7c40` onward.
   - Keep virtual dispatch as real methods on `TViewMgr`, `TMacViewMgr`, or the
     recovered dialog/view class. Avoid raw `vftable[]` indexing and call-convention
     casts for recoverable class methods.
2. Improve the strategic-map side effects needed by turn-event handlers.
   - Prioritize `TMacViewMgr` slots that refresh map/city panels:
     `0x0050d310`, `0x0050d360`, `0x0050d470`, `0x0050d5b0`, `0x0050d920`, and
     `0x0050d950`.
   - Replace wrapper names with semantic real methods once the receiver and slot
     are verified from the listing.
3. Recover the concrete registered window/dialog classes that should appear in the
   code-0 sweep with tags `'Wpam'` and `'Wnrt'`.
   - Use constructor/vtable evidence, not only `controlTag`, to name the classes.
   - Once the classes are known, replace the local `UiWindowTraversalNode` vtable-view
     with real virtuals on the recovered owner.
4. Validate each slice with:
   - `just sync-ownership && just regen-stubs && just build` after marker moves.
   - `just compare <addresses>` for changed functions.
   - `just debug-timeout` breakpoints on `CWMgrIterator::FirstWindow`,
     `TViewMgr::DispatchTurnEventSlot4C`, and selected `TMacViewMgr` slots to prove
     the loop advances past the current empty-refresh point.
