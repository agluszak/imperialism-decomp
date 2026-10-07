# Recovered UI architecture

The Rust UI follows one direction:

```text
retail resource evidence -> generated Bevy scene -> bind once
                                                 -> typed interaction
                                                 -> GameState / screen state
                                                 -> presentation rendering
```

Recovered hierarchy, layout, tags and initial widget structure are generated
from committed evidence. Handwritten Rust provides semantic interpretation,
event handlers and state projection. Neither side duplicates the other's
screen tree.

## Identity and ownership

- A scoped `FourCc` or `RetailTag` identifies a recovered control **only
  while binding**. Tags are immutable evidence and are not globally unique.
- Typed game IDs identify domain concepts; Bevy `Entity` identifies a live
  presentation object. Generated Rust field names, string paths, `Name`,
  and generated node IDs are not additional identity systems.
- One independently lived screen/dialog may retain a root semantic view
  containing the minimum stable control `Entity` handles and screen-local
  state. Repeated rows are normally plain Rust fields, not leaf components.
- Fixed screens resolve controls once with `RetailTree`; normal input and
  rendering must not repeatedly search the recovered tree.
- For a snapshot screen, populate once and retain no unnecessary live view.
  Dynamic world objects and interactive collections may use ordinary ECS
  components where their independent lifetime requires it.

## State and rendering

`GameSession` owns authoritative `GameState`. Do not mirror gameplay into
ECS or split `GameState` into smaller component authorities. Camera,
selection, window positions and other presentation state have a distinct
screen-local resource/component owner. Hover, press, focus and slider state
belong to the widget.

Bind interactions to direct typed operations. Constants used by one handler
belong in its closure. The resulting coarse screen renderer reads the
authoritative state and writes Bevy `Text`, `Node`, `Visibility`,
`ImageNode` or `BackgroundColor` directly. Standard change detection is
sufficient until profiling demonstrates a need for smaller update units.

Use stock Bevy headless widgets for input behavior where possible; recover
a specific retail skin or interaction only when necessary. `RetailSidewaysArrow`
needs hold-repeat, and `RetailPageCorner` needs its triangular hit test;
these are behavior, not reasons to introduce a general widget framework.
Passive visual children should not acquire mirror components and their own
projection systems.

## Generated hierarchy

Generated BSN owns `Node`/`Children` hierarchy, retail placement and
static assets. Reusable scene fragments and Parts may contribute children,
but codegen must merge those children with recovered ones into one hierarchy.
`ChildOf` is the runtime hierarchy and lifetime owner.

Use a compact scoped tag-to-domain table for repeated recovered controls
sharing semantics. Do not generate a typed public field for every retail node,
invent a selector registry, dynamic binder, generalized `Binding<T>` graph,
lens layer or second tree representation.

Bind once, then use direct `Entity` handles or widget interaction state.
Create a custom relationship or independently queried leaf component only
for a concrete caller that needs it. Do not mimic the C++ class hierarchy
as Rust component classes.

## Validation

Regenerate and check the existing C++/Rust UI code generators, then test
the changed view or interaction against recovered retail behavior. The
production caller must use the recovered scene, not a separate test-only
screen. Verify layout, input timing, event propagation, domain mutations
and the rendered result as appropriate.
