# Recovered UI architecture

Imperialism's recovered UI has one directional pipeline:

```text
retail evidence -> generated Bevy scene -> bind once -> semantic view
                                                       |           ^
                                                       v           |
                                                    input       render
                                                       |           |
                                                       v           |
                                                authoritative state
```

Recovered resource identities describe how to find controls while binding a generated scene. After
binding, application code uses typed domain identifiers for meaning and Bevy `Entity` values for
runtime addresses. Input mutates authoritative state, and render systems project that state into
Bevy presentation components.

This is external state management, not a data-binding graph. ECS does not mirror gameplay state and
does not serve as a database for rediscovering which entity displays each field.

## Identity and ownership

The UI uses three kinds of identity:

| Identity | Meaning | Use |
| --- | --- | --- |
| `FourCc` plus a scoped recovered hierarchy | A selector or provenance value in a retail resource | Recovery and one-time binding |
| Typed IDs such as `TradeCommodity`, `CityOrderId`, or `CityFacilitySlot` | What a control means to the game | Application and gameplay logic |
| Bevy `Entity` | Where one runtime object lives | Runtime UI addressing |

A FourCC is not globally unique. Binders resolve it under the narrowest known recovered parent. A
generator node ID, generated Rust field name, `Name`, string path, or similar value must not become
another identity namespace used by handwritten application code.

`RetailTag` is immutable recovered provenance. Runtime presentation state, such as which zoom image
is active, belongs in widget or screen state and must not rewrite the tag.

Each independently lived screen or dialog owns one semantic view component on its root. That view
retains the minimum direct `Entity` handles and semantic state that must survive binding. It is not
a cached description of the generated scene: do not copy addressed `Node` geometry, shared assets,
presentation properties, dynamic gameplay state, or an identity already expressed by a typed table
key into it. Repeated rows and other subordinate structures are normally plain Rust values inside
the root view, not leaf components added so another system can query the display destination.

For example, the intended shape is:

```rust,ignore
#[derive(Component)]
struct TechnologyAdvanceView {
    picture: Entity,
    text: Entity,
}

#[derive(Component)]
struct TradeView {
    capacity: Entity,
    rows: TradeCommodityTable<TradeRowView>,
}

struct TradeRowView {
    decrease: Entity,
    increase: Entity,
    quantity: Entity,
    gauge_fill: Entity,
}
```

Only the aggregate root views are components here. A direct `Entity` field is sufficient for a
relation known when the scene is constructed. Define a custom Bevy relationship only when the
relationship is itself a first-class concept queried by multiple independent systems.

Do not apply "make a `FooView`" mechanically to every screen. The pattern is not universal, and
forcing a root address table onto genuinely dynamic content is the next cargo-cult abstraction.
Decide by what can change while the screen stays alive:

- **Snapshot screens** (newspaper, council, game score, high score): resolve controls and populate
  them once during binding; retain nothing unnecessary and register no `Update` system.
- **Live fixed screens** (Trade, Transport, Offer Sheet, industry dialogs): bind the minimum
  addresses once into one semantic view and let a coarse renderer project authoritative state on
  change. Do not also annotate those addresses with a reverse action/display index.
- **Dynamic collections and world objects** (technology store rows, diplomacy panels, strategic-map
  units): ordinary ECS leaf components and actions remain appropriate; there is no fixed row set to
  index.

## Generated and handwritten code

Generated code owns facts obtained mechanically from retail evidence: hierarchy, layout, ordering,
tags, styles, static pictures, initial widget types and states, and recovered tables whose contents
are themselves evidence.

Handwritten code owns semantic interpretation, behavior, and policy. It may use a compact table that
maps scoped recovered tags to domain values, such as a trade-row FourCC to `TradeCommodity`. That is
the translation boundary, not a duplicate screen tree.

Generated code must not wire game semantics such as a Cotton row to a gameplay operation or expose
one public Rust `Entity` field per recovered node for handwritten code to address. Handwritten code
must not recreate the generated hierarchy. Generated variants with the same semantics share a
handwritten binder through compact recovered-tag tables.

`RetailTree` is the production bind-time mechanism. A binder runs when a newly spawned generated
scene arrives, resolves required controls under the scene root or a local parent, attaches semantic
actions to interactive entities, and stores the resulting semantic view on the root. Normal input
and rendering do not search tags or walk the tree to rediscover those controls.

## State and data flow

State has one owner:

- Authoritative gameplay state remains in `GameState` through `GameSession`. It is not mirrored into
  ECS components.
- Screen-local semantic state has one explicit screen component or resource owner. Selection before
  confirmation, camera position, armory selection, and window position belong here.
- Widget-local ephemeral state such as press, focus, hover, and cursor position belongs to Bevy
  widgets and reusable presentation behavior.

Application data flow is always:

```text
widget event -> typed state mutation -> render authoritative state -> Bevy presentation
```

An interactive leaf component is useful when it describes behavior on a dynamically created or
independently queried control. A display marker whose only meaning is "write this field here later"
is not useful; its destination belongs in the owning view.

Bind-time constants needed only by an event handler belong in that observer's closure, not in ECS.
If a fixed control's semantic argument is known at binding and only its handler needs that argument,
capture it (for example a trade card captures its `TradeCommodity` and `TradeCardKind`). Store it as
a component only when other independent systems need to query it.

Reusable autonomous presentation components such as `RetailPictureSwap` remain appropriate. The
criterion is meaningful state, behavior, lifecycle, or relationship on that entity, not a blanket
ban on leaf components.

## Rendering

Prefer one deliberately coarse renderer per screen or independently lived dialog family. It reads
authoritative gameplay or screen state and writes `Text`, `Visibility`, `ImageNode`, `Node`, and
other Bevy presentation components through the entities retained by the semantic view.

Standard Bevy change detection is enough to decide when to render. A renderer may use a resource's
`is_changed()` state and `Ref<T>::is_added()` for a newly bound view. A gameplay mutation marking the
whole `GameSession` changed is an acceptable correctness-first invalidation boundary; do not split
`GameState` into ECS components to obtain finer invalidation.

Split a renderer only for a concrete independent lifecycle or update cadence, or for demonstrated
expensive work such as regenerating a raster surface. Optimize that surface directly rather than
introducing a generic dependency, projection, observer, lens, or binding framework.

## Hierarchy and windows

`ChildOf` remains the source of truth for hierarchy and descendant lifetime. Use event propagation
through that hierarchy when the event is designed to propagate. When a child needs direct access to
an invariant owner and propagation does not apply, store the owner explicitly. Do not repeatedly walk
ancestors to rediscover an ownership relation established when the child was created.

A window caption knows the window it drags, its close button knows the host it dismisses, and a modal
root knows its default and cancel controls. Each is established once at binding: pointer, drag,
keyboard, and activation events propagate to those observers, whose closures capture the invariant
targets.

Generated BSN remains the structure mechanism for recovered screens. `SceneComponent` may be used
for a genuinely reusable semantic widget authored by this project, but recovered screens do not get
a second handcrafted scene merely to wrap their generated hierarchy.

## Tests

Tests follow the same boundaries:

- Generator tests prove hierarchy, tags, layout, ordering, and presentation facts came from recovery
  evidence.
- Binding tests prove every required semantic slot resolves exactly once to the expected structural
  control.
- Input tests deliver real widget events and assert the authoritative gameplay or screen-state
  mutation.
- Render tests seed authoritative state and assert actual Bevy presentation components.

Do not test an intermediate display or projection identity whose only purpose is implementation
plumbing.

## Contract

UI changes must preserve these rules:

1. Gameplay and screen-local semantic facts each have one authoritative owner; Bevy widget state is
   presentation state.
2. Data flows one way: input event, typed state mutation, render, Bevy presentation. There is no
   two-way binding.
3. Generated code owns evidence-derived structure and presentation facts; handwritten code owns
   semantic interpretation and behavior and does not recreate generated trees.
4. Scoped FourCC selectors are for recovery and binding, typed domain IDs express meaning, and
   `Entity` is the runtime address. There is no additional application UI identity namespace.
5. FourCC lookup and recovered-tree traversal stop after binding a newly spawned scene. Normal
   behavior and rendering do not rediscover static controls.
6. A screen or dialog root retains only the addresses and semantic state that must survive binding
   in one semantic view. It does not cache presentation facts already owned by addressed entities or
   identities already expressed by typed table keys. Nested row and control structures are normally
   plain Rust structs.
7. Bind-time constants needed only by an event handler are captured in that observer's closure, not
   stored as components. Store a leaf component only when other independent systems need to query
   it, or it describes genuinely first-class behavior or relationship.
8. Renderers are coarse by default and split only for a concrete independent lifecycle, cadence, or
   expensive surface. There is no generic reactive or binding framework.
9. Generated variants with the same semantics share handwritten binding through compact recovered-
   tag tables. Generated per-node fields are not a public application API.
10. Change this contract explicitly before introducing a selector registry, generated typed screen
    API, `Binding<T>`, lenses, a generic ownership graph, or equivalent infrastructure. Such an
    architectural change must not arrive incidentally inside a screen refactor.
