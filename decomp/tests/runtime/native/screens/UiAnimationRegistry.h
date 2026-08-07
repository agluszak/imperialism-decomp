#pragma once

#ifndef IMPERIALISM_UI_ANIMATION_REGISTRY_H
#define IMPERIALISM_UI_ANIMATION_REGISTRY_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error UiAnimationRegistry is test-only and must not be included in the production build
#endif

// The animator's transient registry, as a scenario sees it.
//
// Not a screen: it is the global list of animations the current screen owns, and what a test
// wants to know about it is whether a screen change took its animations with it. An animation
// left registered after its owning view is gone is a dangling per-frame blit into a freed view.
class UiAnimationRegistry {
public:
  // False when there is no animator yet, which is a different thing from an empty registry.
  static bool IsReady();
  static int Count();
  static bool Contains(int tag);
};

#endif
