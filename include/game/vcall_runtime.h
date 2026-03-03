#pragma once

#include "decomp_types.h"

#ifndef __fastcall
#define __fastcall
#endif

namespace vcall_runtime {

static __inline void* resolve_slot(void* object, unsigned int slot_index) {
  return (*reinterpret_cast<void***>(object))[slot_index];
}

template <typename Ret> static __inline Ret fastcall0(void* object, unsigned int slot_index) {
  typedef Ret(__fastcall * Fn)(void*, int);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, 0);
}

template <typename Ret, typename A0>
static __inline Ret fastcall1(void* object, unsigned int slot_index, A0 a0) {
  typedef Ret(__fastcall * Fn)(void*, int, A0);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, 0, a0);
}

template <typename Ret, typename A0, typename A1>
static __inline Ret fastcall2(void* object, unsigned int slot_index, A0 a0, A1 a1) {
  typedef Ret(__fastcall * Fn)(void*, int, A0, A1);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, 0, a0, a1);
}

template <typename Ret, typename A0, typename A1, typename A2>
static __inline Ret fastcall3(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2) {
  typedef Ret(__fastcall * Fn)(void*, int, A0, A1, A2);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, 0, a0, a1, a2);
}

template <typename Ret, typename A0, typename A1, typename A2, typename A3>
static __inline Ret fastcall4(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2, A3 a3) {
  typedef Ret(__fastcall * Fn)(void*, int, A0, A1, A2, A3);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, 0, a0, a1, a2, a3);
}

static __inline void fastcall0v(void* object, unsigned int slot_index) {
  typedef void(__fastcall * Fn)(void*, int);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, 0);
}

template <typename A0>
static __inline void fastcall1v(void* object, unsigned int slot_index, A0 a0) {
  typedef void(__fastcall * Fn)(void*, int, A0);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, 0, a0);
}

template <typename A0, typename A1>
static __inline void fastcall2v(void* object, unsigned int slot_index, A0 a0, A1 a1) {
  typedef void(__fastcall * Fn)(void*, int, A0, A1);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, 0, a0, a1);
}

template <typename A0, typename A1, typename A2>
static __inline void fastcall3v(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2) {
  typedef void(__fastcall * Fn)(void*, int, A0, A1, A2);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, 0, a0, a1, a2);
}

template <typename A0, typename A1, typename A2, typename A3>
static __inline void fastcall4v(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2, A3 a3) {
  typedef void(__fastcall * Fn)(void*, int, A0, A1, A2, A3);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, 0, a0, a1, a2, a3);
}

template <typename A0, typename A1>
static __inline void fastcall2v_with_edx(void* object, unsigned int slot_index, int edx_value,
                                         A0 a0, A1 a1) {
  typedef void(__fastcall * Fn)(void*, int, A0, A1);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, edx_value, a0, a1);
}

template <typename A0, typename A1, typename A2>
static __inline void fastcall3v_with_edx(void* object, unsigned int slot_index, int edx_value,
                                         A0 a0, A1 a1, A2 a2) {
  typedef void(__fastcall * Fn)(void*, int, A0, A1, A2);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, edx_value, a0, a1, a2);
}

static __inline void thiscall0v(void* object, unsigned int slot_index) {
  typedef void(__fastcall * Fn)(void*);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object);
}

} // namespace vcall_runtime
