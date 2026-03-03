#pragma once

#include "decomp_types.h"

#if !defined(_MSC_VER)
#ifndef __fastcall
#define __fastcall
#endif
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

template <typename Ret, typename A0, typename A1>
static __inline Ret fastcall2_with_edx(void* object, unsigned int slot_index, int edx_value, A0 a0,
                                       A1 a1) {
  typedef Ret(__fastcall * Fn)(void*, int, A0, A1);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, edx_value, a0, a1);
}

template <typename Ret, typename A0, typename A1, typename A2>
static __inline Ret fastcall3_with_edx(void* object, unsigned int slot_index, int edx_value, A0 a0,
                                       A1 a1, A2 a2) {
  typedef Ret(__fastcall * Fn)(void*, int, A0, A1, A2);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, edx_value, a0, a1, a2);
}

template <typename Ret> static __inline Ret thiscall0(void* object, unsigned int slot_index) {
  typedef Ret(__fastcall * Fn)(void*);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object);
}

template <typename Ret, typename A0>
static __inline Ret thiscall1(void* object, unsigned int slot_index, A0 a0) {
  return fastcall1<Ret>(object, slot_index, a0);
}

template <typename Ret, typename A0, typename A1>
static __inline Ret thiscall2(void* object, unsigned int slot_index, A0 a0, A1 a1) {
  return fastcall2<Ret>(object, slot_index, a0, a1);
}

template <typename Ret, typename A0, typename A1, typename A2>
static __inline Ret thiscall3(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2) {
  return fastcall3<Ret>(object, slot_index, a0, a1, a2);
}

template <typename Ret, typename A0, typename A1, typename A2, typename A3>
static __inline Ret thiscall4(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2, A3 a3) {
  return fastcall4<Ret>(object, slot_index, a0, a1, a2, a3);
}

static __inline void thiscall0v(void* object, unsigned int slot_index) {
  typedef void(__fastcall * Fn)(void*);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object);
}

template <typename A0> static __inline void thiscall1v(void* object, unsigned int slot_index, A0 a0) {
  fastcall1v(object, slot_index, a0);
}

template <typename A0, typename A1>
static __inline void thiscall2v(void* object, unsigned int slot_index, A0 a0, A1 a1) {
  fastcall2v(object, slot_index, a0, a1);
}

template <typename A0, typename A1, typename A2>
static __inline void thiscall3v(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2) {
  fastcall3v(object, slot_index, a0, a1, a2);
}

template <typename A0, typename A1, typename A2, typename A3>
static __inline void thiscall4v(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2, A3 a3) {
  fastcall4v(object, slot_index, a0, a1, a2, a3);
}

template <typename Ret> static __inline Ret cdecl0(void* object, unsigned int slot_index) {
  typedef Ret(__cdecl * Fn)(void*);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object);
}

template <typename Ret, typename A0>
static __inline Ret cdecl1(void* object, unsigned int slot_index, A0 a0) {
  typedef Ret(__cdecl * Fn)(void*, A0);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, a0);
}

template <typename Ret, typename A0, typename A1>
static __inline Ret cdecl2(void* object, unsigned int slot_index, A0 a0, A1 a1) {
  typedef Ret(__cdecl * Fn)(void*, A0, A1);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, a0, a1);
}

template <typename Ret, typename A0, typename A1, typename A2>
static __inline Ret cdecl3(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2) {
  typedef Ret(__cdecl * Fn)(void*, A0, A1, A2);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, a0, a1, a2);
}

template <typename Ret, typename A0, typename A1, typename A2, typename A3>
static __inline Ret cdecl4(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2, A3 a3) {
  typedef Ret(__cdecl * Fn)(void*, A0, A1, A2, A3);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, a0, a1, a2, a3);
}

static __inline void cdecl0v(void* object, unsigned int slot_index) {
  typedef void(__cdecl * Fn)(void*);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object);
}

template <typename A0> static __inline void cdecl1v(void* object, unsigned int slot_index, A0 a0) {
  typedef void(__cdecl * Fn)(void*, A0);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, a0);
}

template <typename A0, typename A1>
static __inline void cdecl2v(void* object, unsigned int slot_index, A0 a0, A1 a1) {
  typedef void(__cdecl * Fn)(void*, A0, A1);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, a0, a1);
}

template <typename A0, typename A1, typename A2>
static __inline void cdecl3v(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2) {
  typedef void(__cdecl * Fn)(void*, A0, A1, A2);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, a0, a1, a2);
}

template <typename A0, typename A1, typename A2, typename A3>
static __inline void cdecl4v(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2, A3 a3) {
  typedef void(__cdecl * Fn)(void*, A0, A1, A2, A3);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, a0, a1, a2, a3);
}

template <typename Ret> static __inline Ret stdcall0(void* object, unsigned int slot_index) {
  typedef Ret(__stdcall * Fn)(void*);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object);
}

template <typename Ret, typename A0>
static __inline Ret stdcall1(void* object, unsigned int slot_index, A0 a0) {
  typedef Ret(__stdcall * Fn)(void*, A0);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, a0);
}

template <typename Ret, typename A0, typename A1>
static __inline Ret stdcall2(void* object, unsigned int slot_index, A0 a0, A1 a1) {
  typedef Ret(__stdcall * Fn)(void*, A0, A1);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, a0, a1);
}

template <typename Ret, typename A0, typename A1, typename A2>
static __inline Ret stdcall3(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2) {
  typedef Ret(__stdcall * Fn)(void*, A0, A1, A2);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, a0, a1, a2);
}

template <typename Ret, typename A0, typename A1, typename A2, typename A3>
static __inline Ret stdcall4(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2, A3 a3) {
  typedef Ret(__stdcall * Fn)(void*, A0, A1, A2, A3);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  return fn(object, a0, a1, a2, a3);
}

static __inline void stdcall0v(void* object, unsigned int slot_index) {
  typedef void(__stdcall * Fn)(void*);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object);
}

template <typename A0>
static __inline void stdcall1v(void* object, unsigned int slot_index, A0 a0) {
  typedef void(__stdcall * Fn)(void*, A0);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, a0);
}

template <typename A0, typename A1>
static __inline void stdcall2v(void* object, unsigned int slot_index, A0 a0, A1 a1) {
  typedef void(__stdcall * Fn)(void*, A0, A1);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, a0, a1);
}

template <typename A0, typename A1, typename A2>
static __inline void stdcall3v(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2) {
  typedef void(__stdcall * Fn)(void*, A0, A1, A2);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, a0, a1, a2);
}

template <typename A0, typename A1, typename A2, typename A3>
static __inline void stdcall4v(void* object, unsigned int slot_index, A0 a0, A1 a1, A2 a2, A3 a3) {
  typedef void(__stdcall * Fn)(void*, A0, A1, A2, A3);
  Fn fn = reinterpret_cast<Fn>(resolve_slot(object, slot_index));
  fn(object, a0, a1, a2, a3);
}

} // namespace vcall_runtime
