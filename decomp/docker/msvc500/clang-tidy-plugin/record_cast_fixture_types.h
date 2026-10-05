#pragma once

#line 1 "/home/build/imperialism/include/game/clang_tidy_record_fixture_types.h"
namespace cast_fixture {
struct A {};
struct B {};
struct C {};
struct Prefix {
    int prefix;
};
struct Base {
    int base;
};
struct Derived : Prefix, Base {
    int derived;
};
struct Controls {};
struct Renderer {
    struct Pick {};
};

inline B* shared_header_erasure(A* value)
{
    return reinterpret_cast<B*>(static_cast<void*>(value));
}
} // namespace cast_fixture

#line 1 "/opt/msvc5/include/vendor_fixture.h"
#pragma clang system_header
namespace cast_vendor {
struct VendorCollision {};
} // namespace cast_vendor
