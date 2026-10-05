#include "record_cast_fixture_types.h"

#line 1 "/imperialism/src/game/clang_tidy_record_cast_fixture_second.cpp"
cast_fixture::B* repeated_header_from_second_translation_unit(cast_fixture::A* value)
{
    return cast_fixture::shared_header_erasure(value);
}
