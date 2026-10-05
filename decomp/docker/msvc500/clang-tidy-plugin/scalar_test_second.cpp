#include "scalar_test.h"
void ObserveStorageSpecializations()
{
    fixture_int_storage.storage_count = 1;
    fixture_unsigned_storage.storage_count = 2;
}
void StoreDuration(int milliseconds)
{
    g_scalar_state.stored_duration = milliseconds;
}

void MutateOverload(int* value) { *value = 1; }

void InvokeFixtureCallback()
{
    int callback_argument = 7;
    int callback_result = fixture_callback(callback_argument);
}

// A separately declared external twin keeps its numeric use out of the bool domain.
unsigned char FixtureTwinFlag();
int CountTwinFlag()
{
    return FixtureTwinFlag() + 1;
}
