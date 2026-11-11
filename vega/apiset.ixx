module;
#include <Windows.h>

export module manualmap.apiset;

export namespace manualmap {
inline constexpr ULONG API_SET_SCHEMA_ENTRY_FLAGS_SEALED = 1;

struct API_SET_NAMESPACE {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
};

struct API_SET_HASH_ENTRY {
    ULONG Hash;
    ULONG Index;
};

struct API_SET_NAMESPACE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
};

struct API_SET_VALUE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
};
}
