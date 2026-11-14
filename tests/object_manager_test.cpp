#include <windows.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <vector>
extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lobject.h"
#include "ltable.h"
}
import grid.entity_client;
import grid.wow;
import grid.wow_api;
import grid.object_manager;
import grid.object_api;
import grid.breakpoint;
import grid.exceptions;
import grid.lua_registration;

using namespace grid;
using namespace grid::wow;
static_assert(sizeof(Udata)==0x30 && offsetof(Udata,uv.metatable)==0x18 &&
              offsetof(Udata,uv.env)==0x20 && offsetof(Udata,uv.len)==0x28);
namespace {
struct alignas(16) storage { std::array<std::byte,0x3000> bytes{}; bool live{true}; } objects[3];
std::array<std::array<uintptr_t,80>,15> vtables{};
uint16_t flags=0x10;
int32_t requests{};
struct index_entry { uint32_t state{},reserved{}; uintptr_t entity{}; };
std::array<index_entry,5> entries{};
struct index_header { uintptr_t unused{}; index_entry* entries{}; uint64_t count{}; } index;
std::array<std::array<std::byte,0x60>,3> ecs{};
std::array<std::array<std::byte,0x450>,3> metadata{};
std::array<std::byte,48> banks{};
std::array<uintptr_t,6> out_of_line{};
uintptr_t counter=reinterpret_cast<uintptr_t>(&requests),layer{},manager=1,visible{};
bool enumerate_fault{},enumerate_overflow{};
template<class T> void put(storage& object,size_t offset,T value) {
    std::memcpy(object.bytes.data()+offset,&value,sizeof(value));
}
entity* at(unsigned i) { return reinterpret_cast<entity*>(objects[i].bytes.data()); }
const char* name(entity* object) { return object->type()==GAMEOBJECT ? "Bobber" : "Unit"; }
vector3* position(entity*,vector3* out) { *out={1,2,3}; return out; }
float facing(entity*) { return 0.5f; }
int power(entity*,int8_t type) { return type==0 ? 1 : 0; }
bool death(entity*) { return true; }
bool ghost(entity*) { return false; }
// The script-facing native wrapper deliberately fails in this regression test.
// Object resolution must use the real index layout, not this stand-in.
entity* lookup(const guid*,int,const char*,int) { return nullptr; }

bool enumerate(unsigned int (*callback)(const guid*,uintptr_t)) {
    if (enumerate_fault) { RaiseException(EXCEPTION_ACCESS_VIOLATION,0,0,nullptr); return false; }
    if (enumerate_overflow) {
        const auto id=at(0)->id();
        for (unsigned i=0;i<65537;++i) if (!callback(&id,0)) return false;
        return true;
    }
    for (unsigned i=0;i<3;++i) {
        const auto id=at(i)->id();
        if (!callback(&id,0)) return false;
    }
    return true;
}
int conflicting_registration(lua_State* L) {
    lua_registration::register_api(L,"BadLibrary",object_api::functions);
    return 0;
}
bool run(lua_State* L,const char* script) {
    if (!luaL_dostring(L,script)) return true;
    std::fprintf(stderr,"%s\n",lua_tostring(L,-1)); return false;
}
}
int main() {
    entity_client::bindings b{};
    for (unsigned i=0;i<15;++i) {
        vtables[i][15]=reinterpret_cast<uintptr_t>(position);
        vtables[i][52]=reinterpret_cast<uintptr_t>(name);
        vtables[i][75]=reinterpret_cast<uintptr_t>(ghost);
        b.vtables[i]=reinterpret_cast<uintptr_t>(vtables[i].data());
    }
    const uint8_t types[]={UNIT,ACTIVEPLAYER,GAMEOBJECT};
    for (unsigned i=0;i<3;++i) {
        ::new(objects[i].bytes.data()) entity;
        put(objects[i],0,b.vtables[types[i]]);
        put(objects[i],0x10,guid{100+i,uint64_t{2}<<58});
        put(objects[i],0x24,types[i]); put(objects[i],0x25,types[i]);
        put(objects[i],0x1e28,int64_t{5000000000});
        put(objects[i],0x1bc4,int32_t{99});
        put(objects[i],0x1c9,uint8_t{17});put(objects[i],0x114,uint8_t{0x13});
        put(objects[i],0x1d88,guid{77,uint64_t{2}<<58});
    }
    auto write=[](void* data,std::size_t offset,const auto& value) {
        std::memcpy(static_cast<std::byte*>(data)+offset,&value,sizeof(value));
    };
    for (unsigned i=0;i<3;++i) {
        write(ecs[i].data(),8,reinterpret_cast<uintptr_t>(metadata[i].data()));
        write(ecs[i].data(),0x10,uint32_t{0});
        write(metadata[i].data(),0x34,int32_t{0x30});
        write(ecs[i].data(),0x30,reinterpret_cast<uintptr_t>(at(i)));
        entries[i]={0x80000000,0,reinterpret_cast<uintptr_t>(ecs[i].data())};
    }
    // Exercise the external component-bank form as well as inline components.
    write(metadata[2].data(),0x34,uint32_t{0x80000002});
    write(metadata[2].data(),0x448,reinterpret_cast<uintptr_t>(banks.data()));
    out_of_line[4]=reinterpret_cast<uintptr_t>(at(2));
    write(banks.data(),0x18,reinterpret_cast<uintptr_t>(out_of_line.data()));
    entries[3]={0xbfffffff,0,1}; // Tombstone, despite the sign bit.
    entries[4]={0,0,1}; // Inactive entry.
    index.entries=entries.data(); index.count=entries.size();
    visible=reinterpret_cast<uintptr_t>(&index);
    b.enumerate=reinterpret_cast<uintptr_t>(enumerate); b.lookup=reinterpret_cast<uintptr_t>(lookup);
    b.position=reinterpret_cast<uintptr_t>(position); b.facing=reinterpret_cast<uintptr_t>(facing);
    b.power=reinterpret_cast<uintptr_t>(power); b.death=reinterpret_cast<uintptr_t>(death);
    b.flags=reinterpret_cast<uintptr_t>(&flags); b.counter=reinterpret_cast<uintptr_t>(&counter);
    b.layer=reinterpret_cast<uintptr_t>(&layer); b.manager=reinterpret_cast<uintptr_t>(&manager);
    b.visible=reinterpret_cast<uintptr_t>(&visible);
    b.vtables[GAMEOBJECT]=0; // Exercise native-lookup confirmation for inaccessible ctor pages.
    entity_client::configure_for_tests(b);
    object_manager::set_game_thread(GetCurrentThreadId()); wow_api::set_game_thread(GetCurrentThreadId());
    // Use the real pool and VEH so every global and metatable callback traverses INT3.
    auto* image=static_cast<unsigned char*>(VirtualAlloc(nullptr,0x2000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!image) return 1;
    auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(image);dos->e_magic=IMAGE_DOS_SIGNATURE;dos->e_lfanew=0x100;
    auto* nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(image+0x100);nt->Signature=IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;nt->FileHeader.NumberOfSections=1;
    nt->FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER64);nt->OptionalHeader.SizeOfImage=0x2000;
    auto* section=IMAGE_FIRST_SECTION(nt);section->Characteristics=IMAGE_SCN_MEM_EXECUTE;
    section->VirtualAddress=0x1000;section->Misc.VirtualSize=0x1000;
    const unsigned char bytes[]={0xC3,0xCC,0xCC,0xCC,0xCC,0x48};
    for (unsigned i=0;i<100;++i) std::memcpy(image+0x1000+16*i,bytes,sizeof(bytes));
    DWORD old{};VirtualProtect(image+0x1000,0x1000,PAGE_EXECUTE_READ,&old);
    FlushInstructionCache(GetCurrentProcess(),image+0x1000,0x1000);
    if (!breakpoint::resolve(reinterpret_cast<uintptr_t>(image)) || !exceptions::start()) return 2;
    // Model a host runtime with its own empty hash sentinel. Library-created
    // tables must carry that identity so host GC never frees the DLL sentinel.
    static Node host_dummy{};
    luaH_set_dummynode(&host_dummy);
    lua_State* L=luaL_newstate();if (!L) return 3;luaL_openlibs(L);
    lua_createtable(L,3,0);
    if (static_cast<const Table*>(lua_topointer(L,-1))->node!=&host_dummy) return 17;
    lua_pushliteral(L,"test");lua_setfield(L,-2,"hash");
    lua_pop(L,1);lua_gc(L,LUA_GCCOLLECT,0);
    if (!object_api::initialize(L) || lua_gettop(L)!=0) return 4;
    if (!lua_registration::register_api(L,"C",wow_api::functions) ||
        !lua_registration::register_api(L,nullptr,object_api::functions)) return 5;
    lua_pop(L,1);
    const luaL_Reg extra[]={{"RegistrationError",conflicting_registration},{nullptr,nullptr}};
    if (!lua_registration::register_api(L,"C",extra)) return 16;
    lua_pop(L,1);
    if (!run(L,R"lua(
        assert(C.IsInWorld() and not C.IsLoading())
        local all=C.Objects(); assert(#all==3)
        local stats=C.ObjectManagerStats(); assert(stats.enumerated==3 and stats.unique==3 and stats.missing==0)
        saved=all[1]
        assert(type(saved)=='userdata' and getmetatable(saved)=='grid.entity')
        assert(saved:Valid() and saved:IsA(5) and saved:Type()==5)
        assert(saved:Name()=='Unit' and saved:Health()==5000000000)
        local n,exact=saved:Health(); assert(exact=='5000000000')
        assert(saved:Power(0)==99 and saved:Facing()==0.5)
        local x,y,z=saved:Position(); assert(x==1 and y==2 and z==3)
        assert(not saved:IsDead() and not saved:DeadOrGhost())
        assert(C.Object(saved:GUID())==saved and tostring(saved)==saved:GUID())
        assert(C.Object('Unit')==saved and C.Objects('Unit')==saved)
        assert(C.Objects(saved:GUID())==saved and C.Objects('Bobber'):Type()==8)
        assert(saved:Base():match('^0x%x+$'))
        assert(C.ObjectInfo(saved).guid==saved:GUID())
        assert(C.ObjectName(saved)=='Unit')
        assert(#C.Objects(5)==1 and #C.Objects(5,true)==2 and #C.Objects(14)==0)
        assert(all[3]:Animating() and all[3]:Type()==8)
        local value,err=all[3]:Health();assert(value==nil and err:find('requires a Unit',1,true))
        assert(not pcall(function() saved:IsA(99) end))
        assert(not pcall(function() C.Objects(0/0) end))
        assert(not pcall(function() C.Object('0xgarbage') end))
        BadLibrary=42
        assert(not pcall(C.RegistrationError))
        assert(C.Object('Does Not Exist')==nil)
        for i=1,30 do
            local batch=C.Objects()
            assert(#batch==3 and C.Object('Unit')==batch[1])
            collectgarbage('collect')
        end
        collectgarbage('collect')
        assert(saved:Valid())
    )lua")) return 6;
    if (entity_client::get().vtables[GAMEOBJECT]!=reinterpret_cast<uintptr_t>(vtables[GAMEOBJECT].data())) return 15;
    objects[0].live=false; entries[0].state=0;
    if (!run(L,"assert(not saved:Valid()); local v,e=saved:Health(); assert(v==nil and e:find('no longer',1,true)); assert(#C.Objects()==2)")) return 7;
    objects[0].live=true; entries[0].state=0x80000000;
    put(objects[0],0x25,uint8_t{0x12});
    if (!run(L,"assert(not saved:Valid() and #C.Objects()==2)")) return 8;
    put(objects[0],0x25,uint8_t{UNIT});
    requests=1;
    if (!run(L,"assert(C.IsLoading()); local v,e=C.Objects(); assert(v==nil and e:find('not ready',1,true)); assert(not saved:Valid())")) return 9;
    requests=0;layer=1;
    if (!run(L,"assert(C.IsLoading() and not saved:Valid())")) return 10;
    layer=0;object_manager::set_game_thread(GetCurrentThreadId()+1);
    if (!run(L,"local v,e=C.Objects(); assert(v==nil and e:find('game thread',1,true))")) return 11;
    object_manager::set_game_thread(GetCurrentThreadId());
    enumerate_fault=true;
    if (!run(L,"local v,e=C.Objects(); assert(v==nil and e:find('enumeration failed',1,true))")) return 12;
    enumerate_fault=false;enumerate_overflow=true;
    if (!run(L,"local v,e=C.Objects(); assert(v==nil and e:find('limit exceeded',1,true))")) return 13;
    enumerate_overflow=false;
    if (!run(L,"assert(#C.Objects()==3 and saved:Valid())")) return 14;
    lua_close(L);luaH_set_dummynode(nullptr);exceptions::stop();VirtualFree(image,0,MEM_RELEASE);
    std::puts("Object manager/metatable integration passed through INT3 routing");
}
