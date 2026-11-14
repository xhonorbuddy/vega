module;
#include <windows.h>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <cstring>
#include "luaconf.h"
#undef LUA_API
#define LUA_API extern "C"
#include "lua.h"
#include "lauxlib.h"

export module grid.object_api;
import grid.wow;
import grid.wow_api;
import grid.object_manager;
import grid.lua_registration;

export namespace grid::object_api {
extern const luaL_Reg functions[];
bool initialize(lua_State* L);
}

namespace grid::object_api {
namespace {
constexpr const char* metatable=object_manager::metatable_name;
using handle=object_manager::handle;
int failure(lua_State* L,const char* reason) { lua_pushnil(L); lua_pushstring(L,reason); return 2; }
handle* checked(lua_State* L,int index) {
    auto* value=static_cast<handle*>(luaL_checkudata(L,index,metatable));
    if (lua_objlen(L,index)!=sizeof(handle)) luaL_error(L,"invalid entity handle size");
    return value;
}
void push(lua_State* L,wow::guid id) {
    auto* value=static_cast<handle*>(lua_newuserdata(L,sizeof(handle)));
    value->id=id;
    luaL_getmetatable(L,metatable);
    lua_setmetatable(L,-2);
}
void push_guid(lua_State* L,wow::guid id) {
    char text[35]{};
    std::snprintf(text,sizeof(text),"0x%016llX%016llX",
        static_cast<unsigned long long>(id.high),static_cast<unsigned long long>(id.low));
    lua_pushstring(L,text);
}
bool parse_guid(lua_State* L,int index,wow::guid& id) {
    if (lua_type(L,index)!=LUA_TSTRING) return false;
    std::size_t count{};
    const auto* text=lua_tolstring(L,index,&count);
    if (count!=34 || text[0]!='0' || (text[1]!='x' && text[1]!='X')) return false;
    const auto hi=std::from_chars(text+2,text+18,id.high,16);
    const auto lo=std::from_chars(text+18,text+34,id.low,16);
    return hi.ec==std::errc{} && hi.ptr==text+18 && lo.ec==std::errc{} && lo.ptr==text+34;
}
int valid(lua_State* L) {
    const auto id=checked(L,1)->id;
    lua_pushboolean(L,object_manager::lookup(id)!=nullptr);
    return 1;
}
int guid(lua_State* L) { push_guid(L,checked(L,1)->id); return 1; }
int equal(lua_State* L) {
    const auto a=checked(L,1)->id,b=checked(L,2)->id;
    lua_pushboolean(L,a==b); return 1;
}
int text(lua_State* L) { push_guid(L,checked(L,1)->id); return 1; }
// Reuse the existing guarded entity queries after resolving identity on every call.
template<wow_api::property Kind> int property(lua_State* L) {
    const auto id=checked(L,1)->id;
    if (const auto* reason=object_manager::ready_reason()) return failure(L,reason);
    auto* object=object_manager::lookup(id);
    if (!object) return failure(L,"object is no longer available");
    lua_pushlightuserdata(L,object); lua_replace(L,1);
    return wow_api::read(L,Kind);
}
template<wow_api::property Kind> int coordinates(lua_State* L) {
    const int count=property<Kind>(L);
    if (count!=1 || !lua_istable(L,-1)) return count;
    const auto table=lua_gettop(L);
    lua_getfield(L,table,"x"); lua_getfield(L,table,"y"); lua_getfield(L,table,"z");
    lua_remove(L,table); return 3;
}
int base(lua_State* L) {
    const auto id=checked(L,1)->id;
    auto* object=object_manager::lookup(id);
    if (!object) return failure(L,"object is no longer available");
    char address[19]{};
    std::snprintf(address,sizeof(address),"0x%016llX",static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(object)));
    lua_pushstring(L,address); return 1;
}
int is_a(lua_State* L) {
    const auto id=checked(L,1)->id;
    const auto number=luaL_checknumber(L,2);
    if (!std::isfinite(number) || number<0 || number>14 || number!=static_cast<int>(number))
        return luaL_error(L,"type must be an integer from 0 to 14");
    auto* object=object_manager::lookup(id);
    if (!object) return failure(L,"object is no longer available");
    lua_pushboolean(L,object->isA(static_cast<wow::gameobject>(static_cast<int>(number))));
    return 1;
}
const luaL_Reg methods[]={
    {"Valid",valid},{"GUID",guid},{"IsA",is_a},{"Base",base},
    {"Type",property<wow_api::property::type>},{"Owner",property<wow_api::property::owner>},{"Target",property<wow_api::property::target>},{"TargetGUID",property<wow_api::property::target>},
    {"Health",property<wow_api::property::health>},{"Power",property<wow_api::property::power>},{"ManaPower",property<wow_api::property::power>},
    {"Flags",property<wow_api::property::flags>},{"Flags3",property<wow_api::property::flags3>},{"Name",property<wow_api::property::name>},
    {"Position",coordinates<wow_api::property::position>},{"PlatePosition",coordinates<wow_api::property::plate>},{"Facing",property<wow_api::property::facing>},
    {"IsDead",property<wow_api::property::dead>},{"DeadOrGhost",property<wow_api::property::ghost>},
    {"AnimationFlags",property<wow_api::property::animation>},{"Animating",property<wow_api::property::bite>},
    {"Info",property<wow_api::property::info>},{"__eq",equal},{"__tostring",text},{nullptr,nullptr}
};
bool snapshot(lua_State* L,wow::guid*& ids,std::size_t& count,const char*& error) {
    // Lua owns the temporary buffer, including when allocation or a later API
    // operation exits through Lua's nonlocal error path. No C++ destructors cross Lua.
    if ((error=object_manager::ready_reason())!=nullptr) return false;
    ids=static_cast<wow::guid*>(lua_newuserdata(L,object_manager::max_objects*sizeof(wow::guid)));
    return object_manager::enumerate(ids,object_manager::max_objects,count,error);
}
int object(lua_State* L) {
    std::size_t length{};
    const auto* identifier=luaL_checklstring(L,1,&length);
    wow::guid id{};
    if (parse_guid(L,1,id)) {
        if (const auto* reason=object_manager::ready_reason()) return failure(L,reason);
        if (!object_manager::lookup(id)) return failure(L,"object is no longer available");
        push(L,id); return 1;
    }
    if (length>1 && identifier[0]=='0' && (identifier[1]=='x' || identifier[1]=='X'))
        return luaL_error(L,"expected a full 0x-prefixed 32-digit GUID");
    if (!length || length>=512 || std::memchr(identifier,0,length))
        return luaL_error(L,"expected an object name of 1 to 511 bytes");
    wow::guid* ids{}; std::size_t count{};
    const char* error{};
    if (!snapshot(L,ids,count,error)) return failure(L,error);
    for (std::size_t i=0;i<count;++i) {
        const auto candidate=ids[i];
        auto* value=object_manager::lookup(candidate);
        if (object_manager::name_is(value,identifier,length)) { push(L,candidate); return 1; }
    }
    return failure(L,"object was not found");
}

int statistics(lua_State* L) {
    const auto stats=object_manager::last_statistics();
    lua_createtable(L,0,6);
    const char* names[]={"enumerated","unique","lookups","missing","invalid","mismatched"};
    const std::size_t values[]={stats.enumerated,stats.unique,stats.lookups,stats.missing,stats.invalid,stats.mismatched};
    for (unsigned i=0;i<6;++i) { lua_pushnumber(L,static_cast<lua_Number>(values[i])); lua_setfield(L,-2,names[i]); }
    return 1;
}
int objects(lua_State* L) {
    if (lua_type(L,1)==LUA_TSTRING) return object(L);
    int type=-1;
    bool derived=false;
    if (!lua_isnoneornil(L,1)) {
        const auto number=luaL_checknumber(L,1);
        if (!std::isfinite(number) || number<0 || number>14 || number!=static_cast<int>(number))
            return luaL_error(L,"type must be an integer from 0 to 14");
        type=static_cast<int>(number); derived=lua_toboolean(L,2)!=0;
    }
    wow::guid* ids{}; std::size_t count{};
    const char* error{};
    if (!snapshot(L,ids,count,error)) return failure(L,error);
    lua_createtable(L,static_cast<int>(count),0);
    int index=1;
    for (std::size_t i=0;i<count;++i) {
        const auto id=ids[i];
        auto* entity=object_manager::lookup(id);
        if (!entity) continue;
        if (type>=0 && (derived ? !entity->isA(static_cast<wow::gameobject>(type)) : entity->type()!=type)) continue;
        push(L,id); lua_rawseti(L,-2,index++);
    }
    return 1;
}
}
const luaL_Reg functions[]={ {"Objects",objects},{"ObjectsFiltered",objects},{"Object",object},{"ObjectManagerStats",statistics},{nullptr,nullptr} };
bool initialize(lua_State* L) {
    const auto top=lua_gettop(L);
    luaL_newmetatable(L,metatable);
    if (!lua_registration::register_api(L,nullptr,methods)) { lua_settop(L,top); return false; }
    lua_pushvalue(L,-1); lua_setfield(L,-2,"__index");
    lua_pushliteral(L,"grid.entity"); lua_setfield(L,-2,"__metatable");
    lua_settop(L,top);
    return true;
}
}
