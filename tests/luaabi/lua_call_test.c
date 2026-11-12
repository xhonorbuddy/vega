/* Host test: exercises the vendored Lua with the client-matched layouts
   (CallInfo 0x38, CClosure f at 0x30) without the game. */

#include <stdio.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lobject.h"
#include "lstate.h"
#include "ltable.h"

static int hello(lua_State* L) {
    lua_pushstring(L, "hello");
    return 1;
}

static const luaL_Reg api[] = {
    { "AFK", hello },
    { NULL, NULL },
};

int main(void) {
    lua_State* L = luaL_newstate();

    if (L == NULL) {
        printf("luaL_newstate failed\n");
        return 1;
    }

    luaL_openlibs(L);

    /* Same call shape as DllMain: create global table C and register AFK. */
    luaL_register(L, "C", api);

    if (luaL_dostring(L, "print(C.AFK())") != 0) {
        printf("script error: %s\n", lua_tostring(L, -1));
        lua_close(L);
        return 1;
    }

    lua_close(L);
    printf("RESULT: PASS\n");
    return 0;
}
