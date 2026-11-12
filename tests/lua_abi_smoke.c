#include <stdio.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lstate.h"

static int hello(lua_State *L) {
  lua_pushstring(L, "hello");
  return 1;
}

int main(void) {
  lua_State *L = luaL_newstate();
  if (!L) return 1;
  luaL_openlibs(L);
  lua_register(L, "C", hello);
  if (luaL_dostring(L,
      "assert(C() == 'hello'); "
      "local t = {}; for i=1,10000 do t['key'..i] = i end; "
      "for i=1,10000 do assert(t['key'..i] == i) end; "
      "local co = coroutine.create(function() local n=42; "
      "return function() return n end end); "
      "local ok,f = coroutine.resume(co); assert(ok and f()==42); "
      "collectgarbage('collect'); assert(C() == 'hello')")) {
    fprintf(stderr, "%s\n", lua_tostring(L, -1));
    lua_close(L);
    return 2;
  }
  lua_close(L);
  puts("Lua ABI smoke test passed");
  return 0;
}
