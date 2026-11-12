/* Prints the effective x64 layout of the WoW-patched Lua structures so the
   WOW_ABI_OFFSET assertions in lstate.h can be checked against the real
   compiler output. */

#include <stdio.h>
#include <stddef.h>

#include "lua.h"
#include "lobject.h"
#include "lstate.h"

#define SHOW_OFF(t, f) printf("  %-34s 0x%03x\n", #t "." #f, (unsigned)offsetof(t, f))
#define SHOW_SIZE(t) printf("%-36s 0x%03x (%u)\n", "sizeof(" #t ")", (unsigned)sizeof(t), (unsigned)sizeof(t))

int main(void) {
    printf("== TValue ==\n");
    SHOW_SIZE(TValue);
    SHOW_OFF(TValue, value);
    SHOW_OFF(TValue, tt);
    SHOW_OFF(TValue, taint);

    printf("== GC header ==\n");
    SHOW_SIZE(GCheader);
    SHOW_OFF(GCheader, next);
    SHOW_OFF(GCheader, taint);
    SHOW_OFF(GCheader, tt);
    SHOW_OFF(GCheader, marked);

    printf("== Table ==\n");
    SHOW_SIZE(Table);
    SHOW_OFF(Table, flags);
    SHOW_OFF(Table, lsizenode);
    SHOW_OFF(Table, metatable);
    SHOW_OFF(Table, array);
    SHOW_OFF(Table, node);
    SHOW_OFF(Table, lastfree);
    SHOW_OFF(Table, gclist);
    SHOW_OFF(Table, sizearray);

    printf("== Node / TKey ==\n");
    SHOW_SIZE(Node);
    SHOW_OFF(Node, i_val);
    SHOW_OFF(Node, i_key);
    SHOW_OFF(Node, i_key.nk.next);
    SHOW_OFF(Node, i_key.nk.tt);
    SHOW_OFF(Node, i_key.tvk);

    printf("== TString ==\n");
    SHOW_SIZE(TString);
    SHOW_OFF(TString, tsv.hash);
    SHOW_OFF(TString, tsv.len);

    printf("== Closure ==\n");
    SHOW_SIZE(CClosure);
    SHOW_OFF(CClosure, f);
    SHOW_OFF(CClosure, upvalue);
    SHOW_OFF(CClosure, isC);
    SHOW_OFF(CClosure, env);
    SHOW_OFF(CClosure, nupvalues);
    SHOW_OFF(CClosure, gclist);

    printf("== UpVal ==\n");
    SHOW_SIZE(UpVal);
    SHOW_OFF(UpVal, u.l.next);
    SHOW_OFF(UpVal, v);

    printf("== CallInfo ==\n");
    SHOW_SIZE(CallInfo);
    SHOW_OFF(CallInfo, base);
    SHOW_OFF(CallInfo, func);
    SHOW_OFF(CallInfo, top);
    SHOW_OFF(CallInfo, savedpc);
    SHOW_OFF(CallInfo, nresults);
    SHOW_OFF(CallInfo, tailcalls);

    printf("== LClosure ==\n");
    SHOW_OFF(LClosure, p);
    SHOW_OFF(LClosure, upvals);

    printf("== lua_State ==\n");
    SHOW_SIZE(lua_State);
    SHOW_OFF(lua_State, status);
    SHOW_OFF(lua_State, top);
    SHOW_OFF(lua_State, base);
    SHOW_OFF(lua_State, l_G);
    SHOW_OFF(lua_State, ci);
    SHOW_OFF(lua_State, savedpc);
    SHOW_OFF(lua_State, stack_last);
    SHOW_OFF(lua_State, stack);
    SHOW_OFF(lua_State, end_ci);
    SHOW_OFF(lua_State, base_ci);
    SHOW_OFF(lua_State, stacksize);
    SHOW_OFF(lua_State, size_ci);
    SHOW_OFF(lua_State, nCcalls);
    SHOW_OFF(lua_State, baseCcalls);
    SHOW_OFF(lua_State, execution_taint);
    SHOW_OFF(lua_State, hookmask);
    SHOW_OFF(lua_State, allowhook);
    SHOW_OFF(lua_State, basehookcount);
    SHOW_OFF(lua_State, hookcount);
    SHOW_OFF(lua_State, hook);
    SHOW_OFF(lua_State, l_gt);
    SHOW_OFF(lua_State, env);
    SHOW_OFF(lua_State, openupval);
    SHOW_OFF(lua_State, gclist);
    SHOW_OFF(lua_State, errorJmp);
    SHOW_OFF(lua_State, errfunc);
    SHOW_OFF(lua_State, state_tail_extension);

    printf("== global_State ==\n");
    SHOW_SIZE(global_State);
    SHOW_OFF(global_State, strt);
    SHOW_OFF(global_State, frealloc);
    SHOW_OFF(global_State, ud);
    SHOW_OFF(global_State, pad0);
    SHOW_OFF(global_State, currentwhite);
    SHOW_OFF(global_State, gcstate);
    SHOW_OFF(global_State, sweepstrgc);
    SHOW_OFF(global_State, rootgc);
    SHOW_OFF(global_State, sweepgc);
    SHOW_OFF(global_State, buff);
    SHOW_OFF(global_State, GCthreshold);
    SHOW_OFF(global_State, totalbytes);
    SHOW_OFF(global_State, estimate);
    SHOW_OFF(global_State, gcdept);
    SHOW_OFF(global_State, gcpause);
    SHOW_OFF(global_State, gcstepmul);
    SHOW_OFF(global_State, pad2);
    SHOW_OFF(global_State, panic);
    SHOW_OFF(global_State, l_registry);
    SHOW_OFF(global_State, mainthread);
    SHOW_OFF(global_State, uvhead);
    SHOW_OFF(global_State, mt);
    SHOW_OFF(global_State, tmname);

    return 0;
}
