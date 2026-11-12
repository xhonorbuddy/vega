/*
** $Id: lstate.h,v 2.24.1.2 2008/01/03 15:20:39 roberto Exp $
** Global State
** See Copyright Notice in lua.h
*/

#ifndef lstate_h
#define lstate_h

#include "lua.h"

#include "lobject.h"
#include "ltm.h"
#include "lzio.h"



struct lua_longjmp;  /* defined in ldo.c */


/* table of globals */
#define gt(L)	(&L->l_gt)

/* registry */
#define registry(L)	(&G(L)->l_registry)


/* extra stack space to handle TM calls and some other extras */
#define EXTRA_STACK   5


#define BASIC_CI_SIZE           8

#define BASIC_STACK_SIZE        (2*LUA_MINSTACK)



typedef struct stringtable {
	GCObject** hash;
	lu_int32 nuse;  /* number of elements */
	int size;
} stringtable;


/*
** informations about a call
*/
typedef struct CallInfo {
	StkId base;                       /* 0x00 base for this function */
	StkId func;                       /* 0x08 function index in the stack */
	StkId	top;                        /* 0x10 top for this function */
	const Instruction* savedpc;       /* 0x18 */
	lu_byte call_status;              /* 0x20 client-owned call state */
	char pad0[3];                     /* 0x21 */
	unsigned short call_flags;        /* 0x24 client-owned call flags */
	char pad1[2];                     /* 0x26 */
	lu_byte call_byte;                /* 0x28 client-owned call byte */
	char pad2[3];                     /* 0x29 */
	int nresults;                     /* 0x2C expected number of results from this function */
	int tailcalls;                    /* 0x30 number of tail calls lost under this entry */
	char pad3[4];                     /* 0x34 */
} CallInfo;



#define curr_func(L)	(clvalue(L->ci->func))
#define ci_func(ci)	(clvalue((ci)->func))
#define f_isLua(ci)	(!ci_func(ci)->c.isC)
#define isLua(ci)	(ttisfunction((ci)->func) && f_isLua(ci))


/*
** `global state', shared by all threads of this state
*/
typedef struct global_State {
	stringtable strt;               /* 0x000 hash table for strings */
	lua_Alloc frealloc;             /* 0x010 function to reallocate memory */
	void* ud;                       /* 0x018 auxiliary data to `frealloc' */
	char pad0[1];                   /* 0x020 */
	lu_byte currentwhite;           /* 0x021 */
	lu_byte gcstate;                /* 0x022 state of garbage collector */
	char pad1[1];                   /* 0x023 */
	int sweepstrgc;                 /* 0x024 position of sweep in `strt' */
	GCObject* rootgc;               /* 0x028 list of all collectable objects */
	GCObject** sweepgc;             /* 0x030 position of sweep in `rootgc' */
	GCObject* gray;                 /* 0x038 list of gray objects */
	GCObject* grayagain;            /* 0x040 list of objects to be traversed atomically */
	GCObject* weak;                 /* 0x048 list of weak tables (to be cleared) */
	GCObject* tmudata;              /* 0x050 last element of list of userdata to be GC */
	Mbuffer buff;                   /* 0x058 temporary buffer for string concatentation */
	lu_mem GCthreshold;             /* 0x070 */
	lu_mem totalbytes;              /* 0x078 number of bytes currently allocated */
	lu_mem estimate;                /* 0x080 an estimate of number of bytes actually in use */
	lu_mem gcdept;                  /* 0x088 how much GC is `behind schedule' */
	int gcpause;                    /* 0x090 size of pause between successive GCs */
	int gcstepmul;                  /* 0x094 GC `granularity' */
	char pad2[24];                  /* 0x098 opaque WoW state */
	lua_CFunction panic;            /* 0x0B0 to be called in unprotected errors */
	TValue l_registry;              /* 0x0B8 */
	struct lua_State* mainthread;   /* 0x0D0 */
	UpVal uvhead;                   /* 0x0D8 head of double-linked list of all open upvalues */
	struct Table* mt[NUM_TAGS];     /* 0x110 metatables for basic types */
	TString* tmname[TM_N];          /* 0x158 array with tag-method names */
} global_State;


/*
** `per thread' state
*/
struct lua_State {
	CommonHeader;                     /* 0x000 next/taint/tt/marked; ends at 0x12 */
	lu_byte state_extension[14];      /* 0x012 opaque WoW header; ends at 0x20 */
	lu_byte status;                   /* 0x020 */
	char pad0[7];                     /* 0x021 */
	StkId top;                        /* 0x028 first free slot in the stack */
	StkId base;                       /* 0x030 base of current function */
	global_State* l_G;                /* 0x038 */
	CallInfo* ci;                     /* 0x040 call info for current function */
	const Instruction* savedpc;       /* 0x048 `savedpc' of current function */
	StkId stack_last;                 /* 0x050 last free slot in the stack */
	StkId stack;                      /* 0x058 stack base */
	CallInfo* end_ci;                 /* 0x060 points after end of ci array */
	CallInfo* base_ci;                /* 0x068 array of CallInfo's */
	int stacksize;                    /* 0x070 */
	int size_ci;                      /* 0x074 size of array `base_ci' */
	unsigned short nCcalls;           /* 0x078 number of nested C calls */
	unsigned short baseCcalls;        /* 0x07A nested C calls when resuming coroutine */
	lu_byte execution_taint;          /* 0x07C distinct from GC-header taint */
	lu_byte hookmask;                 /* 0x07D */
	lu_byte allowhook;                /* 0x07E */
	char pad2[1];                     /* 0x07F */
	int basehookcount;                /* 0x080 */
	int hookcount;                    /* 0x084 */
	lua_Hook hook;                    /* 0x088 */
	TValue l_gt;                      /* 0x090 table of globals */
	TValue env;                       /* 0x0A8 temporary place for environments */
	GCObject* openupval;              /* 0x0C0 list of open upvalues in this stack */
	GCObject* gclist;                 /* 0x0C8 */
	struct lua_longjmp* errorJmp;     /* 0x0D0 current error recover point */
	ptrdiff_t errfunc;                /* 0x0D8 current error handling function */
	void* state_tail_extension[2];    /* 0x0E0 opaque WoW per-thread sidecar state */
};


/* Fail the build if the supported WoW x64 ABI drifts. */
#if defined(_WIN64)
#ifdef __cplusplus
#define WOW_ABI_ASSERT static_assert
#else
#define WOW_ABI_ASSERT _Static_assert
#endif
#define WOW_ABI_OFFSET(type, field, offset) \
  WOW_ABI_ASSERT(offsetof(type, field) == (offset), #type "." #field " offset")
WOW_ABI_OFFSET(TValue, value, 0x0);
WOW_ABI_OFFSET(TValue, tt, 0x8);
WOW_ABI_OFFSET(TValue, taint, 0x10);
WOW_ABI_OFFSET(GCheader, tt, 0x10);
WOW_ABI_OFFSET(GCheader, marked, 0x11);
WOW_ABI_OFFSET(Table, flags, 0x12);
WOW_ABI_OFFSET(Table, lsizenode, 0x13);
WOW_ABI_OFFSET(Table, node, 0x28);
WOW_ABI_OFFSET(TString, tsv.hash, 0x14);
WOW_ABI_OFFSET(TString, tsv.len, 0x18);
WOW_ABI_OFFSET(CClosure, f, 0x30);
WOW_ABI_OFFSET(CClosure, upvalue, 0x38);
WOW_ABI_OFFSET(LClosure, p, 0x30);
WOW_ABI_OFFSET(CallInfo, savedpc, 0x18);
WOW_ABI_OFFSET(CallInfo, nresults, 0x2C);
WOW_ABI_OFFSET(CallInfo, tailcalls, 0x30);
WOW_ABI_ASSERT(sizeof(CallInfo) == 0x38, "CallInfo size");
WOW_ABI_OFFSET(UpVal, u.l.next, 0x28);
WOW_ABI_OFFSET(lua_State, status, 0x20);
WOW_ABI_OFFSET(lua_State, top, 0x28);
WOW_ABI_OFFSET(lua_State, l_G, 0x38);
WOW_ABI_OFFSET(lua_State, ci, 0x40);
WOW_ABI_OFFSET(lua_State, execution_taint, 0x7C);
WOW_ABI_OFFSET(lua_State, hookmask, 0x7D);
WOW_ABI_OFFSET(lua_State, allowhook, 0x7E);
WOW_ABI_OFFSET(lua_State, l_gt, 0x90);
WOW_ABI_OFFSET(lua_State, errorJmp, 0xD0);
WOW_ABI_OFFSET(lua_State, errfunc, 0xD8);
WOW_ABI_OFFSET(global_State, currentwhite, 0x21);
WOW_ABI_OFFSET(global_State, gcstate, 0x22);
WOW_ABI_OFFSET(global_State, sweepstrgc, 0x24);
WOW_ABI_OFFSET(global_State, panic, 0xB0);
WOW_ABI_OFFSET(global_State, l_registry, 0xB8);
WOW_ABI_OFFSET(global_State, mainthread, 0xD0);
WOW_ABI_OFFSET(global_State, uvhead, 0xD8);
WOW_ABI_OFFSET(global_State, mt, 0x110);
WOW_ABI_OFFSET(global_State, tmname, 0x158);
WOW_ABI_ASSERT(sizeof(TValue) == 0x18, "TValue size");
WOW_ABI_ASSERT(sizeof(Node) == 0x38, "Node size");
WOW_ABI_ASSERT(sizeof(global_State) == 0x1E0, "global_State size (TM_N = 17)");
WOW_ABI_ASSERT(sizeof(lua_State) == 0xF0, "lua_State size");
WOW_ABI_ASSERT(sizeof(CClosure) == 0x50, "CClosure size");
#undef WOW_ABI_OFFSET
#undef WOW_ABI_ASSERT
#endif


#define G(L)	(L->l_G)


/*
** Union of all collectable objects
*/
union GCObject {
	GCheader gch;
	union TString ts;
	union Udata u;
	union Closure cl;
	struct Table h;
	struct Proto p;
	struct UpVal uv;
	struct lua_State th;  /* thread */
};


/* macros to convert a GCObject into a specific value */
#define rawgco2ts(o)	check_exp((o)->gch.tt == LUA_TSTRING, &((o)->ts))
#define gco2ts(o)	(&rawgco2ts(o)->tsv)
#define rawgco2u(o)	check_exp((o)->gch.tt == LUA_TUSERDATA, &((o)->u))
#define gco2u(o)	(&rawgco2u(o)->uv)
#define gco2cl(o)	check_exp((o)->gch.tt == LUA_TFUNCTION, &((o)->cl))
#define gco2h(o)	check_exp((o)->gch.tt == LUA_TTABLE, &((o)->h))
#define gco2p(o)	check_exp((o)->gch.tt == LUA_TPROTO, &((o)->p))
#define gco2uv(o)	check_exp((o)->gch.tt == LUA_TUPVAL, &((o)->uv))
#define ngcotouv(o) \
	check_exp((o) == NULL || (o)->gch.tt == LUA_TUPVAL, &((o)->uv))
#define gco2th(o)	check_exp((o)->gch.tt == LUA_TTHREAD, &((o)->th))

/* macro to convert any Lua object into a GCObject */
#define obj2gco(v)	(cast(GCObject *, (v)))


LUAI_FUNC lua_State* luaE_newthread(lua_State* L);
LUAI_FUNC void luaE_freethread(lua_State* L, lua_State* L1);
/* WoW extension: restore a coroutine after a protected-call error. */
LUAI_FUNC int luaE_resetthread(lua_State* L, int status);

#endif

