#pragma once

#include "windows.h"

#define INDEX_ILUASHARED_CREATELUAINTERFACE 4
#define INDEX_ILUASHARED_GETLUAINTERFACE 6

#define lua_pop(L,n)  g_pLuaShared->lua_settop(L, -(n)-1)
#define lua_popa(L,n)  lua_settop(L, -(n)-1)


static void**& luagetvtable(void* inst, size_t offset = 0)
{
	return *reinterpret_cast<void***>((size_t)inst + offset);
}

static const void** luagetvtable(const void* inst, size_t offset = 0)
{
	return *reinterpret_cast<const void***>((size_t)inst + offset);
}
template< typename Fn >

static Fn luagetvfunc(const void* inst, size_t index, size_t offset = 0)
{
	return reinterpret_cast<Fn>(luagetvtable(inst, offset)[index]);
}

extern char tmperror[5024];


#undef GetObject

#define lua_BackupStack(GarryInterface, luashared)\
int LUA_TOPoobjecctcount = 0;\
int themagical_LUA_top = GarryInterface->Top();\
ILuaObject* lua_to__Tttopobjects[50];\
void*vstate = luashared->RetLuaState(GarryInterface);\
if(themagical_LUA_top)\
{\
for (int i = 0; i < themagical_LUA_top; i++) {\
	lua_to__Tttopobjects[LUA_TOPoobjecctcount++] = GarryInterface->GetObject(i); MessageBoxA(NULL, "NOW", "k", MB_OK);\
	luashared->lua_remove(vstate, i);\
}\
}\
		
	


#define lua_RestoreStack(GarryInterface)\
for (int i =LUA_TOPoobjecctcount; i != 0; i--)\
{\
	GarryInterface->PushLuaObject(lua_to__Tttopobjects[i]);\
}\
		
class ILuaShared
{
public:

	void*realluashared;

	bool InitShared(void*luashared)
	{
		luaL_loadbufferx = (int(*)(void*, const char*, size_t, const char*, void*))GetProcAddress(GetModuleHandleA("lua_shared.dll"), "luaL_loadbufferx");
		lua_pcall = (int(*)(void*, int, int, int))GetProcAddress(GetModuleHandleA("lua_shared.dll"), "lua_pcall");
		lua_settop = (int(*)(void*, int))GetProcAddress(GetModuleHandleA("lua_shared.dll"), "lua_settop");
		lua_tolstring = (const char*(*)(void*, int, int))GetProcAddress(GetModuleHandleA("lua_shared.dll"), "lua_tolstring");
		lua_replace = (void(*)(void *L, int index))GetProcAddress(GetModuleHandleA("lua_shared.dll"), "lua_replace");
		lua_remove = (void(*)(void *L, int index))GetProcAddress(GetModuleHandleA("lua_shared.dll"), "lua_remove");
		lua_type = (int(*)(void*L, int index))GetProcAddress(GetModuleHandleA("lua_shared.dll"), "lua_type");

		if (!luaL_loadbufferx || !lua_pcall || !lua_settop || !lua_tolstring || !lua_replace || !lua_remove || !lua_type)
		{
			MessageBoxA(NULL, "lua_whatever missing", "k", MB_OK);
			return false;
		}
		realluashared = luashared;

		return true;
	}

	void(*lua_replace)(void *L, int index);
	int(*luaL_loadbufferx)(void *L, const char *buf, size_t len, const char *name, void*nig);
	int(*lua_pcall)(void *L, int a, int b, int c);
	int(*lua_settop)(void *L, int a);
	void(*lua_remove)(void *L, int a);
	const char *(*lua_tolstring)(void *L, int a, int len);
	int(*lua_type)(void*L, int index);

	void* RetLuaState(void*GarryState)
	{
		return *(void**)((char*)GarryState + 0x4);
	}

	char* RunCode(void* state, const char*code, const char*name)
	{
		void* realstate = RetLuaState(state);

		int error = luaL_loadbufferx(realstate, code, strlen(code), name, 0);

		if (error)
		{
			const char*error = lua_tolstring(realstate, -1, 0);
			
			strcpy(tmperror, error);

			lua_popa(realstate, 1);
			return tmperror;
		}

		if (lua_pcall(realstate, 0, -1, 0))
		{
			lua_popa(realstate, 1);
			return "";
		}

		return "";
	}

	inline void* GetLuaInterface(unsigned char state)
	{
		typedef void*(__thiscall* OriginalFn)(void*, unsigned char);
		return luagetvfunc<OriginalFn>(realluashared, INDEX_ILUASHARED_GETLUAINTERFACE)(realluashared, state);
	}

	inline void* CreateLuaInterface(unsigned char state, bool renew)
	{
		typedef void*(__thiscall* OriginalFn)(void*, unsigned char, bool);
		return luagetvfunc<OriginalFn>(realluashared, INDEX_ILUASHARED_CREATELUAINTERFACE)(realluashared, state, renew);
	}

};


extern ILuaShared *g_pLuaShared;