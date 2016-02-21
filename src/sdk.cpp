#include "sdk.h"

IVEngineServer *g_pEngine = 0;
ICvar *g_pCVar = 0;
IServerGameDLL *g_pBaseServer = 0;

std::string InitializeSdk()
{
	HMODULE g_EngineDLL = GetModuleHandle("engine.dll");
	HMODULE g_VstdLibDLL = GetModuleHandle("vstdlib.dll");
	HMODULE g_ServerDLL = GetModuleHandle("server.dll");

	if (!g_EngineDLL || !g_VstdLibDLL || !g_ServerDLL)
	{
		Sleep(200);
		return InitializeSdk();
	}

	CreateInterfaceFn g_ServerFactory = (CreateInterfaceFn)GetProcAddress(g_ServerDLL, "CreateInterface");
	CreateInterfaceFn g_EngineFactory = (CreateInterfaceFn)GetProcAddress(g_EngineDLL, "CreateInterface");
	CreateInterfaceFn g_VstdFactory = (CreateInterfaceFn)GetProcAddress(g_VstdLibDLL, "CreateInterface");

	if ( !g_EngineFactory || !g_VstdFactory ||!g_ServerFactory)
	{
		return "missing factory";
	}

	g_pEngine = (IVEngineServer*)g_EngineFactory("VEngineServer021", 0);
	g_pCVar = (ICvar*)g_VstdFactory("VEngineCvar004", 0);
	g_pBaseServer = (IServerGameDLL*)g_ServerFactory("ServerGameDLL009", 0);

	if (!g_pEngine)
	{
		return "g_pEngine == NULL";
	}

	if (!g_pCVar)
	{
		return "g_pCVar == NULL";
	}

	if (!g_pBaseServer)
	{
		return "g_pBaseServer == NULL";
	}


	return "";

}