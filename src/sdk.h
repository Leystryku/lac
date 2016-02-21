//Engine Stuff
#pragma once
#pragma comment(lib, "tier0.lib")
#include "stdafx.h"
#include <cbase.h>
#include <inetchannel.h>
#include <inetmsghandler.h>
#include <iclient.h>

#include <input.h>
#include <igamemovement.h>
#include <c_baseentity.h>
#include <iservernetworkable.h>

extern IVEngineServer *g_pEngine;
extern IServerGameDLL *g_pBaseServer;
extern IClientEntityList *g_pEntList;
extern ICvar *g_pCVar;

extern std::string(InitializeSdk)();

