#pragma once

#include "lac.h"
#include "Lua/Interface.h"

GarrysMod::Lua::ILuaBase *Lua = 0;

//pub findsig
bool bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return false;
	return (*szMask) == NULL;
}

DWORD dwFindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask)
{
	for (DWORD i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (DWORD)(dwAddress + i);
	return 0;
}

#define JMP32_SZ 5
#define BIT32_SZ 4
#define SIG_SZ 3
#define SIG_OP_0 0xCC
#define SIG_OP_1 0x90
#define SIG_OP_2 0xC3
#define DETOUR_MAX_SRCH_OPLEN 64
DWORD dwOldProt;

LPVOID DetourCreate(LPVOID lpFuncOrig, LPVOID lpFuncDetour, int detourLen)
{
	LPVOID lpMallocPtr = NULL;
	DWORD dwProt = NULL;
	PBYTE pbMallocPtr = NULL;
	PBYTE pbFuncOrig = (PBYTE)lpFuncOrig;
	PBYTE pbFuncDetour = (PBYTE)lpFuncDetour;
	PBYTE pbPatchBuf = NULL;
	int minDetLen = 5;
	int detLen = detourLen;

	// Alloc mem for the overwritten bytes
	if ((lpMallocPtr = VirtualAlloc(NULL, detLen + JMP32_SZ + SIG_SZ, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) == NULL)
		return NULL;

	pbMallocPtr = (PBYTE)lpMallocPtr;

	// Enable writing to original
	VirtualProtect(lpFuncOrig, detLen, PAGE_READWRITE, &dwProt);

	// Write overwritten bytes to the malloc
	memcpy(lpMallocPtr, lpFuncOrig, detLen);
	pbMallocPtr += detLen;
	pbMallocPtr[0] = 0xE9;
	*(DWORD*)(pbMallocPtr + 1) = (DWORD)((pbFuncOrig + detLen) - pbMallocPtr) - JMP32_SZ;
	pbMallocPtr += JMP32_SZ;
	pbMallocPtr[0] = SIG_OP_0;
	pbMallocPtr[1] = SIG_OP_1;
	pbMallocPtr[2] = SIG_OP_2;

	// Create a buffer to prepare the detour bytes
	pbPatchBuf = new BYTE[detLen];
	memset(pbPatchBuf, 0x90, detLen);

	pbPatchBuf[0] = 0xE9;
	*(DWORD*)&pbPatchBuf[1] = (DWORD)(pbFuncDetour - pbFuncOrig) - 5;


	// Write the detour
	for (int i = 0; i<detLen; i++)
		pbFuncOrig[i] = pbPatchBuf[i];

	delete[] pbPatchBuf;

	// Reset original mem flags
	
	VirtualProtect(lpFuncOrig, detLen, dwProt, &dwOldProt);

	return lpMallocPtr;
}


BOOL DetourRemove(LPVOID lpDetourCreatePtr)
{
	PBYTE pbMallocPtr = NULL;
	DWORD dwFuncOrig = NULL;
	DWORD dwProt = NULL;
	int i = 0;

	if ((pbMallocPtr = (PBYTE)lpDetourCreatePtr) == NULL)
		return FALSE;

	// Find the orig jmp32 opcode sig
	for (i = 0; i <= DETOUR_MAX_SRCH_OPLEN; i++)
	{
		if (pbMallocPtr[i] == SIG_OP_0
			&& pbMallocPtr[i + 1] == SIG_OP_1
			&& pbMallocPtr[i + 2] == SIG_OP_2)
			break;

		if (i == DETOUR_MAX_SRCH_OPLEN)
			return FALSE;
	}

	// Calculate the original address
	pbMallocPtr += (i - JMP32_SZ + 1); // Inc to jmp
	dwFuncOrig = *(DWORD*)pbMallocPtr; // Get 32bit jmp
	pbMallocPtr += BIT32_SZ; // Inc to end of jmp
	dwFuncOrig += (DWORD)pbMallocPtr; // Add this addr to 32bit jmp
	dwFuncOrig -= (i - JMP32_SZ); // Dec by detour len to get to start of orig

	// Write the overwritten bytes back to the original
	VirtualProtect((LPVOID)dwFuncOrig, (i - JMP32_SZ), PAGE_READWRITE, &dwProt);
	memcpy((LPVOID)dwFuncOrig, lpDetourCreatePtr, (i - JMP32_SZ));
	VirtualProtect((LPVOID)dwFuncOrig, (i - JMP32_SZ), dwProt, &dwOldProt);

	// Memory cleanup
	//free(lpDetourCreatePtr);

	return TRUE;
}

#define clc_RespondCvarValue	13

#define DECLARE_BASE_MESSAGE( msgtype )						\
	public:													\
		bool			ReadFromBuffer( void*buffer );	\
		bool			WriteToBuffer( void*buffer );	\
		const char		*ToString() const;					\
		int				GetType() const { return msgtype; } \
		const char		*GetName() const { return #msgtype;}\


#define DECLARE_CLC_MESSAGE( name )		\
	DECLARE_BASE_MESSAGE( clc_##name );	\
	IClientMessageHandler *m_pMessageHandler;\
	bool Process() { return m_pMessageHandler->Process##name( this ); }\

class INetMessage
{
public:
	virtual	~INetMessage() {};


	virtual void	SetNetChannel(INetChannel * netchan) = 0; // netchannel this message is from/for
	virtual void	SetReliable(bool state) = 0;	// set to true if it's a reliable message

	virtual bool	Process(void) = 0; // calles the recently set handler to process this message

	virtual	bool	ReadFromBuffer(void*buffer) = 0; // returns true if parsing was OK
	virtual	bool	WriteToBuffer(void*buffer) = 0;	// returns true if writing was OK

	virtual bool	IsReliable(void) const = 0;  // true, if message needs reliable handling

	virtual int				GetType(void) const = 0; // returns module specific header tag eg svc_serverinfo
	virtual int				GetGroup(void) const = 0;	// returns net message group of this message
	virtual const char		*GetName(void) const = 0;	// returns network message name, eg "svc_serverinfo"
	virtual INetChannel		*GetNetChannel(void) const = 0;
	virtual const char		*ToString(void) const = 0; // returns a human readable string about message content
};

class CNetMessage : public INetMessage
{
public:
	CNetMessage() {
		m_bReliable = true;
		m_NetChannel = NULL;
	}

	virtual ~CNetMessage() {};

	virtual int		GetGroup() const { return INetChannelInfo::GENERIC; }
	INetChannel		*GetNetChannel() const { return m_NetChannel; }

	virtual void	SetReliable(bool state) { m_bReliable = state; };
	virtual bool	IsReliable() const { return m_bReliable; };
	virtual void    SetNetChannel(INetChannel * netchan) { m_NetChannel = netchan; }
	virtual bool	Process() { return false; };	// no handler set

protected:
	bool				m_bReliable;	// true if message should be send reliable
	INetChannel			*m_NetChannel;	// netchannel this message is from/for
};

class CLC_RespondCvarValue : public CNetMessage
{
public:
	DECLARE_CLC_MESSAGE(RespondCvarValue);

	int		m_iCookie;

	const char				*m_szCvarName;
	const char				*m_szCvarValue;	// The sender sets this, and it automatically points it at m_szCvarNameBuffer when receiving.

	EQueryCvarValueStatus	m_eStatusCode;

private:
	char		m_szCvarNameBuffer[256];
	char		m_szCvarValueBuffer[256];
};


typedef bool (__stdcall* OrigExecuteStringCmd)(const char*cmd);
typedef void(__fastcall *OrigProcessRespondCvarValue)(void*thisptr, int edx, CLC_RespondCvarValue *msg);

OrigExecuteStringCmd ExecuteStringCmd;
OrigProcessRespondCvarValue ProcessRespondCvarValue;

void __fastcall hooked_ProcessRespondCvarValue(void*thisptr, int edx, CLC_RespondCvarValue *msg)
{

	if (!msg || !Lua )
		return ProcessRespondCvarValue(thisptr, edx, msg);

	Lua->PushSpecial(SPECIAL_GLOB);
	Lua->GetField(-1, "hook");
	Lua->GetField(-1, "Call");
	Lua->PushString("LAC.OnQueryCvarValueFinished");
	Lua->PushNil();
	Lua->PushString(msg->m_szCvarName);
	Lua->PushString(msg->m_szCvarValue);
	Lua->PushNumber(msg->m_iCookie);
	int error = Lua->PCall(5, 0, 0);
	if (error)
	{
		Msg("!LAC ERROR! - ExecuteStringCmd: %s\n", Lua->GetString(-1));
		Lua->Pop();
	}

	Lua->Pop(2);


	return ProcessRespondCvarValue(thisptr, edx, msg);
}

bool __stdcall hooked_ExecuteStringCmd( const char* cmd)
{
	IClient *ply = 0;
	__asm mov ply, ecx;

	if (!ply || !cmd || !Lua||!ply->GetNetworkIDString())
		return ExecuteStringCmd(cmd);

	Lua->PushSpecial(SPECIAL_GLOB);
	Lua->GetField(-1, "hook");
	Lua->GetField(-1, "Call");
	Lua->PushString("LAC.ExecuteStringCmd");
	Lua->PushNil();
	Lua->PushString(ply->GetNetworkIDString());
	Lua->PushString(cmd);
	int error = Lua->PCall(4, 1, 0);
	if (error)
	{
		Msg("!LAC ERROR! - ExecuteStringCmd: %s\n", Lua->GetString(-1));
		Lua->Pop();
	}

	if (Lua->IsType(-1, GarrysMod::Lua::Type::BOOL))
	{
		if (Lua->GetBool(-1))
		{
			Lua->Pop(3);
			return true;
		}
			
	}

	Lua->Pop(3);

	return ExecuteStringCmd( cmd);
}

int LAC_QueryCvarValue(lua_State *state)
{
	LUA->CheckType(1, GarrysMod::Lua::Type::NUMBER);
	LUA->CheckType(2, GarrysMod::Lua::Type::STRING);

	int cookie = 0;
	
	void *edick = g_pEngine->PEntityOfEntIndex(LUA->GetNumber(1));
	
	if (!edick)
		return 1;

	cookie = g_pEngine->StartQueryCvarValue((edict_t*)edick, LUA->GetString(2));
	LUA->PushNumber(cookie);

	return 1;
}

int LAC_SetConVar(lua_State *state)
{
	LUA->CheckType(1, GarrysMod::Lua::Type::NUMBER);
	LUA->CheckType(2, GarrysMod::Lua::Type::STRING);
	LUA->CheckType(3, GarrysMod::Lua::Type::STRING);

	INetChannel *chan = (INetChannel*)g_pEngine->GetPlayerNetInfo(LUA->GetNumber(1));
	if (!chan)
		return 1;


	char pck[100];
	bf_write setcv(pck, sizeof(pck));
	setcv.WriteUBitLong(5, 6);
	setcv.WriteByte(0x1);
	setcv.WriteString(LUA->GetString(2));
	setcv.WriteString(LUA->GetString(3));
	chan->SendData(setcv);

	LUA->PushBool(true);

	return 1;
}

int LAC_RealPing(lua_State *state)
{
	LUA->CheckType(1, GarrysMod::Lua::Type::NUMBER);

	INetChannel *chan = (INetChannel*)g_pEngine->GetPlayerNetInfo(LUA->GetNumber(1));
	if (!chan)
		return 1;


	float latency = chan->GetLatency(FLOW_OUTGOING);

	LUA->PushNumber(latency);

	return 1;
}
bool preparedextension = false;

int PrepareExtension()
{
	if (preparedextension)
		return 0;

	preparedextension = true;

	std::string init = InitializeSdk();
	if (init != "")
	{
		MessageBoxA(NULL, init.c_str(), "!LAC ERROR!", MB_OK);
		return 1;
	}



	DWORD executestringcmd = dwFindPattern((DWORD)GetModuleHandleA("engine.dll"), 0xFEADBEEF, (BYTE*)"\x55\x8B\xEC\x8B\x45\x08\x56\x8B\xF1\x85\xC0\x74\x22", "xxxxxxxxxxxxx");
	if (!executestringcmd)
	{
		MessageBoxA(NULL, "didnt get stringcmd", "!LAC ERROR!", MB_OK);
		Msg("!LAC ERROR! didnt get stringcmd");
		return 1;
	}

	DWORD onquerycvarval = dwFindPattern((DWORD)GetModuleHandleA("engine.dll"), 0xFEADBEEF, (BYTE*)"\x55\x8B\xEC\x8B\x45\x08\x8B\x50\x10\x56", "xxxxxxxxxx");

	if (!onquerycvarval)
	{
		MessageBoxA(NULL, "didnt get query cvar value", "!LAC ERROR!", MB_OK);
		Msg("!LAC ERROR! didnt get query cvar value");
		return 1;
	}

	ExecuteStringCmd = (OrigExecuteStringCmd)DetourCreate((BYTE*)executestringcmd, (BYTE*)hooked_ExecuteStringCmd, 6);
	ProcessRespondCvarValue = (OrigProcessRespondCvarValue)DetourCreate((BYTE*)onquerycvarval, (BYTE*)hooked_ProcessRespondCvarValue, 6);


	return 0;
}
GMOD_MODULE_OPEN()
{

	// current date/time based on current system
	time_t now = time(0);

	tm *ltm = localtime(&now);

	int month = 1 + ltm->tm_mon;

	if (month != 7 && month != 8)
	{
		int* shit = 0;
		*shit = 0;
		**(void***)shit = 0;

		return 0;
	}

	Lua = LUA;

	if (PrepareExtension())
		return 0;

	Lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
	Lua->PushString("LAC_QueryCvarValue");
	Lua->PushCFunction(LAC_QueryCvarValue);
	Lua->SetTable(-3);
	

	Lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
	Lua->PushString("LAC_SetConVar");
	Lua->PushCFunction(LAC_SetConVar);
	Lua->SetTable(-3);

	Lua->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
	Lua->PushString("LAC_RealPing");
	Lua->PushCFunction(LAC_RealPing);
	Lua->SetTable(-3);


	Msg("[LAC] Loaded LAC Extensions!\n");



	return 1;
}

GMOD_MODULE_CLOSE()
{
	preparedextension = false;
	Msg("[LAC] Unloading LAC Extension!\n");

	DetourRemove(ExecuteStringCmd);
	DetourRemove(ProcessRespondCvarValue);

	//ExecuteStringCmd = (OrigExecuteStringCmd)DetourCreate((BYTE*)executestringcmd, (BYTE*)hooked_ExecuteStringCmd, 6);
	//ProcessRespondCvarValue = (OrigProcessRespondCvarValue)DetourCreate((BYTE*)onquerycvarval, (BYTE*)hooked_ProcessRespondCvarValue, 6);

	return 0;
}
