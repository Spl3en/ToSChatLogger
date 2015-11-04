#include <Windows.h>
#include "mhook-lib/mhook.h"
#include "dbg/dbg.h"
#include "PacketType\PacketType.h"
#include <stdint.h>

// Globals
char *loggerPath = NULL;
FILE *defaultOutput = NULL;
FILE *handlersOutput = NULL;
bool enablePacketEncryption = true;
char sessionDateDir[1000];

//=========================================================================
typedef char (__thiscall *_SendPacket) (int self, unsigned char *buffer, size_t size);
typedef char (__thiscall *_RecvPacket) (int self, char *buffer, int *size, int a4);

//=========================================================================
_RecvPacket TrueRecvPacket = (_RecvPacket) 0x663380; // Search "CNetUsr::Recv()"
	/*
		  sub_DDBED0(&v17, v4, (int)"CNetUsr::Recv()", 1);
		  LOBYTE(v53) = 4;
		  v25 = 0;
		  ((void (__cdecl *)(__int16 *, _DWORD, signed int))loc_F9BDCC)(&packetBuffer, 0, 54000);
		  v5 = (signed int)((unsigned __int64)(0x51EB851Fi64 * *((_DWORD *)this + 1)) >> 32) >> 5;
		  v21 = 0;
		  v20 = 100 * (v5 + ((unsigned int)v5 >> 31) + 1);
		  v6 = (int)sub_5FBE80();
		  LOBYTE(v7) = (*(char (__thiscall **)(int, int, int, int))(*(_DWORD *)v6 + 40))(
						 v6,
	*/
_SendPacket TrueSendPacket = (_SendPacket) 0x0663140; // search "GeClientNet.cpp"
	/*
			*(_DWORD *)(a2 + 2) = (*(_DWORD *)(v3 + 12))++;
			*(_DWORD *)(a2 + 6) = sub_662D40(a2, a3);
			if ( a3 > 0x2000 )
			{
			  sub_4032F0((int)&a1, "\n%s %d Line", "GeClientNet.cpp", (char *)0xD0);
			  sub_D28CD0(1, (unsigned int)"ERRCODE_LOGIC_ASSERT", (int)&a1, v6);
	*/

/*
GIVE FUNCTION NAME
sub_DDBED0(&v24, v4, (int)"CNetUsr::RecvContentsNet()", 1);
*/
//=========================================================================
char __fastcall HookRecvPacket(int self, void *edx, char *buffer, int *size, int a4)
{
	char result;

	if ((result = TrueRecvPacket(self, buffer, size, a4))) {
		uint32_t packetType = 0;
		memcpy(&packetType, buffer, 2);
		char *packetTypeStr = PacketType_to_string((PacketType) packetType);
		if (packetTypeStr != NULL) {
			dbg("RECV PacketType = %s", packetTypeStr);
		}
		buffer_print(buffer, *size, "> ");
		dbg("============================");
	}

	return result;
}

//=========================================================================
char __fastcall HookSendPacket(int self, void *edx, unsigned char *buffer, size_t size)
{
	uint32_t packetType = 0;
	memcpy(&packetType, buffer, 2);
	char *packetTypeStr = PacketType_to_string((PacketType) packetType);
	if (packetTypeStr != NULL) {
		dbg("SEND PacketType = %s", packetTypeStr);
	}
	buffer_print(buffer, size, "> ");
	dbg("============================");

	return TrueSendPacket(self, buffer, size);
}

//=========================================================================
// Utils
char *get_module_path(char *module)
{
	// Get current module path
	char path[MAX_PATH] = { 0 };
	GetModuleFileNameA(GetModuleHandleA(module), path, sizeof(path));

	char * lastSlash = strrchr(path, '\\');
	char * dllName = (lastSlash != NULL) ? &lastSlash[0] : path;
	dllName[0] = '\0';

	if (!strlen(path)) {
		return NULL;
	}

	return strdup(path);
}


//=========================================================================
int startInjection() {

	// Init path & dbg
	loggerPath = get_module_path("PacketLogger.dll");

	// Init output path
	SYSTEMTIME time;
	GetSystemTime(&time);

	sprintf(sessionDateDir, "%s/packets/%.02d_%.02d_%d-%.02dh%.02d", loggerPath, time.wDay, time.wMonth, time.wYear, time.wHour, time.wMinute);
	CreateDirectoryA(sessionDateDir, NULL);

	char captureFile[1000];
	sprintf(captureFile, "%s/capture.txt", sessionDateDir);

	if (!(defaultOutput = fopen(captureFile, "w+"))) {
		MessageBoxA(NULL, "Cannot create capture file.", captureFile, 0);
		return 0;
	}

	char handlersFile[1000];
	sprintf(handlersFile, "%s/handlers.txt", sessionDateDir);
	if (!(handlersOutput = fopen(handlersFile, "w+"))) {
		MessageBoxA(NULL, "Cannot create handlers file.", handlersFile, 0);
		return 0;
	}
	dbg_set_output(defaultOutput);

	// initialize packets strings
	packetTypeInit();

	// Set the hooks
	if (!Mhook_SetHook((PVOID*) &TrueSendPacket, HookSendPacket)) {
		MessageBoxA(NULL, "Cannot hook Tos_Client!SendPacket", "Error", 0);
		return 0;
	}
	if (!Mhook_SetHook((PVOID*) &TrueRecvPacket, HookRecvPacket)) {
		MessageBoxA(NULL, "Cannot hook Tos_Client!RecvPacket", "Error", 0);
		return 0;
	}

	return 0;
}

void endInjection(void) {

	Mhook_Unhook((PVOID*)&TrueSendPacket);
	Mhook_Unhook((PVOID*)&TrueRecvPacket);
}


bool WINAPI DllMain(HMODULE dll, DWORD reason, LPVOID reserved) {

	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startInjection, NULL, 0, NULL);
			break;

		case DLL_PROCESS_DETACH:
			endInjection();
			break;
	}

	return true;
}
