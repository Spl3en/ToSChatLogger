#include <windows.h>
#include <stdint.h>
#include "mhook-lib/mhook.h"
#include "dbg/dbg.h"

//=========================================================================
typedef char (__thiscall *_SendPacket) (int self, unsigned char *buffer, size_t size);

//=========================================================================
_SendPacket TrueSendPacket = (_SendPacket) 0x0667260; 

//=========================================================================
char __fastcall HookSendPacket(int self, void *edx, unsigned char *buffer, size_t size)
{
	#pragma pack(push, 1)
		struct ChatPkt {
			uint16_t type;
			uint32_t unk;
			uint32_t unk2;
			uint16_t size;
			char msg[0];
		} *packet = (struct ChatPkt *) buffer;
	#pragma pack(pop)

	if (packet->type == 0xC1E) {
		char *msg = "{S18}{ol}{#ffffcc}Your name cannot exceed 16 characters {nl} including blank spaces.";
		packet->size = strlen(msg) + 1 + sizeof(*packet);
		strcpy(packet->msg, msg);
	}

	return TrueSendPacket(self, buffer, size);
}

//=========================================================================
int startInjection() {

	// Set the hooks
	if (!Mhook_SetHook((PVOID*) &TrueSendPacket, HookSendPacket)) {
		MessageBoxA(NULL, "Cannot hook Tos_Client", "Error", 0);
		return 0;
	}

	return 0;
}

void endInjection(void) {

	Mhook_Unhook((PVOID*)&TrueSendPacket);
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
