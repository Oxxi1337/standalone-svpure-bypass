#pragma once

#include "Hooks.h"

class INetMessage
{
public:
	virtual					~INetMessage() { }
	virtual void			SetNetChannel(void* pNetChannel) = 0;
	virtual void			SetReliable(bool bState) = 0;
	virtual bool			Process() = 0;
	virtual	bool			ReadFromBuffer(uintptr_t& buffer) = 0;
	virtual	bool			WriteToBuffer(uintptr_t& buffer) = 0;
	virtual bool			IsReliable() const = 0;
	virtual int				GetType() const = 0;
	virtual int				GetGroup() const = 0;
	virtual const char* GetName() const = 0;
	virtual void* GetNetChannel() const = 0;
	virtual const char* ToString() const = 0;
	virtual std::size_t		GetSize() const = 0;
};

bool __fastcall hkSendNetMsg(void* thisptr, int edx, INetMessage* pMessage, bool bForceReliable, bool bVoice)
{
	static auto original = Hooks::SendNetMSG.GetOriginal<decltype(&hkSendNetMsg)>();
	if (pMessage->GetType() == 14) {
		return false;
	}
	if (pMessage->GetGroup() == 9) {
		bVoice = true;
	}
	return original(thisptr, edx, pMessage, bForceReliable, bVoice);
}

int __fastcall hkGetUnverifiedFileHashes(void* _this, void* someclass, int nMaxFiles)
{
	return 0;
}

int __fastcall hkCanLoadThirdPartyFiles(void* _this)
{
	return 1;
}

int __fastcall hkAllowLooseFileLoads(void* _this, void* ecx, void* edx)
{
	return true;
}