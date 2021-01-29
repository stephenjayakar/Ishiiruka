// Copyright 2010 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include <mutex>
#include <vector>

#include "Common/CommonPaths.h"
#include "Common/FileUtil.h"
#include "Common/Logging/Log.h"
#include "Common/Thread.h"

#include "Core/ConfigManager.h"
#include "Core/GeckoCode.h"
#include "Core/HW/Memmap.h"
#include "Core/NetPlayProto.h"
#include "Core/PowerPC/PowerPC.h"

#include "VideoCommon/OnScreenDisplay.h"

#include <iostream>

namespace Gecko
{

static const u32 INSTALLER_BASE_ADDRESS = 0x80001800;
static const u32 INSTALLER_END_ADDRESS = 0x80003000;

// return true if a code exists
bool GeckoCode::Exist(u32 address, u32 data) const
{
	for (const GeckoCode::Code& code : codes)
	{
		if (code.address == address && code.data == data)
			return true;
	}

	return false;
}

// return true if the code is identical
bool GeckoCode::Compare(const GeckoCode& compare) const
{
	if (codes.size() != compare.codes.size())
		return false;

	unsigned int exist = 0;

	for (const GeckoCode::Code& code : codes)
	{
		if (compare.Exist(code.address, code.data))
			exist++;
	}

	return exist == codes.size();
}

static bool code_limit_reached = false;
static bool code_handler_installed = false;
// the currently active codes
static std::vector<GeckoCode> active_codes;
static std::mutex active_codes_lock;

static bool IsEnabledMeleeCode(const GeckoCode& code)
{
    if(SConfig::GetInstance().bMeleeForceWidescreen && code.name == "Widescreen 16:9")
        return true;
        
    if(NetPlay::IsNetPlayRunning() && SConfig::GetInstance().iLagReductionCode != MELEE_LAG_REDUCTION_CODE_UNSET)
    {
        if(SConfig::GetInstance().iLagReductionCode == MELEE_LAG_REDUCTION_CODE_NORMAL)
            return code.name.find("Normal Lag Reduction") != std::string::npos;

        if(SConfig::GetInstance().iLagReductionCode == MELEE_LAG_REDUCTION_CODE_PERFORMANCE)
            return code.name.find("Performance Lag Reduction") != std::string::npos;
    }

    return false;
}

static bool IsDisabledMeleeCode(const GeckoCode& code)
{
    if(NetPlay::IsNetPlayRunning() && SConfig::GetInstance().iLagReductionCode != MELEE_LAG_REDUCTION_CODE_UNSET)
    {
        if(SConfig::GetInstance().iLagReductionCode == MELEE_LAG_REDUCTION_CODE_NORMAL)
            return code.name.find("Performance Lag Reduction") != std::string::npos;

        if(SConfig::GetInstance().iLagReductionCode == MELEE_LAG_REDUCTION_CODE_PERFORMANCE)
            return code.name.find("Normal Lag Reduction") != std::string::npos;
    }

    return false;
}

void SetActiveCodes(const std::vector<GeckoCode>& gcodes)
{
	std::lock_guard<std::mutex> lk(active_codes_lock);

	active_codes.clear();

	// add enabled codes
	for (const GeckoCode& gecko_code : gcodes)
	{        
		if ((gecko_code.enabled && !IsDisabledMeleeCode(gecko_code)) 
			|| IsEnabledMeleeCode(gecko_code))
		{
			active_codes.push_back(gecko_code);
		}
	}

	code_limit_reached = false;
	code_handler_installed = false;
}

static bool InstallCodeHandler()
{
	if (code_limit_reached)
		return false;

	std::string data;
	std::string _rCodeHandlerFilename = File::GetSysDirectory() + GECKO_CODE_HANDLER;
	if (!File::ReadFileToString(_rCodeHandlerFilename, data))
	{
		NOTICE_LOG(ACTIONREPLAY, "Could not enable cheats because codehandler.bin was missing.");
		return false;
	}

	u8 mmioAddr = 0xCC;

	if (SConfig::GetInstance().bWii)
	{
		mmioAddr = 0xCD;
	}

	// Install code handler
	for (size_t i = 0, e = data.length(); i < e; ++i)
		PowerPC::HostWrite_U8(data[i], (u32)(INSTALLER_BASE_ADDRESS + i));

	// Patch the code handler to the system starting up
	for (unsigned int h = 0; h < data.length(); h += 4)
	{
		// Patch MMIO address
		if (PowerPC::HostRead_U32(INSTALLER_BASE_ADDRESS + h) == (0x3f000000u | ((mmioAddr ^ 1) << 8)))
		{
			NOTICE_LOG(ACTIONREPLAY, "Patching MMIO access at %08x", INSTALLER_BASE_ADDRESS + h);
			PowerPC::HostWrite_U32(0x3f000000u | mmioAddr << 8, INSTALLER_BASE_ADDRESS + h);
		}
	}

	u32 codelist_base_address = INSTALLER_BASE_ADDRESS + (u32)data.length() - 8;
	u32 codelist_end_address = INSTALLER_END_ADDRESS;

	u32 melee_heap_start = 0x80bd5c40;
	u32 melee_code_size_max = 0x50000;
	u32 melee_fixed_inject_ofst = 0x34;

	// Move Gecko code handler into the heap region
	if(SConfig::GetInstance().m_gameType == GAMETYPE_MELEE_NTSC)
	{
		// Start of the heap plus offset for our size overwrite patch
		codelist_base_address = melee_heap_start + melee_fixed_inject_ofst;

		// Set max size we allow for gecko codes, how big can this be before game doesn't have enough heap?
		codelist_end_address = codelist_base_address + melee_code_size_max;

		// Overwrite codehandler to point to our custom code list
		PowerPC::HostWrite_U32(0x3DE080bd, 0x80001f58); // lis r15, 0x80BD
		PowerPC::HostWrite_U32(0x61EF5c40 + melee_fixed_inject_ofst, 0x80001f5C); // ori r3, r3, 0x5C4C

		// Here we are replacing a line in the codehandler with a blr.
		// The reason for this is that this is the section of the codehandler
		// that attempts to read/write commands for the USB Gecko. These calls
		// were sometimes interfering with the Slippi EXI calls and causing
		// the game to loop infinitely in EXISync.
		PowerPC::HostWrite_U32(0x4E800020, 0x80001D6C);
	}

	NOTICE_LOG(ACTIONREPLAY, "Gecko Bounds: %X - %X", codelist_base_address, codelist_end_address);

	// Write a magic value to 'gameid' (codehandleronly does not actually read this).
	PowerPC::HostWrite_U32(0xd01f1bad, INSTALLER_BASE_ADDRESS);

	// Create GCT in memory
	PowerPC::HostWrite_U32(0x00d0c0de, codelist_base_address);
	PowerPC::HostWrite_U32(0x00d0c0de, codelist_base_address + 4);

	std::lock_guard<std::mutex> lk(active_codes_lock);

	int i = 0;

	for (const GeckoCode& active_code : active_codes)
	{
		if ((active_code.enabled && !IsDisabledMeleeCode(active_code)) || IsEnabledMeleeCode(active_code))
		{
			for (const GeckoCode::Code& code : active_code.codes)
			{
				// Make sure we have enough memory to hold the code list
				if ((codelist_base_address + 24 + i) < codelist_end_address)
				{
					PowerPC::HostWrite_U32(code.address, codelist_base_address + 8 + i);
					PowerPC::HostWrite_U32(code.data, codelist_base_address + 12 + i);
					i += 8;
				}
				else
				{
					OSD::AddMessage("Ran out of memory applying gecko codes. Too many codes enabled.", 30000, 0xFFFF0000);

					ERROR_LOG(SLIPPI, "Ran out of memory applying gecko codes");
					code_limit_reached = true;
					return false;
				}
			}
		}
	}

	// Write terminator
	PowerPC::HostWrite_U32(0xff000000, codelist_base_address + 8 + i);
	PowerPC::HostWrite_U32(0x00000000, codelist_base_address + 12 + i);

	if (SConfig::GetInstance().m_gameType == GAMETYPE_MELEE_NTSC)
	{
		// Overwrite the end address to only store the code list and nothing more
		codelist_end_address = codelist_base_address + 16 + i;

		// Overwrite some game logic that determines where to start the heap. This causes the game
		// to not touch the section of code where we wrote the gct
		PowerPC::HostWrite_U32(0x3C600000 | (codelist_end_address >> 16), melee_heap_start); // lis r3, 0xXXXX (top half of new start of heap)
		PowerPC::HostWrite_U32(0x60630000 | (codelist_end_address & 0x0000FFFF), melee_heap_start + 0x4); // lis r3, 0xXXXX (bottom half of new start of heap)
		PowerPC::HostWrite_U32(0x4B43FE88, melee_heap_start + 0x8); // b -0xBC017C # 80bd5c4C -> 80015ad0, branch back

		// Branch to the logic defined above when game is calculating heap start
		PowerPC::HostWrite_U32(0x48BC0174, 0x80015ACC);  // b 0xBC0174 # 80015acc -> 80bd5c40
		PowerPC::ppcState.iCache.Invalidate(0x80015ACC); // invalidate this address

		// Overwrite more game logic that clears memory to prevent the game from clearing the memory we just set
		PowerPC::HostWrite_U32(0x3CC080BD, melee_heap_start + 0xC); // lis r6, 0x80bd
		PowerPC::HostWrite_U32(0x60C65C40, melee_heap_start + 0x10); // ori r6, r6, 0x5c40
		PowerPC::HostWrite_U32(0x7CA33050, melee_heap_start + 0x14); // sub r5, r6, r3
		PowerPC::HostWrite_U32(0x4B42D4A9, melee_heap_start + 0x18); // bl -0xBD2B54 # memset. 80BD5C58 -> 80003100
		PowerPC::HostWrite_U32(0x3C600000 | (codelist_end_address >> 16), melee_heap_start + 0x1C); // lis r3, 0x80bd
		PowerPC::HostWrite_U32(0x60630000 | (codelist_end_address & 0x0000FFFF), melee_heap_start + 0x20); // ori r3, r3, 0x5c4C
		PowerPC::HostWrite_U32(0x38800000, melee_heap_start + 0x24); // li r4, 0
		PowerPC::HostWrite_U32(0x7CA3F050, melee_heap_start + 0x28); // sub r5, r30, r3
		PowerPC::HostWrite_U32(0x4B42D495, melee_heap_start + 0x2C); // bl -0xBD2B68 # memset. 80BD5C6C -> 80003100
		PowerPC::HostWrite_U32(0x4B76D290, melee_heap_start + 0x30); // b -0xBC017C # branch back. 80BD5C70 -> 80342f00

		// Branch to the logic defined above when game is clearing memory
		PowerPC::HostWrite_U32(0x48892D50, 0x80342efc);  // b 0xBC0174 # 80342efc -> 80bd5c4c
		PowerPC::ppcState.iCache.Invalidate(0x80342efc); // invalidate this address

		// Overwrite the base address such that our overwritten logic will get invalidated
		codelist_base_address = melee_heap_start;
	}

	// Turn on codes
	PowerPC::HostWrite_U8(1, INSTALLER_BASE_ADDRESS + 7);

	// Invalidate the icache and any asm codes
	for (unsigned int j = 0; j < (INSTALLER_END_ADDRESS - INSTALLER_BASE_ADDRESS); j += 32)
	{
		PowerPC::ppcState.iCache.Invalidate(INSTALLER_BASE_ADDRESS + j);
	}
	for (unsigned int k = codelist_base_address; k < codelist_end_address; k += 32)
	{
		PowerPC::ppcState.iCache.Invalidate(k);
	}
	return true;
}

void RunCodeHandler()
{
	if (SConfig::GetInstance().bEnableCheats && active_codes.size() > 0)
	{
		if (!code_handler_installed || PowerPC::HostRead_U32(INSTALLER_BASE_ADDRESS) - 0xd01f1bad > 5)
			code_handler_installed = InstallCodeHandler();

		if (!code_handler_installed)
		{
			// A warning was already issued.
			return;
		}

		if (PC == LR)
		{
			u32 oldLR = LR;
			PowerPC::CoreMode oldMode = PowerPC::GetMode();

			PC = INSTALLER_BASE_ADDRESS + 0xA8;
			LR = 0;

			// Execute the code handler in interpreter mode to track when it exits
			PowerPC::SetMode(PowerPC::MODE_INTERPRETER);

			while (PC != 0)
				PowerPC::SingleStep();

			PowerPC::SetMode(oldMode);
			PC = LR = oldLR;
		}
	}
}

} // namespace Gecko
