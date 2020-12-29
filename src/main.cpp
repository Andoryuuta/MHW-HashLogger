#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <set>
#include <mutex>
#include <regex>
#include <filesystem>
#include "fmt/format.h"
#include "strackeror_logger.h"
#include "MinHook.h"
#include "SigScan.hpp"

#define CRCAOB "44 0F B6 09 45 33 D2 45 84 C9 74 2B"
#define LOGFILE_NAME "hash_log.txt"

using CalcCRC_t = uint32_t(__fastcall*)(unsigned char* data, uint32_t init);
CalcCRC_t original_calc_crc1 = nullptr;
CalcCRC_t original_calc_crc2 = nullptr;

std::mutex log_mutex; // Protects "logfile" and "hashes" usage.
std::ofstream logfile;
std::set<uint32_t> hashes;
 
void LogHash(std::string source, unsigned char* data, uint32_t init, uint32_t hash) {
	const std::lock_guard<std::mutex> lock(log_mutex);

	if (hashes.count(hash) == 0) {
		//loader::log(loader::LogLevel::INFO, fmt::format("Got new hash - Source:{0}, Init:0x{1:X}, Hash:0x{2:X}, Value:'{3}'\n", source, init, hash, (char*)data).c_str());
		hashes.insert(hash);

		// Escape double-quotes for CSV.
		std::string escaped_str = std::regex_replace(std::string((char*)data), std::regex("\""), "\"\"");

		logfile << fmt::format("{0:X},{1},{2:X},\"{3}\",\n", hash, source, init, escaped_str).c_str();

		// We never have a place to actually "close" this output stream with our hooks, so make sure to flush it on each write.
		logfile.flush();
	}
}

uint32_t __fastcall HookedCalcCRC1(unsigned char* data, uint32_t init) {
	uint32_t hash = original_calc_crc1(data, init);
	LogHash("CRC1", data, init, hash);
	return hash;
}

uint32_t __fastcall HookedCalcCRC2(unsigned char* data, uint32_t init) {

	uint32_t hash = original_calc_crc2(data, init);
	LogHash("CRC2", data, init, hash);
	return hash;
}

bool HookCRCFunctions() {

	uint64_t image_base = (uint64_t)GetModuleHandle(NULL);
	uint64_t crc1 = SigScan::Scan(image_base, CRCAOB);
	if (crc1 == 0) {
		loader::log(loader::LogLevel::ERR, "Failed to get CRC1\n");
		return false;
	}

	uint64_t crc2 = SigScan::Scan(crc1 + 1, CRCAOB);
	if (crc2 == 0) {
		loader::log(loader::LogLevel::ERR, "Failed to get CRC2\n");
		return false;
	}

	loader::log(loader::LogLevel::DEBUG, fmt::format("CRC1: 0x{0:X}\n", crc1).c_str());
	loader::log(loader::LogLevel::DEBUG, fmt::format("CRC2: 0x{0:X}\n", crc2).c_str());

	if (MH_Initialize() != MH_OK) {
		loader::log(loader::LogLevel::ERR, "Failed to initialize Minhook\n");
		return false;
	}

	if (MH_CreateHook(reinterpret_cast<LPVOID*>(crc1), reinterpret_cast<LPVOID*>(&HookedCalcCRC1), reinterpret_cast<LPVOID*>(&original_calc_crc1)) != MH_OK)
	{
		loader::log(loader::LogLevel::ERR, "Failed to create hook CRC1\n");
		return false;
	}

	if (MH_CreateHook(reinterpret_cast<LPVOID*>(crc2), reinterpret_cast<LPVOID*>(&HookedCalcCRC2), reinterpret_cast<LPVOID*>(&original_calc_crc2)) != MH_OK)
	{
		loader::log(loader::LogLevel::ERR, "Failed to create hook CRC2\n");
		return false;
	}

	if (MH_EnableHook(reinterpret_cast<LPVOID*>(crc1)) != MH_OK)
	{
		loader::log(loader::LogLevel::ERR, "Failed to enable hook CRC1\n");
		return false;
	}

	if (MH_EnableHook(reinterpret_cast<LPVOID*>(crc2)) != MH_OK)
	{
		loader::log(loader::LogLevel::ERR, "Failed to enable hook CRC2\n");
		return false;
	}

	return true;
}

void LoadHashLog(std::string filename) {
	std::ifstream infile(filename);
	while (infile) {
		std::string line;
		if (!std::getline(infile, line)) {
			break;
		}

		std::istringstream ss(line);
		std::uint32_t hash;
		ss >> std::hex >> hash;

		// Insert the hash into our global set.
		hashes.insert(hash);

		//loader::log(loader::LogLevel::DEBUG, fmt::format("Loaded hash: 0x{0:X}\n", hash).c_str());
	}

}

DWORD WINAPI MyFunc(LPVOID lpvParam)
{
	loader::InitLogger();
	loader::log(loader::LogLevel::INFO, "MHW-HashLogger started\n");


	// Either load the existing hash file(if any) and append to it, or create the file (with header) if not.
	if (std::filesystem::exists(LOGFILE_NAME)) { 
		loader::log(loader::LogLevel::INFO, "Loading existing hash log\n");
		LoadHashLog(LOGFILE_NAME);

		// Loaded from existing. Open as output, at end, append.
		logfile.open(LOGFILE_NAME, std::ios::out | std::ios::ate | std::ios::app);
	}
	else {
		// New file. Open as output, truncate.
		logfile.open(LOGFILE_NAME, std::ios::out | std::ios::trunc);
		logfile << "hash,source,init,data,\n";
	}

	// Hook the CRC functions to 
	if (!HookCRCFunctions()) {
		return 1;
	}

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {

		// Calling this from DllMain could easily deadlock due to the global DLL loader lock depending on your version of windows and MSVC runtime.
		MyFunc(NULL);

		// If you aren't needing the hashes calculated in the first few seconds of the game, spawn a new thread to avoid this potential deadlock:
		//CreateThread(NULL, 0, MyFunc, 0, 0, NULL);
	}

	return TRUE;
}