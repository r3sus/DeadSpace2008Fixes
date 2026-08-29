#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <shellapi.h>

#include <string>
#include <vector>

#include "CommandLineRestore.h"
#include "Utils.h"
#include "Config.h"

namespace CommandLineRestore {

	// The engine's argv+cmd.txt wrapper:
	//   int __usercall sub_4012C0@<eax>(unsigned int argc@<eax>, char** argv@stack)
	// It flushes the token table, stores argc/argv, and if argc<=1 reads cmd.txt
	// via sub_401180 + sub_401050. Ends with a plain `retn` (caller clears argv).
	static uintptr_t s_enginePopulate = 0;

	// Address to jump back to (the instruction after the replaced call).
	static uintptr_t s_backTo = 0;

	// Real argv proc must stay alive: the engine table stores the argv pointer
	// array directly (sub_4012C0), so we must not free seeds after feeding it.
	static LPSTR* s_hostArgv = nullptr;
	static int s_hostArgc = 0;

	static void PopulateFromHostCmdLine();

	// cdecl shim that forwards to the engine wrapper with the correct convention.
	__declspec(naked) static void CallEnginePopulate(unsigned int argc, char** argv)
	{
		__asm {
			mov eax, dword ptr[esp + 4]   // argc
			mov ecx, dword ptr[esp + 8]   // argv
			push ecx
			call dword ptr[s_enginePopulate]
			add esp, 4                    // caller clears (sub_4012C0 uses retn)
			ret
		}
	}

	// Persistent storage for the converted (ANSI) command line.
	static std::vector<std::string> s_argvStorage;

	// C++ helper: builds a persistent argv from the real command line, then feeds
	// it to the engine (which falls back to cmd.txt when argc<=1 on a normal launch).
	static void PopulateFromHostCmdLine()
	{
		if (s_hostArgv != nullptr || s_hostArgc != 0)
		{
			// Already populated once.
			CallEnginePopulate((unsigned int)s_hostArgc, s_hostArgv);
			return;
		}

		int wc = 0;
		LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wc);
		if (wargv == nullptr || wc <= 0)
		{
			if (wargv) LocalFree(wargv);
			// Fall back to the engine's cmd.txt path (argc 1 with no argv).
			CallEnginePopulate(1, nullptr);
			return;
		}

		// Convert each UTF-16 argument to ANSI, keeping the buffers alive.
		s_argvStorage.clear();
		s_argvStorage.reserve((size_t)wc);
		for (int i = 0; i < wc; ++i)
		{
			int len = WideCharToMultiByte(CP_ACP, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
			if (len <= 0)
				len = 1;
			std::string arg(len, '\0');
			WideCharToMultiByte(CP_ACP, 0, wargv[i], -1, &arg[0], len, nullptr, nullptr);
			arg.resize(len - 1); // drop the trailing NUL that WideCharToMultiByte wrote
			s_argvStorage.push_back(std::move(arg));
		}
		LocalFree(wargv);

		// Build the argv[] array the engine expects (index 0 = program name).
		s_hostArgc = wc;
		s_hostArgv = new LPSTR[(size_t)wc];
		for (int i = 0; i < wc; ++i)
			s_hostArgv[i] = const_cast<LPSTR>(s_argvStorage[(size_t)i].c_str());

		CallEnginePopulate((unsigned int)s_hostArgc, s_hostArgv);
		// Keep s_argvStorage + s_hostArgv alive; the engine references them later.
	}

	// Naked trampoline that replaces `call sub_401050` at the boot call site
	// (0x414b87). Runs on the engine's stack with no return address pushed.
	__declspec(naked) static void BootCmdLineTrampoline()
	{
		__asm {
			call PopulateFromHostCmdLine
			jmp dword ptr[s_backTo]
		}
	}

	void Initialise()
	{
		if (!Config::RestoreCommandLine)
			return;

		HMODULE hExe = GetModuleHandleA(nullptr);
		if (!hExe)
			return;

		// Locate sub_4012C0 (argv+cmd.txt wrapper).
		s_enginePopulate = Utils::FindPattern(hExe, "56 8B F0 E8 ? ? ? ? 83 FE 01");
		if (s_enginePopulate == 0)
		{
			DEBUG_LOG("CommandLineRestore: sub_4012C0 pattern not found");
			return;
		}

		// Locate the boot call site: `call sub_401310; mov eax, off Str; call sub_401050`.
		// Pattern is unique; the 5-byte call to replace starts +10 bytes in.
		const char* bootSig = "E8 8E C7 FE FF B8 28 CF EB 00 E8 C4 C4 FE FF";
		uintptr_t region = Utils::FindPattern(hExe, bootSig);
		if (region == 0)
		{
			DEBUG_LOG("CommandLineRestore: boot call-site pattern not found");
			return;
		}

		uintptr_t callSite = region + 10; // `call sub_401050`
		s_backTo = region + 15;           // instruction after the call

		// Replace `call sub_401050` (5 bytes) with `jmp BootCmdLineTrampoline`.
		BYTE patch[5];
		patch[0] = 0xE9;
		*reinterpret_cast<uintptr_t*>(patch + 1) = reinterpret_cast<uintptr_t>(&BootCmdLineTrampoline) - callSite - 5;

		if (Utils::WriteBytes(callSite, patch, sizeof(patch)))
		{
			DEBUG_LOG("CommandLineRestore: applied (call site 0x%X, back to 0x%X)", callSite, s_backTo);
		}
	}

} // namespace CommandLineRestore
