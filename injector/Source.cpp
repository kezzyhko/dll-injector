#include <Windows.h>
#include <tchar.h>
#include <winternl.h>
#include <psapi.h>

extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtSuspendProcess(_In_ HANDLE ProcessHandle);
extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(_In_ HANDLE ProcessHandle);



#if defined(_WIN64)
	#define IMAGE_NT_HEADERS IMAGE_NT_HEADERS64
	#define APP_PATH "C:\\Users\\kezzyhko\\Desktop\\DLLInjector\\x64\\Release\\app.exe"
#else
	#define IMAGE_NT_HEADERS IMAGE_NT_HEADERS32
	//#define APP_PATH "C:\\WINDOWS\\system32\\notepad.exe"
	#define APP_PATH "C:\\Users\\kezzyhko\\Desktop\\DLLInjector\\Release\\app.exe"
#endif





#define assert(condition, label, err) \
	if (!(condition)) { \
		DWORD error_code = err; \
		_tprintf(_T("Error | %s | 0x%x\n"), _T(label), error_code); \
		exit(error_code); \
	}
#define assert_bool(condition, label) assert(condition, label, GetLastError())
#define assert_status(status, label) assert(status == 0, label, status)



#define remoteFuncWithSize(func, offset, data, size) \
	assert_bool( \
		func(proc, (LPVOID)(offset), data, size, nullptr), \
		"Could not access process' data" \
	);
#define remoteFunc(func, Type, offset, data) remoteFuncWithSize(func, offset, data, sizeof(Type))

#define remoteWriteBuffer(offset, data) remoteFuncWithSize(WriteProcessMemory, offset, &data, sizeof(data))
#define remoteWriteValue(Type, offset, value) \
	{ \
		Type data = value; \
		remoteFunc(WriteProcessMemory, Type, offset, &data) \
	}

#define remoteRead(Type, offset, name) \
	Type name = {}; \
	remoteFunc(ReadProcessMemory, Type, offset, &name)
#define remoteReadArray(Type, offset, name, amount) \
	Type name[amount] = {}; \
	remoteFuncWithSize(ReadProcessMemory, offset, name, sizeof(name))
#define remoteReadPointer(Type, offset, name, amount) \
	Type* name = (Type*)malloc(sizeof(Type) * amount); \
	remoteFuncWithSize(ReadProcessMemory, offset, name, sizeof(Type) * amount)

#define remoteReadStringAndCheck(offset, searchValue) \
    remoteReadArray(CHAR, moduleBaseAddress + offset, foundString, sizeof(searchValue)) \
    if (strcmp(foundString, searchValue) != 0) continue;



IMAGE_NT_HEADERS getNtHeaders(HANDLE proc, ULONG_PTR baseAddress) {
	remoteRead(IMAGE_DOS_HEADER, baseAddress, dosHeader);
	remoteRead(IMAGE_NT_HEADERS, baseAddress + dosHeader.e_lfanew, ntHeaders);
	return ntHeaders;
}
														


int main() {

	// CREATE SUSPENDED PROCESS

	LPCTSTR appName = _T(APP_PATH);

	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};

	assert_bool(
		CreateProcess(
			appName, 
			nullptr, nullptr, nullptr, 
			true, 
			CREATE_SUSPENDED, 
			nullptr, nullptr, 
			&si, &pi
		),
		"Could not create process"
	);

	Sleep(1000);
	HANDLE proc = pi.hProcess;
	HANDLE thread = pi.hThread;



	// RECIEVE INFORMATION ABOUT PROCESS

	PROCESS_BASIC_INFORMATION pbi = {};
	ULONG retlen = 0;
	NTSTATUS info_status = NtQueryInformationProcess(proc, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &retlen);
	assert_status(info_status, "Could not recieve process information");
	assert(pbi.PebBaseAddress != 0, "PEB base address is zero", -1);

	remoteRead(PEB, pbi.PebBaseAddress, peb);
	ULONG_PTR imageBaseAddress = (ULONG_PTR)peb.Reserved3[1];
	IMAGE_NT_HEADERS ntHeaders = getNtHeaders(proc, imageBaseAddress);
	ULONG_PTR addressOfEntry = imageBaseAddress + ntHeaders.OptionalHeader.AddressOfEntryPoint;
	
	

	// CREATE INFINITE LOOP IN ENTRY POINT

	remoteRead(WORD, addressOfEntry, originalEntry);
	remoteWriteValue(WORD, addressOfEntry, 0xFEEB); // jmp 0
	ResumeThread(thread);
	Sleep(1000);



	// FIND LOADLIBRARY

	CHAR targetLibrary[] = "KERNEL32.dll";
	CHAR targetFunction[] = "LoadLibraryW";

	DWORD needed = 0;
	assert_bool(
		EnumProcessModules(
			proc,
			nullptr, 0,
			&needed
		),
		"Could not recieve modules amount"
	);

	HMODULE* modules = (HMODULE*)malloc(needed);
	assert_bool(
		EnumProcessModules(proc, modules, needed, &needed),
		"Could not recieve modules list"
	);

	ULONG_PTR loadLibFuncAddr;
	for (DWORD i = 0; i < needed / sizeof(HMODULE); i++) {
		ULONG_PTR moduleBaseAddress = (ULONG_PTR)modules[i];
		IMAGE_NT_HEADERS ntHeaders = getNtHeaders(proc, moduleBaseAddress);
		IMAGE_DATA_DIRECTORY exportData = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (exportData.Size == 0) continue;

		remoteRead(IMAGE_EXPORT_DIRECTORY, moduleBaseAddress + exportData.VirtualAddress, exportDir);
		remoteReadStringAndCheck(exportDir.Name, targetLibrary);

		remoteReadPointer(DWORD, moduleBaseAddress + exportDir.AddressOfNames, functionNames, exportDir.NumberOfNames);
		for (DWORD j = 0; j < exportDir.NumberOfNames; j++) {
			remoteReadStringAndCheck(functionNames[j], targetFunction);
			remoteRead(WORD, moduleBaseAddress + exportDir.AddressOfNameOrdinals + j * sizeof(WORD), ordinal);
			remoteRead(DWORD, moduleBaseAddress + exportDir.AddressOfFunctions + ordinal * sizeof(DWORD), loadLibFuncVirtualAddress);
			loadLibFuncAddr = moduleBaseAddress + loadLibFuncVirtualAddress;
			
			break;
		}

		free(functionNames);
		break;
	}

	free(modules);



	// SETUP THE SHELLCODE

	UCHAR shellcode[]{
		// noop 5
		/* 0x00 */ 0x90, 0x90, 0x90, 0x90, 0x90,

		#if defined(_WIN64)
		// code
		/* 0x05 */ 0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 28h 
		/* 0x09 */ 0x48, 0x8D, 0x0D, 0x30, 0x00, 0x00, 0x00, // lea rcx, string
		/* 0x10 */ 0xFF, 0x15, 0x1A, 0x00, 0x00, 0x00,       // call loadLib
		/* 0x16 */ 0x33, 0xC9,                               // xor ecx, ecx
		/* 0x18 */ 0xBA, 0xFF, 0xFF, 0xFF, 0xFF,             // mov edx, 0FFFFFFFFh
		/* 0x1D */ 0x48, 0x85, 0xC0,                         // test rax, rax
		/* 0x20 */ 0x0F, 0x44, 0xCA,                         // cmove ecx, ecx
		/* 0x23 */ 0x8B, 0xC1,                               // mov eax, ecx
		/* 0x25 */ 0x48, 0x83, 0xC4, 0x28,                   // add rsp, 28h
		/* 0x29 */ 0xC3,                                     // ret

		// noop 6
		/* 0x2A */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		#else
		// code
		/* 0x05 */ 0x68, 0x00, 0x00, 0x00, 0x00,             // push string
		/* 0x0A */ 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,       // call loadLib
		/* 0x10 */ 0xF7, 0xD8,                               // neg eax
		/* 0x12 */ 0x1B, 0xC0,                               // sbb eax, eax
		/* 0x14 */ 0xF7, 0xD8,                               // neg eax
		/* 0x16 */ 0x48,                                     // dec eax
		/* 0x17 */ 0xC3,                                     // ret

		// noop 16+8
		/* 0x18 */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		/* 0x20 */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		#endif

		// for x32: loadLibrary address | for x64: part of loadLibrary address
		/* 0x30 */ 0x90, 0x90, 0x90, 0x90,

		// for x32: noop 4              | for x64: another part of loadLibrary address
		/* 0x34 */ 0x90, 0x90, 0x90, 0x90,

		// noop 8
		/* 0x38 */ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

		// lib path string "C:\Users\kezzyhko\Desktop\DLLInjector\[x64\]Release\library.dll"
		/* 0x40 */ 0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00,
		/* 0x50 */ 0x5c, 0x00, 0x6b, 0x00, 0x65, 0x00, 0x7a, 0x00, 0x7a, 0x00, 0x79, 0x00, 0x68, 0x00, 0x6b, 0x00,
		/* 0x60 */ 0x6f, 0x00, 0x5c, 0x00, 0x44, 0x00, 0x65, 0x00, 0x73, 0x00, 0x6b, 0x00, 0x74, 0x00, 0x6f, 0x00,
		/* 0x70 */ 0x70, 0x00, 0x5c, 0x00, 0x44, 0x00, 0x4c, 0x00, 0x4c, 0x00, 0x49, 0x00, 0x6e, 0x00, 0x6a, 0x00,
		/* 0x80 */ 0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x5c, 0x00,
		#if defined(_WIN64)
		/* 0x__ */ 0x78, 0x00, 0x36, 0x00, 0x34, 0x00, 0x5c, 0x00, // "x64\"
		#endif
		/* 0x__ */ 0x52, 0x00, 0x65, 0x00,
		/* 0x__ */ 0x6c, 0x00, 0x65, 0x00, 0x61, 0x00, 0x73, 0x00, 0x65, 0x00, 0x5c, 0x00, 0x6c, 0x00, 0x69, 0x00,
		/* 0x__ */ 0x62, 0x00, 0x72, 0x00, 0x61, 0x00, 0x72, 0x00, 0x79, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6c, 0x00,
		/* 0x__ */ 0x6c, 0x00, 0x00, 0x00
	};

	ULONG_PTR shellBase = (ULONG_PTR)VirtualAllocEx(proc, nullptr, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(shellcode + 0x30, &loadLibFuncAddr, sizeof(ULONG_PTR));
	#if !defined(_WIN64)
		const ULONG_PTR stringOffset = shellBase + 0x40;
		const ULONG_PTR funcOffset = shellBase + 0x30;
		memcpy(shellcode + 0x06, &stringOffset,    sizeof(ULONG_PTR));
		memcpy(shellcode + 0x0C, &funcOffset,      sizeof(ULONG_PTR));
	#endif



	// INJECT THE SHELLCODE

	remoteWriteBuffer(shellBase, shellcode);
	HANDLE shellcodeThread = CreateRemoteThread(proc, nullptr, 0, LPTHREAD_START_ROUTINE(shellBase), nullptr, 0, nullptr);
	WaitForSingleObject(shellcodeThread, INFINITE);

	DWORD exitCode = 0xf;
	GetExitCodeThread(shellcodeThread, &exitCode);
	assert_status(exitCode, "Problem inside the shellcode");

	CloseHandle(shellcodeThread);



	// RESTORE ENTRY POINT

	assert_status(NtSuspendProcess(proc), "Could not suspend process");
	remoteWriteBuffer(addressOfEntry, originalEntry);
	assert_status(NtResumeProcess(proc), "Could not resume process");
	Sleep(1000);

	return 0;
}