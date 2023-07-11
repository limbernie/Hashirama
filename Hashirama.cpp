#include "internals.h"

int hash(char* winapi)
{
  int hash = 0;
  while (*winapi)
  {
    hash = (*winapi + ((hash << 0x13) | ((unsigned int)hash >> 0xD))) & 0xFFFFFFFF;
    winapi++;
  }
  return hash;
}

int WinMainCRTStartup()
{
  int result = WinMain(GetModuleHandle(0), 0, 0, 0);
  return result;
}

int WinMain(
  HINSTANCE Instance,
  HINSTANCE PrevInstance,
  LPSTR CommandLine,
  int ShowCode)
{
  /* Export Directory */
  PTEB TEB = (PTEB)NtCurrentTeb();
  PPEB PEB = (PPEB)TEB->ProcessEnvironmentBlock; // Or, PPEB PEB = (PPEB)__readfsdword(0x30);
  PLIST_ENTRY listEntry = PEB->Ldr->InLoadOrderModuleList.Flink->Flink->Flink; // self->ntdll.dll->kernel32.dll
  PLDR_MODULE kernel32 = CONTAINING_RECORD(listEntry, LDR_MODULE, InLoadOrderModuleList);
  DWORD baseAddress = (DWORD)kernel32->BaseAddress;
  DWORD peHeader = ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew;
  PIMAGE_DATA_DIRECTORY exportDirectory = (PIMAGE_DATA_DIRECTORY)(baseAddress + peHeader + 0x78);
  PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(baseAddress + exportDirectory->VirtualAddress);
  DWORD functions = exports->NumberOfNames;
  DWORD  *names = (DWORD *)(exports->AddressOfNames + baseAddress);
  USHORT *ordinals = (USHORT *)(exports->AddressOfNameOrdinals + baseAddress);
  DWORD  *addresses = (DWORD *)(exports->AddressOfFunctions + baseAddress);
  
  /* Looping through exports to find CreateProcessA */
  int ordinal = 0;
  for (int o = 0; o < functions; o++)
  {
    char* name = (char*)(names[o] + baseAddress);
    if (hash(name) == 0x16B3FE72) // CreateProcessA
    {
      ordinal = ordinals[o];
      break;
    }
  }

  /* Found it */
  LPVOID CreateProcessA = (LPVOID)(addresses[ordinal] + baseAddress);

  /* Empty struct */
  int empty[0x20];
  for (int i = 0; i < 0x20; i++)
  {
    empty[i] = 0;
  }

  /* Build "calc\0" */
  BYTE a = 0xDE ^ 0xBD; // 'c'
  BYTE b = 0xAD ^ 0xCC; // 'a'
  BYTE c = 0xBE ^ 0xD2; // 'l'
  BYTE d = 0xEF ^ 0x8C; // 'c'
  BYTE e = 0xCC ^ 0xCC; // '\0'
  BYTE cmd[5] = { a, b, c, d, e };

  /* Let's do this! */
  ((BOOL(*)
  (
    LPCSTR, // _in_opt    LPCSTR                lpApplicationName
    LPSTR,  // _inout_opt LPSTR                 lpCommandLine
    LPVOID, // _in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes
    LPVOID, // _in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes
    BOOL,   // _in        BOOL                  bInheritHandles
    DWORD,  // _in        DWORD                 dwCreationFlags
    LPVOID, // _in_opt    LPVOID                lpEnvironment
    LPCSTR, // _in_opt    LPCSTR                lpCurrentDirectory
    LPVOID, // _in        LPSTARTUPINFOA        lpStartupInfo
    LPVOID  // out        LPPROCESS_INFORMATION lpProcessInformation
  ))CreateProcessA)
  (
    0,
    (LPSTR)cmd,
    0,
    0,
    0,
    0,
    0,
    0,
    empty,
    empty
  );
  
  return 0;
}
