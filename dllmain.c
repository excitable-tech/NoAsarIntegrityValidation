// ReSharper disable CppClangTidyPerformanceNoIntToPtr
// ReSharper disable CppClangTidyClangDiagnosticCastAlign

#ifndef VER_H
// prevent header inclusion 
#define VER_H
#endif

#include <Windows.h>

#define SENTINEL_SIZE 0x20
#define ALIGN_EIGHT(ptr, modifier) \
  ((((ULONG_PTR)(ptr) + 0x07) & ~0x07) + ((modifier) * 0x08))

char* find_fuse(const int offset) {
  char* handle = (char*)GetModuleHandleA(NULL);
  if (handle == NULL)
    return NULL;
  const IMAGE_NT_HEADERS* p_nt_headers =
      (IMAGE_NT_HEADERS*)(handle + ((IMAGE_DOS_HEADER*)handle)->e_lfanew);
  const char* limit = (char*)ALIGN_EIGHT(
      handle + p_nt_headers->OptionalHeader.SizeOfImage - SENTINEL_SIZE, -0x01);

#if defined(_WIN64) && _WIN64
  const DWORD64* end_ptr = (const DWORD64*)(limit - offset);
  for (DWORD64* ptr = (DWORD64*)((char*)ALIGN_EIGHT(handle, 0x01) + offset);
       ptr < end_ptr; ptr++) {
    if (*ptr != 0x6E64474B70374C64)
      continue;
    if (ptr[0x01] != 0x6262503639377A4E || ptr[0x02] != 0x58486D4B4E57516A ||
        ptr[0x03] != 0x5873743942615A42)
      continue;
#else
  const DWORD* end_ptr = (const DWORD*)(limit - offset);
  for (DWORD* ptr = (DWORD*)((char*)ALIGN_EIGHT(handle, 0x01) + offset);
       ptr < end_ptr; ptr += 0x02) {
    if (*ptr != 0x70374C64)
      continue;
    if (ptr[0x01] != 0x6E64474B || ptr[0x02] != 0x39377A4E ||
        ptr[0x03] != 0x62625036 || ptr[0x04] != 0x4E57516A ||
        ptr[0x05] != 0x58486D4B || ptr[0x06] != 0x42615A42 ||
        ptr[0x07] != 0x58737439)
      continue;
#endif
    return (char*)ptr + SENTINEL_SIZE;
  }

  return NULL;
}

#undef ALIGN_EIGHT
#undef SENTINEL_SIZE
#define PROXY_TRAMPOLINE(name)                               \
  void* p##name;                                             \
  __declspec(dllexport) __attribute__((naked)) void name() { \
    __asm jmp [p##name]                             \
  }

PROXY_TRAMPOLINE(GetFileVersionInfoA)
PROXY_TRAMPOLINE(GetFileVersionInfoByHandle)
PROXY_TRAMPOLINE(GetFileVersionInfoExA)
PROXY_TRAMPOLINE(GetFileVersionInfoExW)
PROXY_TRAMPOLINE(GetFileVersionInfoSizeA)
PROXY_TRAMPOLINE(GetFileVersionInfoSizeExA)
PROXY_TRAMPOLINE(GetFileVersionInfoSizeExW)
PROXY_TRAMPOLINE(GetFileVersionInfoSizeW)
PROXY_TRAMPOLINE(GetFileVersionInfoW)
PROXY_TRAMPOLINE(VerFindFileA)
PROXY_TRAMPOLINE(VerFindFileW)
PROXY_TRAMPOLINE(VerInstallFileA)
PROXY_TRAMPOLINE(VerInstallFileW)
PROXY_TRAMPOLINE(VerLanguageNameA)
PROXY_TRAMPOLINE(VerLanguageNameW)
PROXY_TRAMPOLINE(VerQueryValueA)
PROXY_TRAMPOLINE(VerQueryValueW)

#undef PROXY_TRAMPOLINE
#define PROXY_RESOLVE(name) \
  p##name = (void*)GetProcAddress(handle, #name); \
  if (p##name == NULL) { \
    return FALSE; \
  }

BOOL init_proxy(void) {
  char path[MAX_PATH];
  const DWORD offset = GetSystemDirectoryA(path, MAX_PATH);
  if (offset == 0x00 || offset + 0x0C >= MAX_PATH) {
    return FALSE;
  }
  *(DWORD*)&path[offset] = 0x7265765C;
  *(DWORD*)&path[offset + 0x04] = 0x6E6F6973;
  *(DWORD*)&path[offset + 0x08] = 0x6C6C642E;
  path[offset + 0x0C] = 0x00;

  const HMODULE handle = LoadLibraryA(&path[0x00]);
  PROXY_RESOLVE(GetFileVersionInfoA)
  PROXY_RESOLVE(GetFileVersionInfoByHandle)
  PROXY_RESOLVE(GetFileVersionInfoExA)
  PROXY_RESOLVE(GetFileVersionInfoExW)
  PROXY_RESOLVE(GetFileVersionInfoSizeA)
  PROXY_RESOLVE(GetFileVersionInfoSizeExA)
  PROXY_RESOLVE(GetFileVersionInfoSizeExW)
  PROXY_RESOLVE(GetFileVersionInfoSizeW)
  PROXY_RESOLVE(GetFileVersionInfoW)
  PROXY_RESOLVE(VerFindFileA)
  PROXY_RESOLVE(VerFindFileW)
  PROXY_RESOLVE(VerInstallFileA)
  PROXY_RESOLVE(VerInstallFileW)
  PROXY_RESOLVE(VerLanguageNameA)
  PROXY_RESOLVE(VerLanguageNameW)
  PROXY_RESOLVE(VerQueryValueA)
  PROXY_RESOLVE(VerQueryValueW)
  return TRUE;
}

#undef PROXY_RESOLVE

BOOL APIENTRY dll_main(const HMODULE handle, const DWORD reason, LPVOID dummy) {
  if (reason != DLL_PROCESS_ATTACH)
    return TRUE;

  DisableThreadLibraryCalls(handle);
  if (!init_proxy()) {
    MessageBoxA(0x00, "Failed to initialize version.dll", "Error", MB_ICONERROR);
    return FALSE;
  }

  char* p_fuse = find_fuse(0x00);
  if (p_fuse == NULL) {
    p_fuse = find_fuse(0x04);
    if (p_fuse == NULL)
      return TRUE;
  }
  if (*p_fuse != 0x01) {
    MessageBoxA(0x00, "Unsupported Fuse version", "Error", MB_ICONERROR);
    return FALSE;
  }
  if (p_fuse[1] < 0x05)
    return TRUE;

  DWORD protection;
  p_fuse += 0x06;
  VirtualProtect(p_fuse, 0x01, PAGE_READWRITE, &protection);
  *p_fuse = 0x72;
  VirtualProtect(p_fuse, 0x01, protection, &protection);
  return TRUE;
}
