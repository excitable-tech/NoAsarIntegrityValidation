// ReSharper disable CppClangTidyPerformanceNoIntToPtr
// ReSharper disable CppClangTidyClangDiagnosticCastAlign
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

const char kUnsupportedVersion[] = "Unsupported version";
const char kVirtualProtectFailed[] = "VirtualProtect failed";

const char* init_fuse(void) {
  char* p_fuse = find_fuse(0x00);
  if (p_fuse == NULL) {
    p_fuse = find_fuse(0x04);
    if (p_fuse == NULL)
      return NULL;
  }
  if (*p_fuse != 0x01) {
    return &kUnsupportedVersion[0x00];
  }
  if (p_fuse[1] < 0x05)
    return NULL;

  DWORD protection;
  p_fuse += 0x06;
  if (!VirtualProtect(p_fuse, 0x01, PAGE_READWRITE, &protection)) {
    return &kVirtualProtectFailed[0x00];
  }
  *p_fuse = 0x72;
  VirtualProtect(p_fuse, 0x01, protection, &protection);
  return NULL;
}