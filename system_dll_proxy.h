#ifndef SYSTEM_DLL_PROXY_H
#define SYSTEM_DLL_PROXY_H

#define DECLARE_TRAMPOLINE(name)                             \
  const char k##name[] = #name;                              \
  void* p##name;                                             \
  __declspec(dllexport) __attribute__((naked)) void name() { \
    __asm jmp[p##name]                                       \
  }

#define BEGIN_INIT_METHOD(name)                                     \
  const char k##name[] = "\\" #name ".dll";                         \
  const char* init_proxy_##name(void) {                             \
    const int size = sizeof(k##name) / sizeof(char);                \
    char path[MAX_PATH];                                            \
    const DWORD offset = GetSystemDirectoryA(path, MAX_PATH);       \
    if (offset == 0x00 || offset + size >= MAX_PATH) {              \
      return &k##name[0x01];                                        \
    }                                                               \
    for (int i = size - sizeof(DWORD); i > 0; i -= sizeof(DWORD)) { \
      *(DWORD*)&path[offset + i] = *(DWORD*)&k##name[i];            \
    }                                                               \
    *(DWORD*)&path[offset] = *(DWORD*)&k##name[0];                  \
    const HMODULE handle = LoadLibraryA(&path[0x00]);               \
    if (handle == NULL) {                                           \
      return &k##name[0x01];                                        \
    }

#define INIT_TRAMPOLINE(name)                              \
  p##name = (void*)GetProcAddress(handle, &k##name[0x00]); \
  if (p##name == NULL) {                                   \
    FreeLibrary(handle);                                   \
    return &k##name[0x00];                                 \
  }

#define END_INIT_METHOD() \
  return NULL;            \
  }
#endif
