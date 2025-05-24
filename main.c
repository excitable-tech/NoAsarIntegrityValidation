#include <Windows.h>

extern const char* init_proxy_version(void);
extern const char* init_fuse(void);

const char kProxyError[] = "Proxy error";
const char kFuseError[] = "Fuse error";

BOOL APIENTRY dll_main(const HMODULE handle, const DWORD reason, LPVOID dummy) {
  if (reason != DLL_PROCESS_ATTACH)
    return TRUE;

  DisableThreadLibraryCalls(handle);
  const char* proxy = init_proxy_version();
  if (proxy != NULL) {
    MessageBoxA(0x00, proxy, &kProxyError[0], MB_ICONERROR);
    return FALSE;
  }

  const char* fuse = init_fuse();
  if (fuse != NULL) {
    MessageBoxA(0x00, fuse, &kFuseError[0], MB_ICONERROR);
    return FALSE;
  }

  return TRUE;
}
