/* Mino: the functions newer than XP that LLVM's Support library imports, in
   the OpenGL ICD that `cargo xtask icd-build` makes for the XP loader
   (ADR-025). Linked before the import libraries, this object defines each
   function under its own name (`_Name@N`, for direct calls) and its import
   slot (`__imp__Name@N`, for `dllimport` calls), so that the DLL imports
   neither. Each one calls the real function when the system has it
   (GetProcAddress, a newer system), and otherwise fails as the function
   does for an unsupported request: ERROR_CALL_NOT_IMPLEMENTED, or E_NOTIMPL.
   LLVM only uses them for paths, processor groups and memory statistics,
   which it does without. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static FARPROC lookup(const char *module, const char *name)
{
    HMODULE handle = GetModuleHandleA(module);
    if (!handle)
        handle = LoadLibraryA(module);
    return handle ? GetProcAddress(handle, name) : 0;
}

/* A function returning `type`, of `bytes` bytes of arguments, found in
   `module` (or `fallback`, a DLL of XP that has it under the name `old`),
   failing with `failure`. */
#define STUB(type, name, bytes, params, args, module, fallback, old, failure)            \
    type WINAPI mino_##name params __asm__("_" #name "@" #bytes);                         \
    type WINAPI mino_##name params                                                       \
    {                                                                                    \
        typedef type(WINAPI * fn) params;                                                \
        fn real = (fn)(void *)lookup(module, #name);                                     \
        if (!real && (fallback))                                                         \
            real = (fn)(void *)lookup((fallback), (old));                                \
        if (real)                                                                        \
            return real args;                                                            \
        failure;                                                                         \
    }                                                                                    \
    void *mino_slot_##name __asm__("__imp__" #name "@" #bytes) = (void *)mino_##name;

#define UNSUPPORTED(value) do { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return (value); } while (0)

STUB(DWORD, GetFinalPathNameByHandleW, 16, (HANDLE file, LPWSTR path, DWORD size, DWORD flags),
     (file, path, size, flags), "kernel32.dll", 0, 0, UNSUPPORTED(0))
STUB(BOOL, GetLogicalProcessorInformationEx, 12, (int relationship, void *buffer, PDWORD length),
     (relationship, buffer, length), "kernel32.dll", 0, 0, UNSUPPORTED(FALSE))
STUB(BOOL, GetThreadGroupAffinity, 8, (HANDLE thread, void *affinity), (thread, affinity), "kernel32.dll",
     0, 0, UNSUPPORTED(FALSE))
STUB(BOOL, SetThreadGroupAffinity, 12, (HANDLE thread, const void *affinity, void *previous),
     (thread, affinity, previous), "kernel32.dll", 0, 0, UNSUPPORTED(FALSE))
STUB(BOOL, SetFileInformationByHandle, 16, (HANDLE file, int information_class, LPVOID information, DWORD size),
     (file, information_class, information, size), "kernel32.dll", 0, 0, UNSUPPORTED(FALSE))
/* The K32 names are those of later systems; XP has the functions in psapi.dll. */
STUB(BOOL, K32EnumProcessModules, 16, (HANDLE process, HMODULE *modules, DWORD size, LPDWORD needed),
     (process, modules, size, needed), "kernel32.dll", "psapi.dll", "EnumProcessModules", UNSUPPORTED(FALSE))
STUB(BOOL, K32GetProcessMemoryInfo, 12, (HANDLE process, void *counters, DWORD size), (process, counters, size),
     "kernel32.dll", "psapi.dll", "GetProcessMemoryInfo", UNSUPPORTED(FALSE))
STUB(HRESULT, SHGetKnownFolderPath, 16, (const GUID *id, DWORD flags, HANDLE token, PWSTR *path),
     (id, flags, token, path), "shell32.dll", 0, 0, if (path) *path = 0; return E_NOTIMPL)
