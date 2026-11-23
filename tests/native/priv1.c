/* The privileges of the logged-on user's token: started by userinit as the
   shell of Administrator (a scenario's `session`), it lists the privileges
   of its token (GetTokenInformation, TokenPrivileges) by name, with their
   attributes, then enables SeShutdownPrivilege, which a session needs to
   shut the system down (ExitWindowsEx). lsasrv gives a logon token the
   privileges of the LSA accounts of its groups (LsapSetPrivileges), which
   minoinit gives them at setup from the [Privilege Rights] of defltwk.inf:
   20 for Administrators. Each line goes to the debug port (DbgPrint). */
#include "app_probe.h"

#define TAG "[priv] "

__declspec(dllimport) LONG NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

typedef BOOL(WINAPI *OpenProcessTokenFn)(HANDLE, DWORD, HANDLE *);
typedef BOOL(WINAPI *GetTokenInformationFn)(HANDLE, TOKEN_INFORMATION_CLASS, void *, DWORD, DWORD *);
typedef BOOL(WINAPI *LookupPrivilegeNameWFn)(const WCHAR *, LUID *, WCHAR *, DWORD *);

/* SE_SHUTDOWN_PRIVILEGE. */
#define SHUTDOWN_PRIVILEGE 19

static char narrow_buffer[128];
static const char *narrow(const WCHAR *w)
{
    if (!WideCharToMultiByte(CP_ACP, 0, w, -1, narrow_buffer, sizeof(narrow_buffer), 0, 0)) narrow_buffer[0] = 0;
    return narrow_buffer;
}

static DWORD buffer[1024];

DWORD WINAPI GuiStartup(void)
{
    HMODULE advapi32 = LoadLibraryW(L"advapi32.dll");
    OpenProcessTokenFn open_token = (OpenProcessTokenFn)(void *)GetProcAddress(advapi32, "OpenProcessToken");
    GetTokenInformationFn token_information =
        (GetTokenInformationFn)(void *)GetProcAddress(advapi32, "GetTokenInformation");
    LookupPrivilegeNameWFn privilege_name =
        (LookupPrivilegeNameWFn)(void *)GetProcAddress(advapi32, "LookupPrivilegeNameW");
    HANDLE token = 0;
    DWORD size = 0;
    if (!open_token || !token_information || !privilege_name) {
        DbgPrint(TAG "FAIL advapi32 (%lu)\n", GetLastError());
        ExitProcess(1);
    }
    if (!open_token(GetCurrentProcess(), TOKEN_QUERY, &token)
        || !token_information(token, TokenPrivileges, buffer, sizeof(buffer), &size)) {
        DbgPrint(TAG "FAIL the token's privileges (%lu)\n", GetLastError());
        ExitProcess(1);
    }
    TOKEN_PRIVILEGES *privileges = (TOKEN_PRIVILEGES *)buffer;
    DbgPrint(TAG "%lu privileges\n", privileges->PrivilegeCount);
    for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
        WCHAR name[64];
        DWORD length = 64;
        LUID luid = privileges->Privileges[i].Luid;
        if (!privilege_name(0, &luid, name, &length)) name[0] = 0;
        DbgPrint(TAG "%s (%lu): attributes %lx\n", narrow(name), luid.LowPart, privileges->Privileges[i].Attributes);
    }
    CloseHandle(token);
    BOOLEAN was = FALSE;
    LONG status = RtlAdjustPrivilege(SHUTDOWN_PRIVILEGE, TRUE, FALSE, &was);
    DbgPrint(TAG "RtlAdjustPrivilege SeShutdownPrivilege: %08lx (it was %d)\n", status, was);
    DbgPrint(TAG "done\n");
    ExitProcess(0);
    return 0;
}
