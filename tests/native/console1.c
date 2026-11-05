/*
 * M5, console: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32, which the scenario `console` puts on the
 * boot disk in the place of winlogon.exe (like `gui`, see gui1.c). It takes
 * a desktop like winlogon, then starts THREADS1.EXE (threads1.c), a program
 * of the CONSOLE subsystem, by CreateProcessW: kernel32 creates the process
 * and tells csrss (basesrv), and the new process asks consrv for its
 * console. It waits for it and reads its exit code. Each result goes to the
 * debug port (DbgPrint), where the scenario looks for it; the program ends
 * with EXIT_STATUS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HWINSTA;
typedef void *HDESK;

typedef struct {
    DWORD cb;
    WCHAR *lpReserved;
    WCHAR *lpDesktop;
    WCHAR *lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    BYTE *lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOW;

typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION;

#define MAXIMUM_ALLOWED 0x02000000
#define WAIT_OBJECT_0 0
#define CHILD_WAIT 60000
#define INFINITE 0xFFFFFFFF
#define EXIT_STATUS 0x600D

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line, void *process_attributes,
                                                    void *thread_attributes, BOOL inherit_handles, DWORD flags,
                                                    void *environment, const WCHAR *directory,
                                                    STARTUPINFOW *startup_info, PROCESS_INFORMATION *information);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) BOOL __stdcall GetExitCodeProcess(HANDLE process, DWORD *code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

/* Like winlogon: the logon process, WinSta0, a desktop, on it. */
static BOOL take_a_desktop(void)
{
    HWINSTA station;
    HDESK desktop;

    if (!RegisterLogonProcess(GetCurrentProcessId(), 1))
        return 0;
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station))
        return 0;
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    if (!desktop || !SetThreadDesktop(desktop) || !SwitchDesktop(desktop))
        return 0;
    DbgPrint("[console] on WinSta0\\Default\n");
    return 1;
}

/* THREADS1.EXE, started on this desktop; its exit code once it ends. */
static void start_the_console_program(void)
{
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD wait;
    DWORD code = 0;

    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\THREADS1.EXE", 0, 0, 0, 0, 0, 0, 0, &startup, &process)) {
        DbgPrint("[console] CreateProcessW: error %lu\n", GetLastError());
        return;
    }
    DbgPrint("[console] CreateProcessW: a process and its thread\n");
    wait = WaitForSingleObject(process.hProcess, CHILD_WAIT);
    if (!GetExitCodeProcess(process.hProcess, &code))
        DbgPrint("[console] GetExitCodeProcess: error %lu\n", GetLastError());
    DbgPrint("[console] THREADS1.EXE: wait %lu, exit code %lx\n", wait, code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

/* CONSHOW1.EXE, started on this desktop, which stays with its console
   shown: this program waits for it, so that the screen capture shows it. */
static void start_the_console_window(void)
{
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;

    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\CONSHOW1.EXE", 0, 0, 0, 0, 0, 0, 0, &startup, &process)) {
        DbgPrint("[console] CreateProcessW(CONSHOW1.EXE): error %lu\n", GetLastError());
        return;
    }
    DbgPrint("[console] CONSHOW1.EXE started\n");
    DbgPrint("[console] done\n");
    WaitForSingleObject(process.hProcess, INFINITE);
}

DWORD __stdcall GuiStartup(void)
{
    if (!take_a_desktop())
        ExitProcess(1);
    start_the_console_program();
    start_the_console_window();
    ExitProcess(EXIT_STATUS);
    return 0;
}
