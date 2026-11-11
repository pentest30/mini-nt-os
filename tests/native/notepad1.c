/*
 * The Notepad probe: a Win32 program (subsystem WINDOWS), compiled with
 * MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `notepad` puts on the boot disk in the place of winlogon.exe (like `cmd`,
 * see concmd1.c). Like winlogon, it takes WinSta0\Default and loads the US
 * keyboard layout; then it starts ReactOS's notepad.exe by CreateProcessW
 * and, each second for PROBE_SECONDS, lists the top-level windows of the
 * desktop with their titles when the list changes, and says when Notepad
 * ends (its exit code). One line of the debug port (DbgPrint) for each;
 * the program ends with EXIT_STATUS.
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
typedef long LONG;
typedef long LPARAM;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HWINSTA;
typedef void *HDESK;
typedef void *HKL;
typedef BOOL(__stdcall *WNDENUMPROC)(HWND, LPARAM);

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
#define KLF_ACTIVATE 0x00000001
#define WAIT_TIMEOUT 0x102
#define PROBE_SECONDS 8
#define MAX_WINDOWS 16
#define EXIT_STATUS 0x6011

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line,
                                                    void *process_attributes, void *thread_attributes,
                                                    BOOL inherit_handles, DWORD flags, void *environment,
                                                    const WCHAR *directory, STARTUPINFOW *startup_info,
                                                    PROCESS_INFORMATION *information);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) BOOL __stdcall GetExitCodeProcess(HANDLE process, DWORD *code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) BOOL __stdcall EnumWindows(WNDENUMPROC procedure, LPARAM parameter);
__declspec(dllimport) int __stdcall GetWindowTextW(HWND window, WCHAR *text, int max);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *name, UINT flags);
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

/* Like winlogon: the logon process, WinSta0, a desktop, on it, and the
 * keyboard layout. */
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
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        return 0;
    DbgPrint("[notepad] on WinSta0\\Default\n");
    return 1;
}

/* The top-level windows, as EnumWindows gives them. */
static HWND windows[MAX_WINDOWS];
static int window_count;

static BOOL __stdcall collect(HWND window, LPARAM parameter)
{
    (void)parameter;
    if (window_count < MAX_WINDOWS)
        windows[window_count++] = window;
    return 1;
}

/* `text` in ASCII (non-ASCII as '?'), at most 63 characters. */
static const char *ascii(const WCHAR *text, char *out)
{
    int i;
    for (i = 0; i < 63 && text[i]; i++)
        out[i] = text[i] < 0x80 ? (char)text[i] : '?';
    out[i] = 0;
    return out;
}

/* The windows and their titles, when they are not those of the last time. */
static void list_windows(void)
{
    static HWND last[MAX_WINDOWS];
    static int last_count = -1;
    WCHAR title[64];
    char text[64];
    int i, same;

    window_count = 0;
    EnumWindows(collect, 0);
    same = window_count == last_count;
    for (i = 0; same && i < window_count; i++)
        same = windows[i] == last[i];
    if (same)
        return;
    DbgPrint("[notepad] %d top-level windows\n", window_count);
    for (i = 0; i < window_count; i++) {
        title[0] = 0;
        GetWindowTextW(windows[i], title, 64);
        DbgPrint("[notepad]   %p \"%s\"\n", windows[i], ascii(title, text));
        last[i] = windows[i];
    }
    last_count = window_count;
}

DWORD __stdcall GuiStartup(void)
{
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    WCHAR command_line[] = L"notepad.exe";
    DWORD code = 0;
    int second;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE", command_line, 0, 0, 0, 0, 0, L"C:\\", &startup,
                        &process)) {
        DbgPrint("[notepad] CreateProcessW: error %lu\n", GetLastError());
        ExitProcess(2);
    }
    DbgPrint("[notepad] launched (PID %lu)\n", process.dwProcessId);
    for (second = 0; second < PROBE_SECONDS; second++) {
        list_windows();
        if (WaitForSingleObject(process.hProcess, 1000) != WAIT_TIMEOUT) {
            GetExitCodeProcess(process.hProcess, &code);
            DbgPrint("[notepad] ended: exit code %08lx\n", code);
            break;
        }
    }
    list_windows();
    DbgPrint("[notepad] probe done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
