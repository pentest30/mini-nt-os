/*
 * M5, console: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32 and user32, which the scenario `cmd` puts on
 * the boot disk in the place of winlogon.exe (like `console`, see
 * console1.c). Like winlogon, it takes WinSta0\Default and loads the US
 * keyboard layout; then it starts ReactOS's cmd.exe by CreateProcessW, with
 * `/K C:\READ1.EXE`: cmd runs READ1.EXE (read1.c) in its console, which says
 * when the console window waits for keys, then reads the commands that the
 * scenario types (`keys =`), until `exit`. The commands write their results
 * to files of C:, which this program then reads, one line of the debug port
 * (DbgPrint) for each line, where the scenario looks for it; it ends with
 * EXIT_STATUS.
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
typedef void *HKL;

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
#define GENERIC_READ 0x80000000
#define FILE_SHARE_READ 1
#define OPEN_EXISTING 3
#define FILE_ATTRIBUTE_NORMAL 0x80
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define KLF_ACTIVATE 0x00000001
#define CMD_WAIT 100000
#define EXIT_STATUS 0x600D
/* The longest file read, and the longest line printed. */
#define FILE_BYTES 4096
#define LINE_BYTES 160

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR *name, DWORD access, DWORD share, void *attributes,
                                                   DWORD disposition, DWORD flags, HANDLE template_file);
__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line, void *process_attributes,
                                                    void *thread_attributes, BOOL inherit_handles, DWORD flags,
                                                    void *environment, const WCHAR *directory,
                                                    STARTUPINFOW *startup_info, PROCESS_INFORMATION *information);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) BOOL __stdcall GetExitCodeProcess(HANDLE process, DWORD *code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE file, void *buffer, DWORD count, DWORD *read, void *overlapped);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
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
   keyboard layout of the console's keys. */
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
    DbgPrint("[concmd] on WinSta0\\Default\n");
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        return 0;
    return 1;
}

/* The file `name`, one line of the debug port for each of its lines, after
   `tag` and the line's number (from 1); its end of lines (CR, LF) not
   printed. */
static void print_file(const WCHAR *name, const char *tag)
{
    static char bytes[FILE_BYTES + 1];
    char line[LINE_BYTES + 1];
    DWORD read = 0;
    DWORD at;
    DWORD length = 0;
    DWORD number = 0;
    HANDLE file = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (file == INVALID_HANDLE_VALUE) {
        DbgPrint("[concmd] %s: CreateFileW: error %lu\n", tag, GetLastError());
        return;
    }
    if (!ReadFile(file, bytes, FILE_BYTES, &read, 0))
        DbgPrint("[concmd] %s: ReadFile: error %lu\n", tag, GetLastError());
    CloseHandle(file);
    DbgPrint("[concmd] %s: %lu bytes\n", tag, read);
    for (at = 0; at <= read; at++) {
        char c = at < read ? bytes[at] : '\n';
        if (c == '\r')
            continue;
        if (c == '\n') {
            if (length || at < read) {
                line[length] = 0;
                DbgPrint("[concmd] %s %lu: %s\n", tag, ++number, line);
            }
            length = 0;
        } else if (length < LINE_BYTES) {
            line[length++] = c;
        }
    }
}

DWORD __stdcall GuiStartup(void)
{
    static WCHAR command_line[] = L"cmd /K C:\\READ1.EXE";
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD wait;
    DWORD code = 0;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\WINDOWS\\SYSTEM32\\CMD.EXE", command_line, 0, 0, 0, 0, 0, L"C:\\", &startup,
                        &process)) {
        DbgPrint("[concmd] CreateProcessW: error %lu\n", GetLastError());
        ExitProcess(2);
    }
    DbgPrint("[concmd] CMD.EXE started\n");
    wait = WaitForSingleObject(process.hProcess, CMD_WAIT);
    if (!GetExitCodeProcess(process.hProcess, &code))
        DbgPrint("[concmd] GetExitCodeProcess: error %lu\n", GetLastError());
    DbgPrint("[concmd] CMD.EXE: wait %lu, exit code %lx\n", wait, code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    print_file(L"C:\\OUT.TXT", "OUT.TXT");
    print_file(L"C:\\DIR.TXT", "DIR.TXT");
    ExitProcess(EXIT_STATUS);
    return 0;
}
