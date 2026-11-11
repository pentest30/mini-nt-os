/*
 * The Notepad probe: a Win32 program (subsystem WINDOWS), compiled with
 * MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `notepad` puts on the boot disk in the place of winlogon.exe (like `cmd`,
 * see concmd1.c). Like winlogon, it takes WinSta0\Default and loads the US
 * keyboard layout. It checks RegisterWindowMessage (the same message for the
 * same name, whatever its case) and CreateAcceleratorTableW (a count beyond
 * what the kernel takes is refused, without stopping the system); then it starts ReactOS's notepad.exe by
 * CreateProcessW and, for PROBE_SECONDS, lists the top-level windows of the
 * desktop with their titles when the list changes, and says when Notepad
 * ends (its exit code). When Notepad's window is there, it checks that
 * GetWindowThreadProcessId gives Notepad's process and thread, and says so
 * ("[notepad] Notepad is up"): the scenario then types Ctrl+G, Notepad's
 * accelerator for its "Goto line" dialog, then Escape when the probe has
 * seen the dialog. One line of the debug port (DbgPrint) for each; the
 * program ends with EXIT_STATUS.
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
#define POLL_MS 250
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
__declspec(dllimport) DWORD __stdcall GetWindowThreadProcessId(HWND window, DWORD *process);
__declspec(dllimport) UINT __stdcall RegisterWindowMessageW(const WCHAR *name);
__declspec(dllimport) int __stdcall CopyAcceleratorTableW(HANDLE table, void *entries, int count);
__declspec(dllimport) HANDLE __stdcall CreateAcceleratorTableW(void *entries, int count);
__declspec(dllimport) BOOL __stdcall DestroyAcceleratorTable(HANDLE table);
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

/* The two strings are the same. */
static int same_text(const char *a, const char *b)
{
    while (*a && *a == *b)
        a++, b++;
    return *a == *b;
}

/* RegisterWindowMessage: a message of 0xC000 or more, the same for the same
 * name in another case. */
static void check_registered_message(void)
{
    UINT first = RegisterWindowMessageW(L"commdlg_FindReplace");
    UINT again = RegisterWindowMessageW(L"COMMDLG_FINDREPLACE");
    UINT other = RegisterWindowMessageW(L"Mino notepad probe");
    if (first >= 0xC000 && first == again && other >= 0xC000 && other != first)
        DbgPrint("[notepad] RegisterWindowMessage: one message per name\n");
    else
        DbgPrint("[notepad] RegisterWindowMessage: %x %x %x\n", first, again, other);
}

/* `from` copied to `to` (at most 64 bytes, as `ascii` gives). */
static void copy_text(char *to, const char *from)
{
    int i;
    for (i = 0; i < 63 && from[i]; i++)
        to[i] = from[i];
    to[i] = 0;
}

/* ACCEL. */
typedef struct {
    BYTE fVirt;
    WORD key;
    WORD cmd;
} ACCEL;

#define FVIRTKEY 0x01
#define FCONTROL 0x08
#define ERROR_NOT_ENOUGH_MEMORY 8

/* CreateAcceleratorTableW (NtUserCreateAcceleratorTable itself in user32): a
 * table of one entry is made, copied and destroyed; a count of 0xFFFFFFFF,
 * which the kernel once allocated before looking at it (and stopped the
 * system), is refused with ERROR_NOT_ENOUGH_MEMORY. */
static void check_accelerator_tables(void)
{
    ACCEL entry = {FVIRTKEY | FCONTROL, 'S', 0x101};
    HANDLE table = CreateAcceleratorTableW(&entry, 1);
    int copied = table ? CopyAcceleratorTableW(table, 0, 0) : -1;
    BOOL destroyed = table && DestroyAcceleratorTable(table);
    HANDLE huge = CreateAcceleratorTableW(&entry, -1);
    DWORD error = GetLastError();
    if (table && copied == 1 && destroyed && !huge && error == ERROR_NOT_ENOUGH_MEMORY)
        DbgPrint("[notepad] CreateAcceleratorTable: one entry made, a huge count refused\n");
    else
        DbgPrint("[notepad] CreateAcceleratorTable: %p %d %d %p %lu\n", table, copied, destroyed, huge, error);
}

/* What the probe has seen of Notepad's windows. */
static int notepad_seen, goto_seen, goto_closed;

/* The windows and their titles, when they are not those of the last time:
 * another window, or another title. Notepad's window is "Notepad" from its
 * creation until Notepad names its document ("Untitled - Notepad"); a probe
 * that only looked at the windows could see it in between and never again.
 * Notepad's window checked the first time it has that title, its "Goto
 * line" dialog followed. */
static void list_windows(const PROCESS_INFORMATION *process)
{
    static HWND last[MAX_WINDOWS];
    static char last_text[MAX_WINDOWS][64];
    static int last_count = -1;
    char texts[MAX_WINDOWS][64];
    WCHAR title[64];
    int i, same, has_goto = 0;

    window_count = 0;
    EnumWindows(collect, 0);
    for (i = 0; i < window_count; i++) {
        title[0] = 0;
        GetWindowTextW(windows[i], title, 64);
        ascii(title, texts[i]);
    }
    same = window_count == last_count;
    for (i = 0; same && i < window_count; i++)
        same = windows[i] == last[i] && same_text(texts[i], last_text[i]);
    if (same)
        return;
    DbgPrint("[notepad] %d top-level windows\n", window_count);
    for (i = 0; i < window_count; i++) {
        const char *text = texts[i];
        DbgPrint("[notepad]   %p \"%s\"\n", windows[i], text);
        last[i] = windows[i];
        copy_text(last_text[i], text);
        if (!notepad_seen && same_text(text, "Untitled - Notepad")) {
            DWORD pid = 0, tid = GetWindowThreadProcessId(windows[i], &pid);
            notepad_seen = 1;
            if (pid == process->dwProcessId && tid == process->dwThreadId)
                DbgPrint("[notepad] Notepad is up: its window is its main thread's\n");
            else
                DbgPrint("[notepad] the window of PID %lu TID %lu, not %lu %lu\n", pid, tid,
                         process->dwProcessId, process->dwThreadId);
        }
        if (same_text(text, "Goto line"))
            has_goto = 1;
    }
    last_count = window_count;
    if (has_goto && !goto_seen) {
        goto_seen = 1;
        DbgPrint("[notepad] the Goto line dialog is up\n");
    } else if (!has_goto && goto_seen && !goto_closed) {
        goto_closed = 1;
        DbgPrint("[notepad] the Goto line dialog is closed\n");
    }
}

DWORD __stdcall GuiStartup(void)
{
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    WCHAR command_line[] = L"notepad.exe";
    DWORD code = 0;
    int tick;

    if (!take_a_desktop())
        ExitProcess(1);
    check_registered_message();
    check_accelerator_tables();
    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE", command_line, 0, 0, 0, 0, 0, L"C:\\", &startup,
                        &process)) {
        DbgPrint("[notepad] CreateProcessW: error %lu\n", GetLastError());
        ExitProcess(2);
    }
    DbgPrint("[notepad] launched (PID %lu)\n", process.dwProcessId);
    for (tick = 0; tick < PROBE_SECONDS * 1000 / POLL_MS; tick++) {
        list_windows(&process);
        if (WaitForSingleObject(process.hProcess, POLL_MS) != WAIT_TIMEOUT) {
            GetExitCodeProcess(process.hProcess, &code);
            DbgPrint("[notepad] ended: exit code %08lx\n", code);
            break;
        }
    }
    list_windows(&process);
    DbgPrint("[notepad] probe done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
