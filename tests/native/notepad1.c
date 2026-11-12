/*
 * The Notepad probe: a Win32 program (subsystem WINDOWS), compiled with
 * MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `notepad` puts on the boot disk in the place of winlogon.exe (like `cmd`,
 * see concmd1.c). Like winlogon, it takes WinSta0\Default and loads the US
 * keyboard layout. It checks RegisterWindowMessage (the same message for the
 * same name, whatever its case), CreateAcceleratorTableW (a count beyond
 * what the kernel takes is refused, without stopping the system) and what
 * the Save As dialog needs of the kernel (check_save_dialog_needs); then it starts ReactOS's notepad.exe by
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
typedef long long LONGLONG;
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

typedef struct {
    WORD Length;
    WORD MaximumLength;
    WCHAR *Buffer;
} UNICODE_STRING;

typedef struct {
    DWORD Length;
    HANDLE RootDirectory;
    UNICODE_STRING *ObjectName;
    DWORD Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

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
__declspec(dllimport) DWORD __stdcall GetLogicalDrives(void);
__declspec(dllimport) UINT __stdcall GetDriveTypeW(const WCHAR *root);
__declspec(dllimport) LONG __stdcall NtClose(HANDLE handle);
__declspec(dllimport) LONG __stdcall NtOpenKey(HANDLE *key, DWORD access, OBJECT_ATTRIBUTES *attributes);
__declspec(dllimport) LONG __stdcall NtQueryKey(HANDLE key, DWORD class, void *information, DWORD length,
                                                DWORD *result_length);
__declspec(dllimport) LONG __stdcall NtQueryObject(HANDLE handle, DWORD class, void *information, DWORD length,
                                                   DWORD *result_length);
__declspec(dllimport) LONG __stdcall NtQueryInformationProcess(HANDLE process, DWORD class, void *information,
                                                               DWORD length, DWORD *result_length);
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

#define OBJ_CASE_INSENSITIVE 0x40
#define KEY_READ 0x20019
#define KEY_NAME_INFORMATION 3
#define OBJECT_BASIC_INFORMATION 0
#define PROCESS_DEVICE_MAP 23
#define DRIVE_FIXED 3

/* What the Save As dialog needs of the kernel, by ntdll and kernel32: the
 * DOS drives (ProcessDeviceMap: GetLogicalDrives returned 0, and the shell
 * saw no drive, so "C:\" was no path), the full name of a registry key
 * (NtQueryKey, KeyNameInformation) and the rights of its handle (NtQueryObject,
 * ObjectBasicInformation): advapi32 finds HKEY_CLASSES_ROOT's keys by them. */
static void check_save_dialog_needs(void)
{
    static const WCHAR classes[] = L"\\Registry\\Machine\\Software\\Classes";
    static const WCHAR expected[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes";
    UNICODE_STRING name = {sizeof classes - 2, sizeof classes, (WCHAR *)classes};
    OBJECT_ATTRIBUTES attributes = {sizeof attributes, 0, &name, OBJ_CASE_INSENSITIVE, 0, 0};
    struct {
        DWORD drive_map;
        BYTE drive_type[32];
    } map;
    struct {
        DWORD attributes, granted_access, handle_count, pointer_count;
        DWORD reserved[8];
        LONGLONG creation_time;
    } basic;
    struct {
        DWORD name_length;
        WCHAR name[64];
    } key_name;
    HANDLE key = 0;
    DWORD drives = GetLogicalDrives(), length = 0, i;
    UINT type = GetDriveTypeW(L"C:\\");
    LONG device_map = NtQueryInformationProcess((HANDLE)-1, PROCESS_DEVICE_MAP, &map, sizeof map, 0);
    LONG opened = NtOpenKey(&key, KEY_READ, &attributes);
    LONG too_small = NtQueryKey(key, KEY_NAME_INFORMATION, 0, 0, &length);
    DWORD needed = length;
    LONG named = NtQueryKey(key, KEY_NAME_INFORMATION, &key_name, sizeof key_name, &length);
    LONG mismatch = NtQueryObject(key, OBJECT_BASIC_INFORMATION, &basic, 40, &length);
    LONG queried = NtQueryObject(key, OBJECT_BASIC_INFORMATION, &basic, sizeof basic, &length);
    int same_name = named == 0 && key_name.name_length == sizeof expected - 2;
    for (i = 0; same_name && i < key_name.name_length / 2; i++)
        same_name = key_name.name[i] == expected[i];
    if (key)
        NtClose(key);
    if ((drives & 4) && type == DRIVE_FIXED && device_map == 0 && (map.drive_map & 4) && map.drive_type[2] == 3 &&
        opened == 0 && too_small == (LONG)0xC0000023 && needed == 4 + sizeof expected - 2 && same_name &&
        mismatch == (LONG)0xC0000004 && queried == 0 && length == sizeof basic && basic.granted_access == KEY_READ &&
        basic.handle_count == 1)
        DbgPrint("[notepad] Save As needs: drives, key names, handle rights\n");
    else
        DbgPrint("[notepad] Save As needs: drives %lx type %u map %lx/%lx/%u key %lx %lx %lu %lx %d object %lx %lx "
                 "%lu %lx %lu\n",
                 drives, type, device_map, map.drive_map, map.drive_type[2], opened, too_small, needed, named,
                 same_name, mismatch, queried, length, basic.granted_access, basic.handle_count);
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
    check_save_dialog_needs();
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
