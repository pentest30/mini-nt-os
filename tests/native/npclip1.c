/*
 * Copy and paste in Notepad: a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `notepad-clipboard` puts on the boot disk in the place of winlogon.exe
 * (like notepad1.c). It takes WinSta0\Default and the US keyboard layout,
 * makes a window V the first clipboard viewer, and starts ReactOS's
 * notepad.exe. When Notepad's window is up ("[npclip] Notepad is up"), QEMU
 * types "Mino", Ctrl+A and Ctrl+C: Notepad's accelerators (^A, ^C) select
 * the text of its Edit control and send it WM_COPY, which puts it on the
 * clipboard (OpenClipboard, EmptyClipboard, SetClipboardData(CF_UNICODETEXT),
 * CloseClipboard). V gets WM_DRAWCLIPBOARD, opens the clipboard, reads the
 * text as CF_TEXT (which user32 synthesizes from CF_UNICODETEXT) and says
 * whose window owns it. Then QEMU types End, Ctrl+V twice (WM_PASTE: the
 * Edit control reads CF_UNICODETEXT), Ctrl+A and Ctrl+C: the clipboard
 * holds "MinoMinoMino". One line of the debug port (DbgPrint) for each; the
 * program ends with EXIT_STATUS once the second copy is read, or after
 * PROBE_SECONDS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short WORD;
typedef unsigned short ATOM;
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HWINSTA;
typedef void *HDESK;
typedef void *HKL;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL(__stdcall *WNDENUMPROC)(HWND, LPARAM);

typedef struct {
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HICON hCursor;
    HBRUSH hbrBackground;
    const WCHAR *lpszMenuName;
    const WCHAR *lpszClassName;
    HICON hIconSm;
} WNDCLASSEXW;

typedef struct {
    LONG x;
    LONG y;
} POINT;

typedef struct {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
} MSG;

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

#define WM_DRAWCLIPBOARD 0x0308
#define CF_TEXT 1
#define CF_UNICODETEXT 13
#define CF_LOCALE 16
#define PM_REMOVE 0x0001
#define QS_ALLINPUT 0x04FF
#define WAIT_OBJECT_0 0
#define MAXIMUM_ALLOWED 0x02000000
#define KLF_ACTIVATE 0x00000001
#define PROBE_SECONDS 40
#define POLL_MS 250
#define MAX_WINDOWS 16
#define EXIT_STATUS 0x6012

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line,
                                                    void *process_attributes, void *thread_attributes,
                                                    BOOL inherit_handles, DWORD flags, void *environment,
                                                    const WCHAR *directory, STARTUPINFOW *startup_info,
                                                    PROCESS_INFORMATION *information);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void *__stdcall GlobalLock(HANDLE memory);
__declspec(dllimport) DWORD __stdcall GlobalSize(HANDLE memory);
__declspec(dllimport) BOOL __stdcall GlobalUnlock(HANDLE memory);

__declspec(dllimport) BOOL __stdcall CloseClipboard(void);
__declspec(dllimport) int __stdcall CountClipboardFormats(void);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall EnumWindows(WNDENUMPROC procedure, LPARAM parameter);
__declspec(dllimport) HANDLE __stdcall GetClipboardData(UINT format);
__declspec(dllimport) HWND __stdcall GetClipboardOwner(void);
__declspec(dllimport) int __stdcall GetWindowTextW(HWND window, WCHAR *text, int max);
__declspec(dllimport) DWORD __stdcall GetWindowThreadProcessId(HWND window, DWORD *process);
__declspec(dllimport) BOOL __stdcall IsClipboardFormatAvailable(UINT format);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *name, UINT flags);
__declspec(dllimport) DWORD __stdcall MsgWaitForMultipleObjects(DWORD count, const HANDLE *handles, BOOL all,
                                                                DWORD milliseconds, DWORD mask);
__declspec(dllimport) BOOL __stdcall OpenClipboard(HWND window);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) HWND __stdcall SetClipboardViewer(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

static const WCHAR CLASS_NAME[] = L"MinoClipboardViewer";
static PROCESS_INFORMATION notepad;
/* The copies read: the probe ends after the second. */
static int copies;

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
    return 1;
}

/* The clipboard changed: its text, read as CF_TEXT, and its owner. */
static void read_the_clipboard(HWND viewer)
{
    char text[64];
    HANDLE data;
    const char *bytes;
    DWORD size, i, owner_process = 0;
    HWND owner;
    int formats;

    if (!OpenClipboard(viewer)) {
        DbgPrint("[npclip] OpenClipboard: error %lu\n", GetLastError());
        return;
    }
    formats = CountClipboardFormats();
    owner = GetClipboardOwner();
    GetWindowThreadProcessId(owner, &owner_process);
    data = GetClipboardData(CF_TEXT);
    bytes = data ? GlobalLock(data) : 0;
    size = bytes ? GlobalSize(data) : 0;
    for (i = 0; i < size && i < sizeof text - 1 && bytes[i]; i++)
        text[i] = bytes[i];
    text[i] = 0;
    if (bytes)
        GlobalUnlock(data);
    CloseClipboard();
    if (!formats) {
        DbgPrint("[npclip] the clipboard is empty\n");
        return;
    }
    copies++;
    DbgPrint("[npclip] copied: \"%s\" (%d formats: CF_UNICODETEXT %d, CF_LOCALE %d), owned by Notepad %d\n", text,
             formats, IsClipboardFormatAvailable(CF_UNICODETEXT), IsClipboardFormatAvailable(CF_LOCALE),
             owner_process == notepad.dwProcessId);
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_DRAWCLIPBOARD) {
        read_the_clipboard(window);
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

/* Every message waiting for this thread, sent ones included. */
static void pump(void)
{
    MSG message;
    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
        DispatchMessageW(&message);
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

/* Notepad's main window has its title. */
static int notepad_is_up(void)
{
    static const WCHAR UNTITLED[] = L"Untitled - Notepad";
    WCHAR title[64];
    int i, j;

    window_count = 0;
    EnumWindows(collect, 0);
    for (i = 0; i < window_count; i++) {
        title[0] = 0;
        GetWindowTextW(windows[i], title, 64);
        for (j = 0; UNTITLED[j] && title[j] == UNTITLED[j]; j++)
            ;
        if (!UNTITLED[j] && !title[j])
            return 1;
    }
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    STARTUPINFOW startup;
    WNDCLASSEXW class_info;
    WCHAR command_line[] = L"notepad.exe";
    HWND viewer;
    int tick, up = 0;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = GetModuleHandleW(0);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    /* Not shown: Notepad keeps the keyboard. */
    viewer = CreateWindowExW(0, CLASS_NAME, L"V", 0, 0, 0, 10, 10, 0, 0, GetModuleHandleW(0), 0);
    if (!viewer)
        ExitProcess(3);
    SetClipboardViewer(viewer);
    pump();
    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE", command_line, 0, 0, 0, 0, 0, L"C:\\", &startup,
                        &notepad)) {
        DbgPrint("[npclip] CreateProcessW: error %lu\n", GetLastError());
        ExitProcess(4);
    }
    for (tick = 0; tick < PROBE_SECONDS * 1000 / POLL_MS && copies < 2; tick++) {
        if (MsgWaitForMultipleObjects(1, &notepad.hProcess, 0, POLL_MS, QS_ALLINPUT) == WAIT_OBJECT_0) {
            DbgPrint("[npclip] Notepad ended\n");
            break;
        }
        pump();
        if (!up && notepad_is_up()) {
            up = 1;
            DbgPrint("[npclip] Notepad is up\n");
        }
    }
    DbgPrint("[npclip] probe done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
