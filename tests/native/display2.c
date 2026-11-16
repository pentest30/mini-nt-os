/*
 * The display settings (M6), second probe: the Display panel. A Win32
 * program (subsystem WINDOWS), built with MinGW and linked to ReactOS's
 * kernel32, user32 and gdi32, which the scenario `display-panel` puts in the
 * place of winlogon.exe. Like winlogon, it takes WinSta0\Default; a second
 * thread keeps a top-level window of its own, which hears WM_DISPLAYCHANGE,
 * and its messages (GetMessage). Then the first thread starts
 * ReactOS's Display panel on its Settings page:
 *     rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,3
 * and, four times a second, lists the top-level windows with their titles
 * when they change, until rundll32 ends (WaitForSingleObject: with
 * MsgWaitForMultipleObjects, the queue's event stayed signaled and the probe
 * spun, starving the panel; see docs/passation.md). It says when the panel ("Properties for Display",
 * comctl32's PSH_PROPTITLE) is up:
 * the scenario then types Alt+S (the "Screen area" slider), Home (its
 * smallest resolution, 640x480) and Enter (OK: the page applies it by
 * ChangeDisplaySettingsEx(CDS_UPDATEREGISTRY)). It says when the panel's
 * "Display Settings" dialog asks whether to keep them: the scenario types
 * Alt+Y. When rundll32 ends, it checks the mode in use, the system metrics,
 * the registry's mode and what its window heard (WM_DISPLAYCHANGE, once, of
 * 640x480), and paints its window, moved to the bottom-right corner of the
 * new screen, green.
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
typedef unsigned int WPARAM;
typedef long LRESULT;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HWINSTA;
typedef void *HDESK;
typedef void *HKL;
typedef void *HDC;
typedef void *HBRUSH;
typedef void *HINSTANCE;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL(__stdcall *WNDENUMPROC)(HWND, LPARAM);

typedef struct {
    LONG left, top, right, bottom;
} RECT;

typedef struct {
    LONG x, y;
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
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HANDLE hIcon;
    HANDLE hCursor;
    HBRUSH hbrBackground;
    const WCHAR *lpszMenuName;
    const WCHAR *lpszClassName;
    HANDLE hIconSm;
} WNDCLASSEXW;

typedef struct {
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    BYTE rgbReserved[32];
} PAINTSTRUCT;

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

/* DEVMODEW of NT 5 (220 bytes), the display's fields. */
typedef struct {
    WCHAR dmDeviceName[32];
    WORD dmSpecVersion;
    WORD dmDriverVersion;
    WORD dmSize;
    WORD dmDriverExtra;
    DWORD dmFields;
    LONG dmPositionX, dmPositionY;
    DWORD dmDisplayOrientation;
    DWORD dmDisplayFixedOutput;
    short dmColor, dmDuplex, dmYResolution, dmTTOption, dmCollate;
    WCHAR dmFormName[32];
    WORD dmLogPixels;
    DWORD dmBitsPerPel;
    DWORD dmPelsWidth;
    DWORD dmPelsHeight;
    DWORD dmDisplayFlags;
    DWORD dmDisplayFrequency;
    DWORD dmICMMethod, dmICMIntent, dmMediaType, dmDitherType, dmReserved1, dmReserved2;
    DWORD dmPanningWidth, dmPanningHeight;
} DEVMODEW;

typedef char devmode_is_220_bytes[sizeof(DEVMODEW) == 220 ? 1 : -1];

#define MAXIMUM_ALLOWED 0x02000000
#define KLF_ACTIVATE 0x00000001
#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define WM_PAINT 0x000F
#define WM_DISPLAYCHANGE 0x007E
#define SWP_NOZORDER 0x0004
#define SWP_NOACTIVATE 0x0010
#define INFINITE 0xFFFFFFFF
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define ENUM_CURRENT_SETTINGS ((DWORD)-1)
#define ENUM_REGISTRY_SETTINGS ((DWORD)-2)
#define PROBE_SECONDS 180
#define POLL_MS 250
#define MAX_WINDOWS 16
#define SETTLE_MS 3000
#define EXIT_STATUS 0x6053
/* The green of its window: RGB(0x20, 0xA0, 0x40). */
#define GREEN 0x0040A020

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line,
                                                    void *process_attributes, void *thread_attributes,
                                                    BOOL inherit_handles, DWORD flags, void *environment,
                                                    const WCHAR *directory, STARTUPINFOW *startup_info,
                                                    PROCESS_INFORMATION *information);
__declspec(dllimport) BOOL __stdcall GetExitCodeProcess(HANDLE process, DWORD *code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);
typedef DWORD(__stdcall *THREADPROC)(void *);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREADPROC start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual, BOOL initial, const WCHAR *name);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *name, UINT flags);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) WORD __stdcall RegisterClassExW(const WNDCLASSEXW *klass);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *klass, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     void *menu, HINSTANCE instance, void *parameter);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT first, UINT last);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) int __stdcall FillRect(HDC dc, const RECT *rect, HBRUSH brush);
__declspec(dllimport) BOOL __stdcall SetWindowPos(HWND window, HWND after, int x, int y, int width, int height,
                                                  UINT flags);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) BOOL __stdcall EnumWindows(WNDENUMPROC procedure, LPARAM parameter);
__declspec(dllimport) int __stdcall GetWindowTextW(HWND window, WCHAR *text, int max);
__declspec(dllimport) BOOL __stdcall IsWindowVisible(HWND window);
__declspec(dllimport) BOOL __stdcall EnumDisplaySettingsW(const WCHAR *device, DWORD mode, DEVMODEW *out);
__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(DWORD color);

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
    DbgPrint("[display] on WinSta0\\Default\n");
    return 1;
}

/* What its window heard of WM_DISPLAYCHANGE: how many, the last one (in
 * the window's thread, read by the first one). */
static volatile int heard;
static volatile WPARAM heard_wparam;
static volatile LPARAM heard_lparam;
static HBRUSH green;
static HWND probe_window;
static HANDLE window_ready;

static LRESULT __stdcall window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    PAINTSTRUCT paint;
    RECT rect = {0, 0, 1000, 1000};

    switch (message) {
    case WM_DISPLAYCHANGE:
        heard++;
        heard_wparam = wparam;
        heard_lparam = lparam;
        return 0;
    case WM_PAINT:
        BeginPaint(window, &paint);
        FillRect(paint.hdc, &rect, green);
        EndPaint(window, &paint);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

/* The second thread: the probe's window, and its messages. */
static DWORD __stdcall window_thread(void *parameter)
{
    MSG message;
    (void)parameter;
    probe_window = CreateWindowExW(0, L"MinoDisplay", L"probe", WS_POPUP | WS_VISIBLE, 0, 0, 40, 40, 0, 0,
                                   GetModuleHandleW(0), 0);
    SetEvent(window_ready);
    while (GetMessageW(&message, 0, 0, 0) > 0)
        DispatchMessageW(&message);
    return 0;
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

/* `from` copied to `to` (at most 64 bytes, as `ascii` gives). */
static void copy_text(char *to, const char *from)
{
    int i;
    for (i = 0; i < 63 && from[i]; i++)
        to[i] = from[i];
    to[i] = 0;
}

/* What the probe has seen of the panel: when it was first visible (a tick
 * count), then when it said so; when the dialog was first visible, then
 * when it said so. The panel and its dialog are said up once visible for
 * SETTLE_MS, painted: the keys then reach a page that is ready. */
static DWORD panel_since, confirm_since;
static int panel_said, confirm_said;

/* The windows and their titles, when they are not those of the last time;
 * the panel and its dialog said the first time they are there. */
static void list_windows(void)
{
    static HWND last[MAX_WINDOWS];
    static char last_text[MAX_WINDOWS][64];
    static int last_count = -1;
    char texts[MAX_WINDOWS][64];
    WCHAR title[64];
    int i, same, has_panel = 0, has_confirm = 0;
    DWORD now = GetTickCount();

    window_count = 0;
    EnumWindows(collect, 0);
    for (i = 0; i < window_count; i++) {
        title[0] = 0;
        GetWindowTextW(windows[i], title, 64);
        ascii(title, texts[i]);
        if (same_text(texts[i], "Properties for Display") && IsWindowVisible(windows[i]))
            has_panel = 1;
        if (same_text(texts[i], "Display Settings") && IsWindowVisible(windows[i]))
            has_confirm = 1;
    }
    same = window_count == last_count;
    for (i = 0; same && i < window_count; i++)
        same = windows[i] == last[i] && same_text(texts[i], last_text[i]);
    if (!same) {
        DbgPrint("[display] %d top-level windows\n", window_count);
        for (i = 0; i < window_count; i++) {
            DbgPrint("[display]   %p \"%s\"\n", windows[i], texts[i]);
            last[i] = windows[i];
            copy_text(last_text[i], texts[i]);
        }
        last_count = window_count;
    }
    if (has_panel && !panel_since)
        panel_since = now;
    if (has_confirm && !confirm_since)
        confirm_since = now;
    if (panel_since && !panel_said && now - panel_since >= SETTLE_MS) {
        panel_said = 1;
        DbgPrint("[display] the panel is up: %dx%d\n", GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    }
    if (confirm_since && !confirm_said && now - confirm_since >= SETTLE_MS) {
        confirm_said = 1;
        DbgPrint("[display] the panel asks to keep the settings: %dx%d, WM_DISPLAYCHANGE %d (%u, %08lx)\n",
                 GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), heard, heard_wparam, heard_lparam);
    }
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW klass;
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    WCHAR command_line[] = L"rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,3";
    DEVMODEW current, registry;
    DWORD code = 0, start;
    int ended = 0;

    if (!take_a_desktop())
        ExitProcess(1);
    green = CreateSolidBrush(GREEN);
    memset(&klass, 0, sizeof klass);
    klass.cbSize = sizeof klass;
    klass.lpfnWndProc = window_proc;
    klass.hInstance = GetModuleHandleW(0);
    klass.lpszClassName = L"MinoDisplay";
    RegisterClassExW(&klass);
    window_ready = CreateEventW(0, 1, 0, 0);
    CreateThread(0, 0, window_thread, 0, 0, 0);
    WaitForSingleObject(window_ready, INFINITE);

    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\WINDOWS\\SYSTEM32\\RUNDLL32.EXE", command_line, 0, 0, 0, 0, 0, L"C:\\", &startup,
                        &process)) {
        DbgPrint("[display] CreateProcessW: error %lu\n", GetLastError());
        ExitProcess(2);
    }
    DbgPrint("[display] the panel launched (PID %lu)\n", process.dwProcessId);
    start = GetTickCount();
    while (GetTickCount() - start < PROBE_SECONDS * 1000) {
        list_windows();
        if (WaitForSingleObject(process.hProcess, POLL_MS) == 0) {
            GetExitCodeProcess(process.hProcess, &code);
            ended = 1;
            break;
        }
    }
    list_windows();
    DbgPrint("[display] the panel %s: exit code %08lx\n", ended ? "ended" : "still runs", code);

    memset(&current, 0, sizeof current);
    current.dmSize = sizeof current;
    EnumDisplaySettingsW(0, ENUM_CURRENT_SETTINGS, &current);
    memset(&registry, 0, sizeof registry);
    registry.dmSize = sizeof registry;
    EnumDisplaySettingsW(0, ENUM_REGISTRY_SETTINGS, &registry);
    DbgPrint("[display] after the panel: current %lux%lu, metrics %dx%d, the registry's %lux%lu; "
             "WM_DISPLAYCHANGE %d (%u, %08lx)\n",
             current.dmPelsWidth, current.dmPelsHeight, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
             registry.dmPelsWidth, registry.dmPelsHeight, heard, heard_wparam, heard_lparam);

    /* Its window in the corner of the new screen, green. */
    SetWindowPos(probe_window, 0, GetSystemMetrics(SM_CXSCREEN) - 40, GetSystemMetrics(SM_CYSCREEN) - 40, 40, 40,
                 SWP_NOZORDER | SWP_NOACTIVATE);
    Sleep(500);
    DbgPrint("[display] done\n");
    Sleep(INFINITE);
    ExitProcess(EXIT_STATUS);
    return 0;
}
