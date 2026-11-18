/*
 * The clipboard (win32k::clipboard): a Win32 program (subsystem WINDOWS),
 * compiled with MinGW and linked to ReactOS's kernel32 and user32, which the
 * scenario `clipboard` puts on the boot disk in the place of winlogon.exe.
 * It runs twice: as the writer (the initial command), and as the reader,
 * another process the writer starts ("C:\CLIP1.EXE reader") on its desktop.
 *
 * The writer takes WinSta0\Default like winlogon and makes three windows of
 * one class: W (the clipboard owner), V (the viewer) and, at step 7, W2.
 * 1. SetClipboardViewer(V): the first viewer, WM_DRAWCLIPBOARD at once; a
 *    bad window refused (ERROR_INVALID_WINDOW_HANDLE).
 * 2. Closed: CloseClipboard and SetClipboardData refused
 *    (ERROR_CLIPBOARD_NOT_OPEN), OpenClipboard of a bad window refused;
 *    open by W, another thread can neither open it with V
 *    (ERROR_ACCESS_DENIED) nor empty it or read it (ERROR_CLIPBOARD_NOT_OPEN).
 * 3. EmptyClipboard (W becomes the owner), CF_UNICODETEXT "Mino clipboard:
 *    é", "Mino Private" (a registered format, 4 bytes), "Mino Delayed"
 *    (delayed rendering), CloseClipboard: CF_LOCALE, CF_TEXT and CF_OEMTEXT
 *    are added; the sequence number, the formats (the private one printed
 *    as f001, the delayed one as f002), their names and priorities; V's
 *    WM_DRAWCLIPBOARD.
 * 4. The reader reads everything: CF_UNICODETEXT; CF_TEXT and CF_OEMTEXT,
 *    which user32 synthesizes (é is E9 in code page 1252, 82 in 437);
 *    CF_LOCALE; the private format; the delayed one, which W renders
 *    (WM_RENDERFORMAT, across processes); none of it changes the sequence.
 *    Then it empties the clipboard (WM_DESTROYCLIPBOARD to W, which still
 *    sees its 6 formats), puts CF_TEXT "from the reader" and ends without
 *    closing it: its end closes it (WM_DRAWCLIPBOARD to V).
 * 5. The writer: the clipboard is closed and has no owner, the reader's text
 *    is there after its end, as CF_UNICODETEXT too.
 * 6. The chain: SetClipboardViewer(W) gives V; ChangeClipboardChain(V, 0)
 *    goes to W, the head (WM_CHANGECBCHAIN); the head itself leaves.
 * 7. W2 owns CF_UNICODETEXT and "Mino Delayed", both delayed, and is
 *    destroyed: WM_RENDERALLFORMATS, where it renders the text only; then
 *    the clipboard has no owner and the other delayed format is gone.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
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
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef DWORD(__stdcall *THREAD_START)(void *);

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

#define WS_OVERLAPPED 0x00000000
#define WS_CAPTION 0x00C00000
#define WS_VISIBLE 0x10000000
#define WM_RENDERFORMAT 0x0305
#define WM_RENDERALLFORMATS 0x0306
#define WM_DESTROYCLIPBOARD 0x0307
#define WM_DRAWCLIPBOARD 0x0308
#define WM_CHANGECBCHAIN 0x030D
#define CF_TEXT 1
#define CF_OEMTEXT 7
#define CF_DIB 8
#define CF_UNICODETEXT 13
#define CF_LOCALE 16
#define GMEM_MOVEABLE 0x0002
#define GMEM_DDESHARE 0x2000
#define PM_REMOVE 0x0001
#define QS_ALLINPUT 0x04FF
#define WAIT_OBJECT_0 0
#define INFINITE 0xFFFFFFFF
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define EXIT_STATUS 0x7008
#define BAD_WINDOW ((HWND)0xDEAD)

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE object);
__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line, void *process_attributes,
                                                    void *thread_attributes, BOOL inherit, DWORD flags,
                                                    void *environment, const WCHAR *directory,
                                                    STARTUPINFOW *startup, PROCESS_INFORMATION *information);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREAD_START start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) WCHAR *__stdcall GetCommandLineW(void);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) BOOL __stdcall GetExitCodeProcess(HANDLE process, DWORD *code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) DWORD __stdcall GetThreadLocale(void);
__declspec(dllimport) HANDLE __stdcall GlobalAlloc(UINT flags, DWORD size);
__declspec(dllimport) void *__stdcall GlobalLock(HANDLE memory);
__declspec(dllimport) DWORD __stdcall GlobalSize(HANDLE memory);
__declspec(dllimport) BOOL __stdcall GlobalUnlock(HANDLE memory);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE object, DWORD milliseconds);

__declspec(dllimport) BOOL __stdcall ChangeClipboardChain(HWND remove, HWND next);
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
__declspec(dllimport) BOOL __stdcall DestroyWindow(HWND window);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall EmptyClipboard(void);
__declspec(dllimport) UINT __stdcall EnumClipboardFormats(UINT format);
__declspec(dllimport) HANDLE __stdcall GetClipboardData(UINT format);
__declspec(dllimport) int __stdcall GetClipboardFormatNameW(UINT format, WCHAR *name, int count);
__declspec(dllimport) HWND __stdcall GetClipboardOwner(void);
__declspec(dllimport) DWORD __stdcall GetClipboardSequenceNumber(void);
__declspec(dllimport) HWND __stdcall GetClipboardViewer(void);
__declspec(dllimport) HWND __stdcall GetOpenClipboardWindow(void);
__declspec(dllimport) int __stdcall GetPriorityClipboardFormat(UINT *formats, int count);
__declspec(dllimport) DWORD __stdcall GetWindowThreadProcessId(HWND window, DWORD *process);
__declspec(dllimport) BOOL __stdcall IsClipboardFormatAvailable(UINT format);
__declspec(dllimport) DWORD __stdcall MsgWaitForMultipleObjects(DWORD count, const HANDLE *handles, BOOL all,
                                                                DWORD milliseconds, DWORD mask);
__declspec(dllimport) BOOL __stdcall OpenClipboard(HWND window);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) UINT __stdcall RegisterClipboardFormatW(const WCHAR *name);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) HANDLE __stdcall SetClipboardData(UINT format, HANDLE memory);
__declspec(dllimport) HWND __stdcall SetClipboardViewer(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

static const WCHAR CLASS_NAME[] = L"MinoClipboard";
static const WCHAR TEXT_W[] = L"Mino clipboard: \x00e9";
static const char TEXT_ANSI[] = "Mino clipboard: \xe9";
static const char FROM_THE_READER[] = "from the reader";
static const WCHAR FROM_THE_READER_W[] = L"from the reader";
static const WCHAR RENDERED_AT_THE_END[] = L"rendered at the end";
static const char RENDERED[] = "rendered";

static HDESK desktop;
static HWND owner_window, viewer_window;
static UINT private_format, delayed_format;
/* What the windows received. */
static int viewer_draws, owner_draws, renders, destroys, destroy_count, destroy_owner, chains, render_alls;
static UINT rendered_format;
static WPARAM chain_removed;
static LPARAM chain_next;
static BOOL render_set;

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

/* A movable global block of the `size` bytes at `source`. */
static HANDLE global_bytes(const void *source, DWORD size)
{
    HANDLE memory = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, size);
    unsigned char *bytes = memory ? GlobalLock(memory) : 0;
    const unsigned char *from = source;
    DWORD i;

    if (!bytes)
        return 0;
    for (i = 0; i < size; i++)
        bytes[i] = from[i];
    GlobalUnlock(memory);
    return memory;
}

static DWORD wide_length(const WCHAR *text)
{
    DWORD length = 0;
    while (text[length])
        length++;
    return length;
}

static DWORD ansi_length(const char *text)
{
    DWORD length = 0;
    while (text[length])
        length++;
    return length;
}

/* The block `memory` holds `size` bytes equal to those at `expected`. */
static int same_bytes(HANDLE memory, const void *expected, DWORD size)
{
    const unsigned char *bytes = memory ? GlobalLock(memory) : 0;
    const unsigned char *wanted = expected;
    int same = bytes != 0 && GlobalSize(memory) >= size;
    DWORD i;

    for (i = 0; same && i < size; i++)
        same = bytes[i] == wanted[i];
    if (bytes)
        GlobalUnlock(memory);
    return same;
}

/* Its byte `at`, 0 without it. */
static unsigned byte_at(HANDLE memory, DWORD at)
{
    const unsigned char *bytes = memory ? GlobalLock(memory) : 0;
    unsigned byte = bytes && GlobalSize(memory) > at ? bytes[at] : 0;
    if (bytes)
        GlobalUnlock(memory);
    return byte;
}

/* The formats of the open clipboard, in order, as " %04x" each, the private
   one as f001 and the delayed one as f002. */
static const char *format_list(char *out)
{
    static const char HEX[] = "0123456789abcdef";
    UINT format;
    int at = 0, shift;

    for (format = EnumClipboardFormats(0); format && at < 120; format = EnumClipboardFormats(format)) {
        UINT shown = format == private_format ? 0xF001 : format == delayed_format ? 0xF002 : format;
        out[at++] = ' ';
        for (shift = 12; shift >= 0; shift -= 4)
            out[at++] = HEX[(shown >> shift) & 0xF];
    }
    out[at] = 0;
    return out;
}

/* Every message waiting for this thread, sent ones included. */
static void pump(void)
{
    MSG message;
    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
        DispatchMessageW(&message);
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    switch (message) {
    case WM_DRAWCLIPBOARD:
        if (window == viewer_window)
            viewer_draws++;
        else if (window == owner_window)
            owner_draws++;
        return 0;
    case WM_RENDERFORMAT:
        renders++;
        rendered_format = w;
        if (w == delayed_format)
            render_set = SetClipboardData(w, global_bytes(RENDERED, sizeof RENDERED)) != 0;
        return 0;
    case WM_DESTROYCLIPBOARD:
        destroys++;
        destroy_count = CountClipboardFormats();
        destroy_owner = GetClipboardOwner() == window;
        return 0;
    case WM_CHANGECBCHAIN:
        chains++;
        chain_removed = w;
        chain_next = l;
        return 1;
    case WM_RENDERALLFORMATS:
        render_alls++;
        if (OpenClipboard(window)) {
            if (GetClipboardOwner() == window)
                SetClipboardData(CF_UNICODETEXT, global_bytes(RENDERED_AT_THE_END, sizeof RENDERED_AT_THE_END));
            CloseClipboard();
        }
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

static HWND make_window(const WCHAR *title, int y)
{
    return CreateWindowExW(0, CLASS_NAME, title, WS_OVERLAPPED | WS_CAPTION | WS_VISIBLE, 300, y, 240, 80, 0, 0,
                           GetModuleHandleW(0), 0);
}

static BOOL register_class(void)
{
    WNDCLASSEXW class_info;

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = GetModuleHandleW(0);
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    return RegisterClassExW(&class_info) != 0;
}

/* Like winlogon: the logon process, WinSta0, a desktop, on it. */
static BOOL take_a_desktop(void)
{
    HWINSTA station;

    if (!RegisterLogonProcess(GetCurrentProcessId(), 1))
        return 0;
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station))
        return 0;
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    if (!desktop || !SetThreadDesktop(desktop) || !SwitchDesktop(desktop))
        return 0;
    return 1;
}

/* Step 2, another thread, while W has the clipboard open. */
static DWORD __stdcall other_thread(void *unused)
{
    BOOL opened, emptied, read;
    DWORD open_error, empty_error, read_error;

    (void)unused;
    SetThreadDesktop(desktop);
    SetLastError(0);
    opened = OpenClipboard(viewer_window);
    open_error = GetLastError();
    SetLastError(0);
    emptied = EmptyClipboard();
    empty_error = GetLastError();
    SetLastError(0);
    read = GetClipboardData(CF_UNICODETEXT) != 0;
    read_error = GetLastError();
    DbgPrint("[clip] step 2: another thread: OpenClipboard(V) %d, error %lu; EmptyClipboard %d, error %lu; "
             "GetClipboardData %d, error %lu\n",
             opened, open_error, emptied, empty_error, read, read_error);
    return 0;
}

static void step1_viewer(void)
{
    HWND next = SetClipboardViewer(viewer_window);
    HWND bad;
    DWORD error;

    pump();
    SetLastError(0);
    bad = SetClipboardViewer(BAD_WINDOW);
    error = GetLastError();
    DbgPrint("[clip] step 1: SetClipboardViewer(V): no next %d, WM_DRAWCLIPBOARD %d, viewer V %d; a bad window %d, "
             "error %lu\n",
             next == 0, viewer_draws, GetClipboardViewer() == viewer_window, bad != 0, error);
}

static void step2_closed(void)
{
    BOOL closed, set, opened;
    DWORD close_error, set_error, open_error;
    HANDLE thread;

    SetLastError(0);
    closed = CloseClipboard();
    close_error = GetLastError();
    SetLastError(0);
    set = SetClipboardData(CF_UNICODETEXT, global_bytes(TEXT_W, sizeof TEXT_W)) != 0;
    set_error = GetLastError();
    SetLastError(0);
    opened = OpenClipboard(BAD_WINDOW);
    open_error = GetLastError();
    DbgPrint("[clip] step 2: closed: CloseClipboard %d, error %lu; SetClipboardData %d, error %lu; "
             "OpenClipboard(bad) %d, error %lu\n",
             closed, close_error, set, set_error, opened, open_error);
    opened = OpenClipboard(owner_window);
    DbgPrint("[clip] step 2: OpenClipboard(W) %d, the open window W %d, again %d\n", opened,
             GetOpenClipboardWindow() == owner_window, OpenClipboard(owner_window));
    thread = CreateThread(0, 0, other_thread, 0, 0, 0);
    if (thread) {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
    CloseClipboard();
}

static void step3_write(void)
{
    DWORD before = GetClipboardSequenceNumber();
    UINT priority[3];
    WCHAR name[32];
    char list[128];
    int length, short_length, builtin;
    BOOL emptied, owner, closed;

    private_format = RegisterClipboardFormatW(L"Mino Private");
    delayed_format = RegisterClipboardFormatW(L"Mino Delayed");
    OpenClipboard(owner_window);
    emptied = EmptyClipboard();
    owner = GetClipboardOwner() == owner_window;
    SetClipboardData(CF_UNICODETEXT, global_bytes(TEXT_W, sizeof TEXT_W));
    SetClipboardData(private_format, global_bytes("MINO", 4));
    SetClipboardData(delayed_format, 0);
    DbgPrint("[clip] step 3: EmptyClipboard %d, owner W %d; open: %d formats, CF_TEXT %d\n", emptied, owner,
             CountClipboardFormats(), IsClipboardFormatAvailable(CF_TEXT));
    closed = CloseClipboard();
    pump();
    DbgPrint("[clip] step 3: CloseClipboard %d: %d formats, sequence +%lu, V's WM_DRAWCLIPBOARD %d\n", closed,
             CountClipboardFormats(), GetClipboardSequenceNumber() - before, viewer_draws);
    OpenClipboard(owner_window);
    format_list(list);
    DbgPrint("[clip] step 3: the formats:%s (end, error %lu)\n", list, GetLastError());
    CloseClipboard();
    length = GetClipboardFormatNameW(private_format, name, 32);
    short_length = GetClipboardFormatNameW(private_format, name, 5);
    builtin = GetClipboardFormatNameW(CF_TEXT, name, 32);
    DbgPrint("[clip] step 3: registered formats %d, the name %d, in 5 characters %d (then %04x), CF_TEXT's %d\n",
             private_format >= 0xC000 && delayed_format >= 0xC000 && private_format != delayed_format, length,
             short_length, name[4], builtin);
    priority[0] = CF_DIB;
    priority[1] = private_format;
    priority[2] = CF_TEXT;
    DbgPrint("[clip] step 3: GetPriorityClipboardFormat: the private one %d, none %d\n",
             GetPriorityClipboardFormat(priority, 3) == (int)private_format, GetPriorityClipboardFormat(priority, 1));
}

static void step4_reader(void)
{
    static WCHAR command_line[] = L"C:\\CLIP1.EXE reader";
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD code = 0;

    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\CLIP1.EXE", command_line, 0, 0, 0, 0, 0, 0, &startup, &process)) {
        DbgPrint("[clip] step 4: CreateProcessW: error %lu\n", GetLastError());
        return;
    }
    /* W renders and hears of the emptying while the reader runs. */
    while (MsgWaitForMultipleObjects(1, &process.hProcess, 0, INFINITE, QS_ALLINPUT) != WAIT_OBJECT_0)
        pump();
    pump();
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    DbgPrint("[clip] step 4: the reader ended (%lx); W: WM_RENDERFORMAT %d of the delayed format %d, set %d; "
             "WM_DESTROYCLIPBOARD %d, it saw %d formats and itself as the owner %d\n",
             code, renders, rendered_format == delayed_format, render_set, destroys, destroy_count, destroy_owner);
}

static void step5_after(void)
{
    HANDLE text;
    char list[128];

    DbgPrint("[clip] step 5: V's WM_DRAWCLIPBOARD %d; open window none %d, owner none %d, %d formats\n",
             viewer_draws, GetOpenClipboardWindow() == 0, GetClipboardOwner() == 0, CountClipboardFormats());
    if (!OpenClipboard(owner_window)) {
        DbgPrint("[clip] step 5: OpenClipboard: error %lu\n", GetLastError());
        return;
    }
    text = GetClipboardData(CF_UNICODETEXT);
    DbgPrint("[clip] step 5: the reader's text as CF_UNICODETEXT %d; the formats:%s\n",
             same_bytes(text, FROM_THE_READER_W, sizeof FROM_THE_READER_W), format_list(list));
    CloseClipboard();
}

static void step6_chain(void)
{
    HWND next;
    BOOL changed, head;
    DWORD error;

    next = SetClipboardViewer(owner_window);
    pump();
    changed = ChangeClipboardChain(viewer_window, 0);
    DbgPrint("[clip] step 6: SetClipboardViewer(W) gives V %d, W's WM_DRAWCLIPBOARD %d; ChangeClipboardChain(V, 0) "
             "%d: W's WM_CHANGECBCHAIN %d (V %d, none %d), viewer W %d\n",
             next == viewer_window, owner_draws, changed, chains, chain_removed == (WPARAM)viewer_window,
             chain_next == 0, GetClipboardViewer() == owner_window);
    head = ChangeClipboardChain(owner_window, 0);
    SetLastError(0);
    changed = ChangeClipboardChain(BAD_WINDOW, 0);
    error = GetLastError();
    DbgPrint("[clip] step 6: the head leaves %d, WM_CHANGECBCHAIN %d, no viewer %d; a bad window %d, error %lu\n",
             head, chains, GetClipboardViewer() == 0, changed, error);
}

static void step7_destroyed_owner(void)
{
    HWND window = make_window(L"W2", 400);
    DWORD before;
    BOOL destroyed;

    OpenClipboard(window);
    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, 0);
    SetClipboardData(delayed_format, 0);
    CloseClipboard();
    before = GetClipboardSequenceNumber();
    destroyed = DestroyWindow(window);
    DbgPrint("[clip] step 7: DestroyWindow(W2) %d: WM_RENDERALLFORMATS %d; owner none %d, the text %d, the other "
             "delayed format %d, sequence +%lu\n",
             destroyed, render_alls, GetClipboardOwner() == 0, IsClipboardFormatAvailable(CF_UNICODETEXT),
             IsClipboardFormatAvailable(delayed_format), GetClipboardSequenceNumber() - before);
    if (OpenClipboard(owner_window)) {
        DbgPrint("[clip] step 7: CF_TEXT from what it rendered %d\n",
                 same_bytes(GetClipboardData(CF_TEXT), "rendered at the end", 20));
        CloseClipboard();
    }
}

/* The reader, another process. */
static void reader(void)
{
    HANDLE data;
    DWORD before, owner_process = 0;
    HWND owner;
    UINT private_again = RegisterClipboardFormatW(L"Mino Private");
    UINT delayed_again = RegisterClipboardFormatW(L"Mino Delayed");
    const DWORD *locale;

    /* Refused, closed: the block it gave the kernel goes with the process. */
    SetClipboardData(CF_TEXT, global_bytes("lost", 5));
    if (!OpenClipboard(0)) {
        DbgPrint("[clip] reader: OpenClipboard: error %lu\n", GetLastError());
        ExitProcess(1);
    }
    before = GetClipboardSequenceNumber();
    data = GetClipboardData(CF_UNICODETEXT);
    DbgPrint("[clip] reader: CF_UNICODETEXT %d\n", same_bytes(data, TEXT_W, sizeof TEXT_W));
    data = GetClipboardData(CF_TEXT);
    DbgPrint("[clip] reader: CF_TEXT %d, its last byte %02x\n", same_bytes(data, TEXT_ANSI, sizeof TEXT_ANSI),
             byte_at(data, ansi_length(TEXT_ANSI) - 1));
    data = GetClipboardData(CF_OEMTEXT);
    DbgPrint("[clip] reader: CF_OEMTEXT, its last byte %02x\n", byte_at(data, ansi_length(TEXT_ANSI) - 1));
    data = GetClipboardData(CF_LOCALE);
    locale = data ? GlobalLock(data) : 0;
    DbgPrint("[clip] reader: CF_LOCALE %08lx (%lu bytes), GetThreadLocale %08lx\n", locale ? *locale : 0,
             data ? GlobalSize(data) : 0, GetThreadLocale());
    if (locale)
        GlobalUnlock(data);
    data = GetClipboardData(private_again);
    DbgPrint("[clip] reader: the private format, by its name: %d (%lu bytes)\n", same_bytes(data, "MINO", 4),
             data ? GlobalSize(data) : 0);
    data = GetClipboardData(delayed_again);
    DbgPrint("[clip] reader: the delayed format, rendered by its owner: %d\n",
             same_bytes(data, RENDERED, sizeof RENDERED));
    owner = GetClipboardOwner();
    GetWindowThreadProcessId(owner, &owner_process);
    DbgPrint("[clip] reader: the owner is another process's window %d, sequence unchanged %d\n",
             owner != 0 && owner_process != GetCurrentProcessId(), GetClipboardSequenceNumber() == before);
    DbgPrint("[clip] reader: CloseClipboard %d\n", CloseClipboard());
    OpenClipboard(0);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, global_bytes(FROM_THE_READER, sizeof FROM_THE_READER));
    DbgPrint("[clip] reader: emptied, ends with the clipboard open\n");
    ExitProcess(EXIT_STATUS);
}

/* The reader's command line ends with "reader". */
static int is_reader(void)
{
    const WCHAR *line = GetCommandLineW();
    DWORD length = wide_length(line);
    static const WCHAR WORD_READER[] = L"reader";
    DWORD i;

    if (length < 6)
        return 0;
    for (i = 0; i < 6; i++)
        if (line[length - 6 + i] != WORD_READER[i])
            return 0;
    return 1;
}

DWORD __stdcall GuiStartup(void)
{
    if (is_reader())
        reader();
    if (!take_a_desktop())
        ExitProcess(1);
    if (!register_class())
        ExitProcess(2);
    owner_window = make_window(L"W", 100);
    viewer_window = make_window(L"V", 250);
    if (!owner_window || !viewer_window)
        ExitProcess(3);
    pump();
    DbgPrint("[clip] GetThreadLocale %08lx\n", GetThreadLocale());
    step1_viewer();
    step2_closed();
    step3_write();
    step4_reader();
    step5_after();
    step6_chain();
    step7_destroyed_owner();
    DbgPrint("[clip] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
