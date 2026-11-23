/*
 * The system controls seen from an ANSI program: a Win32 program (subsystem
 * WINDOWS), compiled with MinGW and linked to ReactOS's kernel32 and user32,
 * which the scenario `ansi-controls` puts on the boot disk in the place of
 * winlogon.exe. Inno Setup 5.4 (Delphi, ANSI) died on them: Delphi's VCL
 * makes its TEdit a class of its own over Edit (CreateSubClass: GetClassInfoA
 * of "Edit", then CallWindowProcA of the procedure it got), and win32k gave
 * the class's Unicode procedure (EditWndProcW) to the ANSI caller. The
 * control then read its ANSI text as UTF-16, and its WM_GETTEXT wrote two
 * bytes per character into the ANSI buffer of the Delphi heap. ReactOS
 * (IntGetClassWndProc) gives a control's client procedure of the asked
 * character set. The program takes a desktop like winlogon, shows a popup,
 * then:
 * 1. GetClassInfoA and GetClassInfoW of each control class of user32
 *    (Button, ComboBox, Edit, ListBox, Static): the procedure of each set,
 *    the one user32 itself gives for a window of the class (GetClassLongA,
 *    GetClassLongW of GCL_WNDPROC, IntGetClsWndProc), and the two differ;
 * 2. Delphi's way: a class "MinoEditA" made from what GetClassInfoA gave
 *    for Edit, whose procedure passes every message to it by
 *    CallWindowProcA; its window created with an ANSI text, which reads back
 *    whole (GetWindowTextLengthA, GetWindowTextA), and a short buffer gets
 *    its start and nothing past it;
 * 3. a plain Edit created in ANSI (CreateWindowExA) keeps its ANSI text;
 * 4. what Inno Setup 5.4 asks for: its manifest makes "Edit" comctl32 6's,
 *    a Unicode class without a FNID. GetClassInfoA of such a class (here
 *    "MinoWide", registered in Unicode) gives a call procedure (CALLPROCDATA:
 *    its high word 0xFFFF), the same one each time; CallWindowProcA of it
 *    hands the Unicode procedure its text in UTF-16, and its WM_GETTEXT fills
 *    a short ANSI buffer and nothing past it; a window of that class
 *    created in ANSI stays a Unicode window (only the system controls become
 *    ANSI windows for an ANSI creator);
 * 5. GetWindowLongA of the Unicode window is a call procedure too (user32
 *    asks NtUserGetCPD); subclassed in ANSI (SetWindowLongA), its old
 *    procedure is that call procedure, the messages reach the Unicode
 *    procedure through it, and given back it is the Unicode procedure again;
 *    SetWindowLongA that gives it back returns the ANSI subclass itself (the
 *    old procedure seen in the caller's set, not in the call procedure's);
 * 6. the other way: GetClassInfoW of an ANSI class is a call procedure, and
 *    CallWindowProcW of it hands the ANSI procedure its text in ANSI;
 * 7. a call procedure is its process's and its desktop's: a thread of this
 *    process on another desktop gets one of its own from GetClassInfoA of
 *    the Unicode class, which CallWindowProcA converts (the one of step 4 is
 *    in the heap of Default, not mapped there); a second process (this
 *    program, "child") gets one of its own from GetClassLongA of this
 *    program's Unicode window, not this program's (user32's
 *    ValidateCallProc refuses another process's), and this program's still
 *    works after the child's end.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned short ATOM;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HWINSTA;
typedef void *HDESK;
typedef void *HANDLE;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct {
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HICON hCursor;
    HBRUSH hbrBackground;
    const char *lpszMenuName;
    const char *lpszClassName;
} WNDCLASSA;

typedef struct {
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
} WNDCLASSW;

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

#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define GCL_WNDPROC (-24)
#define MAXIMUM_ALLOWED 0x02000000
#define COLOR_WINDOW 5
#define WM_GETTEXT 0x000D
#define WM_SETTEXT 0x000C
#define GWLP_WNDPROC (-4)
#define INFINITE 0xFFFFFFFF
#define CHILD_PASSED 0x77

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE object);
__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line,
                                                    void *process_attributes, void *thread_attributes, BOOL inherit,
                                                    DWORD flags, void *environment, const WCHAR *directory,
                                                    STARTUPINFOW *startup, PROCESS_INFORMATION *information);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, DWORD(__stdcall *start)(void *),
                                                    void *parameter, DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) WCHAR *__stdcall GetCommandLineW(void);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) BOOL __stdcall GetExitCodeProcess(HANDLE process, DWORD *code);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE object, DWORD milliseconds);

__declspec(dllimport) LRESULT __stdcall CallWindowProcA(WNDPROC procedure, HWND window, UINT message, WPARAM w,
                                                       LPARAM l);
__declspec(dllimport) LRESULT __stdcall CallWindowProcW(WNDPROC procedure, HWND window, UINT message, WPARAM w,
                                                       LPARAM l);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExA(DWORD ex_style, const char *class_name, const char *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcA(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall GetClassInfoA(HINSTANCE instance, const char *name, WNDCLASSA *info);
__declspec(dllimport) BOOL __stdcall GetClassInfoW(HINSTANCE instance, const WCHAR *name, WNDCLASSW *info);
__declspec(dllimport) DWORD __stdcall GetClassLongA(HWND window, int index);
__declspec(dllimport) DWORD __stdcall GetClassLongW(HWND window, int index);
__declspec(dllimport) LONG __stdcall GetWindowLongA(HWND window, int index);
__declspec(dllimport) LONG __stdcall GetWindowLongW(HWND window, int index);
__declspec(dllimport) int __stdcall GetWindowTextA(HWND window, char *text, int count);
__declspec(dllimport) int __stdcall GetWindowTextLengthA(HWND window);
__declspec(dllimport) ATOM __stdcall RegisterClassA(const WNDCLASSA *info);
__declspec(dllimport) ATOM __stdcall RegisterClassW(const WNDCLASSW *info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) LRESULT __stdcall SendMessageA(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) LONG __stdcall SetWindowLongA(HWND window, int index, LONG value);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

static int same(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
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
    return 1;
}

/* What GetClassInfoA gave for Edit: the procedure Delphi calls. */
static WNDPROC edit_procedure;

/* Delphi's TWinControl.DefaultHandler: every message to the class's
 * procedure, by CallWindowProcA. */
static LRESULT __stdcall subclassed_edit(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    return CallWindowProcA(edit_procedure, hwnd, message, w, l);
}

static LRESULT __stdcall parent_procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    return DefWindowProcA(hwnd, message, w, l);
}

static int same_wide(const WCHAR *a, const WCHAR *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

/* The last WM_SETTEXT of the Unicode procedure, and of the ANSI one. */
static WCHAR wide_text[64];
static char narrow_text[64];

static LRESULT __stdcall wide_procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_SETTEXT && l) {
        const WCHAR *text = (const WCHAR *)l;
        int i;
        for (i = 0; i < 63 && text[i]; i++)
            wide_text[i] = text[i];
        wide_text[i] = 0;
    }
    return DefWindowProcW(hwnd, message, w, l);
}

static LRESULT __stdcall narrow_procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_SETTEXT && l) {
        const char *text = (const char *)l;
        int i;
        for (i = 0; i < 63 && text[i]; i++)
            narrow_text[i] = text[i];
        narrow_text[i] = 0;
    }
    return DefWindowProcA(hwnd, message, w, l);
}

/* What SetWindowLongA gave back: the procedure the subclass passes on to. */
static WNDPROC subclassed_previous;
static int subclass_seen;

static LRESULT __stdcall ansi_subclass(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    subclass_seen += message == WM_SETTEXT;
    return CallWindowProcA(subclassed_previous, hwnd, message, w, l);
}

static int is_call_procedure(WNDPROC procedure)
{
    return ((DWORD)procedure & 0xFFFF0000) == 0xFFFF0000;
}

static const char path[] = "C:\\Program Files\\PeaZip";

/* The command line of step 7's child: "C:\ANSICTL1.EXE child HWND CPD",
 * both in eight hexadecimal digits. */
static WCHAR child_line[] = L"C:\\ANSICTL1.EXE child 00000000 00000000";
#define CHILD_WINDOW_AT 22
#define CHILD_CPD_AT 31

static void put_hex(WCHAR *out, DWORD value)
{
    int i;
    for (i = 0; i < 8; i++)
        out[i] = L"0123456789abcdef"[(value >> (28 - 4 * i)) & 15];
}

static DWORD get_hex(const WCHAR *in)
{
    DWORD value = 0;
    int i;
    for (i = 0; i < 8; i++)
        value = value * 16 + (in[i] <= L'9' ? in[i] - L'0' : in[i] - L'a' + 10);
    return value;
}

/* The child's command line holds " child " after the program's path. */
static const WCHAR *child_arguments(void)
{
    const WCHAR *line = GetCommandLineW();
    static const WCHAR WORD_CHILD[] = L" child ";
    for (; *line; line++) {
        int i;
        for (i = 0; WORD_CHILD[i] && line[i] == WORD_CHILD[i]; i++)
            ;
        if (!WORD_CHILD[i])
            return line + 7;
    }
    return 0;
}

/* Step 7's child: GetClassLongA of the parent's Unicode window gives a call
 * procedure of its own, which CallWindowProcA converts (the procedure is the
 * same program's, at the same address here). */
static void child(const WCHAR *arguments)
{
    HWND window = (HWND)get_hex(arguments);
    WNDPROC parents = (WNDPROC)get_hex(arguments + 9);
    WNDPROC got = (WNDPROC)GetClassLongA(window, GCL_WNDPROC);
    int converts;

    wide_text[0] = 0;
    CallWindowProcA(got, 0, WM_SETTEXT, 0, (LPARAM) "from the child");
    converts = same_wide(wide_text, L"from the child");
    DbgPrint("[ansictl] child: GetClassLongA of the parent's window: a call procedure %d, not the parent's %d, it "
             "converts %d\n",
             is_call_procedure(got), got != parents, converts);
    ExitProcess(is_call_procedure(got) && got != parents && converts ? CHILD_PASSED : 1);
}

/* Step 7's thread on another desktop. */
static HDESK other_desktop;
static HINSTANCE the_instance;
static int on_other_desktop = -1;

static DWORD __stdcall another_desktop(void *parameter)
{
    WNDCLASSA seen;
    (void)parameter;
    if (!SetThreadDesktop(other_desktop)) {
        on_other_desktop = -2;
        return 0;
    }
    memset(&seen, 0, sizeof seen);
    wide_text[0] = 0;
    if (!GetClassInfoA(the_instance, "MinoWide", &seen)) {
        on_other_desktop = -3;
        return 0;
    }
    CallWindowProcA(seen.lpfnWndProc, 0, WM_SETTEXT, 0, (LPARAM) "on another desktop");
    on_other_desktop = is_call_procedure(seen.lpfnWndProc) && same_wide(wide_text, L"on another desktop");
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    static const char *const names_a[] = {"Button", "ComboBox", "Edit", "ListBox", "Static"};
    static const WCHAR *const names_w[] = {L"Button", L"ComboBox", L"Edit", L"ListBox", L"Static"};
    HINSTANCE instance = GetModuleHandleW(0);
    WNDCLASSA class_a, edit_class;
    WNDCLASSW class_w;
    HWND parent, window, plain;
    char text[64];
    int i, ansi_seen = 0, unicode_seen = 0, differ = 0, length, got, untouched, whole, plain_length;
    const WCHAR *arguments = child_arguments();

    if (arguments)
        child(arguments);
    the_instance = instance;
    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_a, 0, sizeof class_a);
    class_a.lpfnWndProc = parent_procedure;
    class_a.hInstance = instance;
    class_a.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_a.lpszClassName = "MinoAnsiParent";
    if (!RegisterClassA(&class_a))
        ExitProcess(2);
    parent = CreateWindowExA(0, "MinoAnsiParent", "P", WS_POPUP | WS_VISIBLE, 100, 100, 300, 200, 0, 0, instance, 0);
    DbgPrint("[ansictl] ready: the parent %d\n", parent != 0);
    if (!parent)
        ExitProcess(3);

    /* 1. Each control class, asked in each character set. */
    for (i = 0; i < 5; i++) {
        HWND control_a = CreateWindowExA(0, names_a[i], "", WS_CHILD, 0, 0, 50, 20, parent, 0, instance, 0);
        HWND control_w = CreateWindowExW(0, names_w[i], L"", WS_CHILD, 0, 0, 50, 20, parent, 0, instance, 0);
        memset(&class_a, 0, sizeof class_a);
        memset(&class_w, 0, sizeof class_w);
        if (control_a && control_w && GetClassInfoA(0, names_a[i], &class_a) &&
            GetClassInfoW(0, names_w[i], &class_w)) {
            DWORD user32_a = GetClassLongA(control_a, GCL_WNDPROC);
            DWORD user32_w = GetClassLongW(control_w, GCL_WNDPROC);
            ansi_seen += (DWORD)class_a.lpfnWndProc == user32_a;
            unicode_seen += (DWORD)class_w.lpfnWndProc == user32_w;
            differ += class_a.lpfnWndProc != class_w.lpfnWndProc;
            if ((DWORD)class_a.lpfnWndProc != user32_a || (DWORD)class_w.lpfnWndProc != user32_w)
                DbgPrint("[ansictl] %s: GetClassInfoA %p (user32 %lx), GetClassInfoW %p (user32 %lx)\n", names_a[i],
                         class_a.lpfnWndProc, user32_a, class_w.lpfnWndProc, user32_w);
        }
    }
    DbgPrint("[ansictl] step 1: GetClassInfoA gives the ANSI procedure of %d controls of 5, GetClassInfoW the "
             "Unicode one of %d, the two differ for %d\n",
             ansi_seen, unicode_seen, differ);

    /* 2. Delphi's TEdit: a class of its own over what GetClassInfoA gave. */
    memset(&edit_class, 0, sizeof edit_class);
    if (!GetClassInfoA(0, "Edit", &edit_class))
        ExitProcess(4);
    edit_procedure = edit_class.lpfnWndProc;
    edit_class.lpfnWndProc = subclassed_edit;
    edit_class.hInstance = instance;
    edit_class.lpszClassName = "MinoEditA";
    if (!RegisterClassA(&edit_class))
        ExitProcess(5);
    window = CreateWindowExA(0, "MinoEditA", path, WS_CHILD | WS_VISIBLE, 10, 10, 200, 20, parent, 0, instance, 0);
    if (!window)
        ExitProcess(6);
    length = GetWindowTextLengthA(window);
    memset(text, 0x5A, sizeof text);
    got = GetWindowTextA(window, text, 8);
    untouched = 1;
    for (i = 8; i < (int)sizeof text; i++)
        untouched &= text[i] == 0x5A;
    DbgPrint("[ansictl] step 2: a class over Edit: length %d, GetWindowTextA(8) %d \"%s\", the bytes past it "
             "untouched %d\n",
             length, got, got == 7 && text[7] == 0 ? text : "?", untouched);
    memset(text, 0x5A, sizeof text);
    got = (int)SendMessageA(window, WM_GETTEXT, sizeof text, (LPARAM)text);
    whole = got == length && same(text, path);
    DbgPrint("[ansictl] step 2: WM_GETTEXT %d, the whole text %d\n", got, whole);

    /* 3. A plain Edit created in ANSI. */
    plain = CreateWindowExA(0, "Edit", path, WS_CHILD | WS_VISIBLE, 10, 40, 200, 20, parent, 0, instance, 0);
    memset(text, 0x5A, sizeof text);
    plain_length = plain ? GetWindowTextA(plain, text, sizeof text) : -1;
    DbgPrint("[ansictl] step 3: an Edit created in ANSI: GetWindowTextA %d, the whole text %d\n", plain_length,
             plain_length == length && same(text, path));

    /* 4. A Unicode class without a FNID, asked in ANSI. */
    {
        WNDCLASSW wide_class;
        WNDCLASSA seen, again;
        HWND wide;
        WNDPROC cpd;
        int text_ok, got, untouched_4 = 1;

        memset(&wide_class, 0, sizeof wide_class);
        wide_class.lpfnWndProc = wide_procedure;
        wide_class.hInstance = instance;
        wide_class.lpszClassName = L"MinoWide";
        memset(&seen, 0, sizeof seen);
        memset(&again, 0, sizeof again);
        if (!RegisterClassW(&wide_class) || !GetClassInfoA(instance, "MinoWide", &seen) ||
            !GetClassInfoA(instance, "MinoWide", &again))
            ExitProcess(7);
        cpd = seen.lpfnWndProc;
        DbgPrint("[ansictl] step 4: GetClassInfoA of a Unicode class: a call procedure %d (not the procedure %d), "
                 "the same again %d\n",
                 is_call_procedure(cpd), cpd != wide_procedure, again.lpfnWndProc == cpd);
        wide = CreateWindowExW(0, L"MinoWide", L"", WS_CHILD, 0, 70, 50, 20, parent, 0, instance, 0);
        if (!wide)
            ExitProcess(8);
        CallWindowProcA(cpd, wide, WM_SETTEXT, 0, (LPARAM) "ansi text");
        text_ok = same_wide(wide_text, L"ansi text");
        memset(text, 0x5A, sizeof text);
        got = (int)CallWindowProcA(cpd, wide, WM_GETTEXT, 8, (LPARAM)text);
        for (i = 8; i < (int)sizeof text; i++)
            untouched_4 &= text[i] == 0x5A;
        DbgPrint("[ansictl] step 4: CallWindowProcA: the Unicode procedure gets the text %d; WM_GETTEXT(8) %d "
                 "\"%s\", the bytes past it untouched %d\n",
                 text_ok, got, got == 7 && text[7] == 0 ? text : "?", untouched_4);
        {
            HWND made_in_ansi = CreateWindowExA(0, "MinoWide", "", WS_CHILD, 60, 70, 50, 20, parent, 0, instance, 0);
            wide_text[0] = 0;
            if (made_in_ansi)
                SendMessageA(made_in_ansi, WM_SETTEXT, 0, (LPARAM) "made in ansi");
            DbgPrint("[ansictl] step 4: a window of it created in ANSI stays Unicode: its procedure gets the text "
                     "%d\n",
                     made_in_ansi && same_wide(wide_text, L"made in ansi"));
        }

        /* 5. The window's procedure in ANSI, subclassed and given back. */
        {
            WNDPROC window_cpd = (WNDPROC)GetWindowLongA(wide, GWLP_WNDPROC);
            WNDPROC old = (WNDPROC)SetWindowLongA(wide, GWLP_WNDPROC, (LONG)ansi_subclass), given_back;
            int through, back;
            subclassed_previous = old;
            wide_text[0] = 0;
            SendMessageA(wide, WM_SETTEXT, 0, (LPARAM) "via the subclass");
            through = subclass_seen == 1 && same_wide(wide_text, L"via the subclass");
            given_back = (WNDPROC)SetWindowLongA(wide, GWLP_WNDPROC, (LONG)old);
            back = (WNDPROC)GetWindowLongW(wide, GWLP_WNDPROC) == wide_procedure;
            DbgPrint("[ansictl] step 5: GetWindowLongA a call procedure %d, SetWindowLongA gave it back %d, the "
                     "Unicode procedure gets the text through the subclass %d; given back, GetWindowLongW the "
                     "procedure %d\n",
                     is_call_procedure(window_cpd), old == window_cpd, through, back);
            DbgPrint("[ansictl] step 5: SetWindowLongA that gave it back returned the ANSI subclass %d\n",
                     given_back == ansi_subclass);
        }

        /* 7. A call procedure of another desktop, of another process. */
        {
            HANDLE thread;
            STARTUPINFOW startup;
            PROCESS_INFORMATION process;
            DWORD code = 0;
            WNDPROC mine = (WNDPROC)GetClassLongA(wide, GCL_WNDPROC), again;
            int still;

            other_desktop = CreateDesktopW(L"MinoOther", 0, 0, 0, MAXIMUM_ALLOWED, 0);
            thread = other_desktop ? CreateThread(0, 0, another_desktop, 0, 0, 0) : 0;
            if (thread) {
                WaitForSingleObject(thread, INFINITE);
                CloseHandle(thread);
            }
            DbgPrint("[ansictl] step 7: a thread on another desktop: its own call procedure converts %d\n",
                     on_other_desktop);

            put_hex(child_line + CHILD_WINDOW_AT, (DWORD)wide);
            put_hex(child_line + CHILD_CPD_AT, (DWORD)mine);
            memset(&startup, 0, sizeof startup);
            startup.cb = sizeof startup;
            startup.lpDesktop = L"WinSta0\\Default";
            if (CreateProcessW(L"C:\\ANSICTL1.EXE", child_line, 0, 0, 0, 0, 0, 0, &startup, &process)) {
                WaitForSingleObject(process.hProcess, INFINITE);
                GetExitCodeProcess(process.hProcess, &code);
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
            }
            wide_text[0] = 0;
            CallWindowProcA(mine, wide, WM_SETTEXT, 0, (LPARAM) "still mine");
            still = same_wide(wide_text, L"still mine");
            again = (WNDPROC)GetClassLongA(wide, GCL_WNDPROC);
            DbgPrint("[ansictl] step 7: another process: its own call procedure %d; after its end, this one's "
                     "converts %d, the same again %d\n",
                     code == CHILD_PASSED, still, again == mine);
        }
    }

    /* 6. An ANSI class asked in Unicode. */
    {
        WNDCLASSA narrow_class;
        WNDCLASSW seen_w;
        HWND narrow;
        WNDPROC cpd;

        memset(&narrow_class, 0, sizeof narrow_class);
        narrow_class.lpfnWndProc = narrow_procedure;
        narrow_class.hInstance = instance;
        narrow_class.lpszClassName = "MinoNarrow";
        memset(&seen_w, 0, sizeof seen_w);
        if (!RegisterClassA(&narrow_class) || !GetClassInfoW(instance, L"MinoNarrow", &seen_w))
            ExitProcess(9);
        cpd = seen_w.lpfnWndProc;
        narrow = CreateWindowExA(0, "MinoNarrow", "", WS_CHILD, 0, 100, 50, 20, parent, 0, instance, 0);
        if (!narrow)
            ExitProcess(10);
        CallWindowProcW(cpd, narrow, WM_SETTEXT, 0, (LPARAM)L"wide text");
        DbgPrint("[ansictl] step 6: GetClassInfoW of an ANSI class: a call procedure %d; CallWindowProcW: the ANSI "
                 "procedure gets the text %d\n",
                 is_call_procedure(cpd), same(narrow_text, "wide text"));
    }
    DbgPrint("[ansictl] done\n");
    ExitProcess(0);
    return 0;
}
