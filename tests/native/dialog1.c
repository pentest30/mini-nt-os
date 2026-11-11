/*
 * A dialog from a template: a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32 and user32, which the
 * scenario `dialog` puts on the boot disk in the place of winlogon.exe.
 * Unlike the other programs, it takes no desktop itself: like taskmgr as
 * the session shell, its first window gets WinSta0\Default from the
 * kernel, which also gives that desktop the screen.
 *
 * It builds a dialog template in memory (DS_SETFONT "MS Shell Dlg" 8,
 * centred, a static text and an OK button) and creates it with
 * CreateDialogIndirectParam, as taskmgr creates its main dialog and its
 * pages. user32 gives the dialog its DIALOGINFO through SetDialogPointer
 * and reads it back from the WND: without it, CreateDialog destroys the
 * dialog it has just made. Then:
 * - WM_INITDIALOG with the creation parameter, and its controls, in the
 *   template's order (GetWindow, GetDlgCtrlID);
 * - GetWindowLong(DWL_DLGPROC) comes from the DIALOGINFO, DWL_USER from the
 *   extra bytes;
 * - painted, centred on the desktop: its frame, its caption, its
 *   background (WM_CTLCOLORDLG), the static text, and the OK button with
 *   its label centred (DrawState and the viewport origin).
 * It ends with EXIT_STATUS. Each result goes to the debug port (DbgPrint),
 * where the scenario looks for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short WORD;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HWND;
typedef void *HINSTANCE;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef BOOL(__stdcall *DLGPROC)(HWND, UINT, WPARAM, LPARAM);

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

#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WS_CAPTION 0x00C00000
#define WS_SYSMENU 0x00080000
#define WS_TABSTOP 0x00010000
#define WS_DISABLED 0x08000000
#define DS_SETFONT 0x0040
#define DS_MODALFRAME 0x0080
#define DS_CENTER 0x0800
#define BS_DEFPUSHBUTTON 0x0001
#define WM_INITDIALOG 0x0110
#define PM_REMOVE 0x0001
#define DWL_DLGPROC 4
#define DWL_USER 8
#define GW_HWNDNEXT 2
#define GW_CHILD 5
#define IDOK 1
#define ID_TEXT 100
#define ID_DISABLED 101
#define EXIT_STATUS 0x7004

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) HWND __stdcall CreateDialogIndirectParamW(HINSTANCE instance, const void *dialog_template,
                                                                HWND parent, DLGPROC procedure, LPARAM param);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) int __stdcall GetDlgCtrlID(HWND window);
__declspec(dllimport) HWND __stdcall GetWindow(HWND window, UINT relation);
__declspec(dllimport) LONG __stdcall GetWindowLongW(HWND window, int index);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) LONG __stdcall SetWindowLongW(HWND window, int index, LONG value);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

/* The template, DWORD-aligned as CreateDialogIndirect wants it. */
static DWORD template_words[128];

/* Appends `value` at `*at`. */
static void word(WORD **at, WORD value)
{
    *(*at)++ = value;
}

static void dword(WORD **at, DWORD value)
{
    word(at, (WORD)(value & 0xFFFF));
    word(at, (WORD)(value >> 16));
}

static void string(WORD **at, const WCHAR *text)
{
    do
        word(at, *text);
    while (*text++);
}

/* The next DWORD boundary, where a DLGITEMTEMPLATE begins. */
static void align(WORD **at)
{
    if ((unsigned long)*at & 2)
        word(at, 0);
}

/* A control of a predefined class (0x0080 button, 0x0082 static). */
static void item(WORD **at, DWORD style, short x, short y, short cx, short cy, WORD id, WORD class_atom,
                 const WCHAR *text)
{
    align(at);
    dword(at, style);
    dword(at, 0);
    word(at, (WORD)x);
    word(at, (WORD)y);
    word(at, (WORD)cx);
    word(at, (WORD)cy);
    word(at, id);
    word(at, 0xFFFF);
    word(at, class_atom);
    string(at, text);
    word(at, 0); /* no creation data */
}

static const void *build_template(void)
{
    WORD *at = (WORD *)template_words;

    /* DLGTEMPLATE */
    dword(&at, WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | DS_SETFONT | DS_MODALFRAME | DS_CENTER);
    dword(&at, 0);
    word(&at, 3);
    word(&at, 0);
    word(&at, 0);
    word(&at, 200);
    word(&at, 100);
    word(&at, 0); /* no menu */
    word(&at, 0); /* the dialog class */
    string(&at, L"Mino dialog");
    word(&at, 8);
    string(&at, L"MS Shell Dlg");
    item(&at, WS_CHILD | WS_VISIBLE, 10, 10, 120, 10, ID_TEXT, 0x0082, L"A dialog from a template");
    item(&at, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 140, 76, 50, 14, IDOK, 0x0080, L"OK");
    /* Disabled, its text grayed by DrawState in a font made from GetObject
       of the DC's (Task Manager's Switch To). */
    item(&at, WS_CHILD | WS_VISIBLE | WS_DISABLED, 75, 76, 60, 14, ID_DISABLED, 0x0080, L"&Switch To");
    return template_words;
}

static BOOL __stdcall procedure(HWND dialog, UINT message, WPARAM w, LPARAM l)
{
    (void)w;
    if (message == WM_INITDIALOG) {
        HWND first = GetWindow(dialog, GW_CHILD);
        HWND second = first ? GetWindow(first, GW_HWNDNEXT) : 0;
        DbgPrint("[dialog] WM_INITDIALOG, parameter %lx; controls %d and %d\n", l, first ? GetDlgCtrlID(first) : -1,
                 second ? GetDlgCtrlID(second) : -1);
        return 1;
    }
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    HWND dialog;
    MSG message;
    int i;

    dialog = CreateDialogIndirectParamW(GetModuleHandleW(0), build_template(), 0, procedure, 0x1234);
    DbgPrint("[dialog] created %d\n", dialog != 0);
    if (!dialog)
        ExitProcess(1);
    SetWindowLongW(dialog, DWL_USER, 0x5678);
    DbgPrint("[dialog] DWL_DLGPROC is the procedure %d, DWL_USER %lx\n",
             GetWindowLongW(dialog, DWL_DLGPROC) == (LONG)procedure, GetWindowLongW(dialog, DWL_USER));
    for (i = 0; i < 75; i++) {
        while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        Sleep(20);
    }
    DbgPrint("[dialog] painted\n");
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
