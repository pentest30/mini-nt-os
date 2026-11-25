/*
 * The welcome page of an MSI as msi.dll builds it (dll/win32/msi/dialog.c,
 * the 7-Zip 9.20 MSI made with WiX): a Win32 program (subsystem WINDOWS),
 * compiled with MinGW and linked to ReactOS's kernel32, user32 and gdi32,
 * which the scenario `msi-dialog-text` puts on the boot disk in the place of
 * winlogon.exe. In VirtualBox, the page showed nothing but its buttons.
 * Like msi.dll: a dialog window whose procedure sends WM_CTLCOLORSTATIC back
 * to the control; its controls in the order of the Control table: the title
 * and the description, Static controls made WS_EX_TRANSPARENT afterwards
 * (SetWindowLongPtr) and subclassed to answer WM_CTLCOLORSTATIC with
 * TRANSPARENT and NULL_BRUSH, the Cancel button, then the Bitmap control, an
 * SS_BITMAP Static over the whole top of the page, without its picture (the
 * MSI has none: "Failed to load bitmap WixUI_Bmp_Dialog"), Back and Next;
 * then dialog_set_tab_order puts Next, Cancel, the picture and Back on top
 * of the Z order: the picture's Static goes above the two texts. The Static
 * class has CS_PARENTDC: the texts paint in a DC that sees what the dialog
 * sees, not cut by the picture above them (DceUpdateVisRgn); Mino cut their
 * DC by their siblings above, and the texts drew nothing.
 * The dialog shown, its messages pumped, the screen is read back where the
 * two texts are: their dark pixels, and the gray of the page around them.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned short WORD;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HWND;
typedef void *HDC;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HBITMAP;
typedef void *HGDIOBJ;
typedef void *HWINSTA;
typedef void *HDESK;
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
    const WCHAR *lpszMenuName;
    const WCHAR *lpszClassName;
} WNDCLASSW;

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
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;

typedef struct {
    DWORD biSize;
    LONG biWidth;
    LONG biHeight;
    WORD biPlanes;
    WORD biBitCount;
    DWORD biCompression;
    DWORD biSizeImage;
    LONG biXPelsPerMeter;
    LONG biYPelsPerMeter;
    DWORD biClrUsed;
    DWORD biClrImportant;
} BITMAPINFOHEADER;

#define WS_OVERLAPPED 0x00000000
#define WS_SYSMENU 0x00080000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WS_GROUP 0x00020000
#define WS_TABSTOP 0x00010000
#define WS_EX_TRANSPARENT 0x00000020
#define SS_LEFT 0x00000000
#define SS_BITMAP 0x0000000E
#define BS_PUSHBUTTON 0x00000000
#define SW_SHOW 5
/* dialog_set_tab_order: SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOREDRAW |
   SWP_NOREPOSITION | SWP_NOSENDCHANGING | SWP_NOSIZE. */
#define SWP_TABORDER 0x060B
#define GWL_EXSTYLE (-20)
#define GWLP_WNDPROC (-4)
#define WM_CTLCOLORSTATIC 0x0138
#define TRANSPARENT 1
#define NULL_BRUSH 5
#define COLOR_3DFACE 15
#define PM_REMOVE 0x0001
#define SRCCOPY 0x00CC0020
#define MAXIMUM_ALLOWED 0x02000000

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) LRESULT __stdcall CallWindowProcW(WNDPROC procedure, HWND window, UINT message, WPARAM w,
                                                       LPARAM l);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) DWORD __stdcall GetSysColor(int index);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassW(const WNDCLASSW *info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC dc);
__declspec(dllimport) LRESULT __stdcall SendMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) LONG __stdcall SetWindowLongW(HWND window, int index, LONG value);
__declspec(dllimport) BOOL __stdcall SetWindowPos(HWND window, HWND after, int x, int y, int width, int height,
                                                  UINT flags);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

__declspec(dllimport) BOOL __stdcall BitBlt(HDC destination, int x, int y, int width, int height, HDC source,
                                            int source_x, int source_y, DWORD rop);
__declspec(dllimport) HDC __stdcall CreateCompatibleDC(HDC dc);
__declspec(dllimport) HBITMAP __stdcall CreateDIBSection(HDC dc, const void *info, UINT usage, void **bits,
                                                         void *section, DWORD offset);
__declspec(dllimport) BOOL __stdcall DeleteDC(HDC dc);
__declspec(dllimport) BOOL __stdcall DeleteObject(HGDIOBJ object);
__declspec(dllimport) HGDIOBJ __stdcall GetStockObject(int index);
__declspec(dllimport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ object);
__declspec(dllimport) int __stdcall SetBkMode(HDC dc, int mode);

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
    return 1;
}

/* MSIDialog_WndProc: WM_CTLCOLORSTATIC bounced back to the static control. */
static LRESULT __stdcall dialog_procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_CTLCOLORSTATIC)
        return SendMessageW((HWND)l, WM_CTLCOLORSTATIC, w, l);
    return DefWindowProcW(hwnd, message, w, l);
}

/* MSIText_WndProc of a transparent text: TRANSPARENT and NULL_BRUSH. */
static WNDPROC static_procedure;

static LRESULT __stdcall text_procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_CTLCOLORSTATIC) {
        SetBkMode((HDC)w, TRANSPARENT);
        return (LRESULT)GetStockObject(NULL_BRUSH);
    }
    return CallWindowProcW(static_procedure, hwnd, message, w, l);
}

/* The dialog's messages, for `milliseconds`. */
static void pump(DWORD milliseconds)
{
    DWORD start = GetTickCount();
    MSG message;
    while (GetTickCount() - start < milliseconds) {
        while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        Sleep(10);
    }
}

/* The screen under `window`, in a 32-bit DIB section: its pixels darker than
   the page's gray (the text's), and those of the gray. */
static void count_pixels(HWND window, int *dark, int *gray)
{
    RECT rect;
    BITMAPINFOHEADER info;
    DWORD *bits = 0;
    HDC screen, memory;
    HBITMAP section;
    DWORD face = GetSysColor(COLOR_3DFACE);
    DWORD face_bgr = ((face & 0xFF) << 16) | (face & 0xFF00) | ((face >> 16) & 0xFF);
    int width, height, i;

    *dark = *gray = 0;
    GetWindowRect(window, &rect);
    width = rect.right - rect.left;
    height = rect.bottom - rect.top;
    memset(&info, 0, sizeof info);
    info.biSize = sizeof info;
    info.biWidth = width;
    info.biHeight = -height;
    info.biPlanes = 1;
    info.biBitCount = 32;
    screen = GetDC(0);
    memory = CreateCompatibleDC(screen);
    section = CreateDIBSection(screen, &info, 0, (void **)&bits, 0, 0);
    if (!section || !bits) {
        DeleteDC(memory);
        ReleaseDC(0, screen);
        return;
    }
    SelectObject(memory, section);
    BitBlt(memory, 0, 0, width, height, screen, rect.left, rect.top, SRCCOPY);
    for (i = 0; i < width * height; i++) {
        DWORD pixel = bits[i] & 0xFFFFFF;
        if (pixel == face_bgr)
            (*gray)++;
        else if ((pixel & 0xFF) < 0x60 && ((pixel >> 8) & 0xFF) < 0x60 && ((pixel >> 16) & 0xFF) < 0x60)
            (*dark)++;
    }
    DeleteDC(memory);
    DeleteObject(section);
    ReleaseDC(0, screen);
}

/* A text is shown: dark pixels (its glyphs) on the page's gray. */
static const char *shown(int dark, int gray)
{
    return dark > 20 && gray > 0 ? "shown" : "missing";
}

DWORD __stdcall GuiStartup(void)
{
    HINSTANCE instance = GetModuleHandleW(0);
    WNDCLASSW info;
    HWND dialog, title, description, bitmap, cancel, back, next, chain[4];
    int i;
    int title_dark, title_gray, description_dark, description_gray;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&info, 0, sizeof info);
    info.lpfnWndProc = dialog_procedure;
    info.hInstance = instance;
    info.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
    info.lpszClassName = L"MinoMsiDialog";
    if (!RegisterClassW(&info))
        ExitProcess(2);
    /* dialog_run_message_loop: not visible yet, shown once its controls are
       made. */
    dialog = CreateWindowExW(0, L"MinoMsiDialog", L"Setup", WS_OVERLAPPED | WS_SYSMENU, 200, 150, 497, 420, 0, 0,
                             instance, 0);
    if (!dialog)
        ExitProcess(3);
    /* The Control table's order: Title, Description, Cancel, Bitmap, Back,
       Next. */
    title = CreateWindowExW(0, L"Static", L"Welcome to the Mino Setup Wizard", SS_LEFT | WS_GROUP | WS_CHILD | WS_VISIBLE,
                            180, 26, 293, 80, dialog, 0, 0, 0);
    description = CreateWindowExW(0, L"Static", L"The Setup Wizard will install Mino on your computer.",
                                  SS_LEFT | WS_GROUP | WS_CHILD | WS_VISIBLE, 180, 93, 293, 80, dialog, 0, 0, 0);
    if (!title || !description)
        ExitProcess(4);
    SetWindowLongW(title, GWL_EXSTYLE, WS_EX_TRANSPARENT);
    SetWindowLongW(description, GWL_EXSTYLE, WS_EX_TRANSPARENT);
    static_procedure = (WNDPROC)SetWindowLongW(title, GWLP_WNDPROC, (LONG)text_procedure);
    SetWindowLongW(description, GWLP_WNDPROC, (LONG)text_procedure);
    cancel = CreateWindowExW(0, L"Button", L"Cancel", BS_PUSHBUTTON | WS_TABSTOP | WS_CHILD | WS_VISIBLE, 405, 324, 75,
                             23, dialog, 0, 0, 0);
    bitmap = CreateWindowExW(0, L"Static", 0, SS_BITMAP | SS_LEFT | WS_GROUP | WS_CHILD | WS_VISIBLE, 0, 0, 493, 312,
                             dialog, 0, 0, 0);
    back = CreateWindowExW(0, L"Button", L"Back", BS_PUSHBUTTON | WS_TABSTOP | WS_CHILD | WS_VISIBLE, 240, 324, 75, 23,
                           dialog, 0, 0, 0);
    next = CreateWindowExW(0, L"Button", L"Next", BS_PUSHBUTTON | WS_TABSTOP | WS_CHILD | WS_VISIBLE, 315, 324, 75, 23,
                           dialog, 0, 0, 0);
    if (!cancel || !bitmap || !back || !next)
        ExitProcess(5);
    /* dialog_set_tab_order: the chain Next, Cancel, Bitmap, Back on top of the
       Z order, in that order: the picture's Static goes above the two texts. */
    chain[0] = next;
    chain[1] = cancel;
    chain[2] = bitmap;
    chain[3] = back;
    for (i = 0; i < 4; i++)
        SetWindowPos(chain[i], i ? chain[i - 1] : 0, 0, 0, 0, 0, SWP_TABORDER);
    ShowWindow(dialog, SW_SHOW);
    pump(1500);
    count_pixels(title, &title_dark, &title_gray);
    count_pixels(description, &description_dark, &description_gray);
    DbgPrint("[msidlg] the title: %s (%d dark pixels, %d gray)\n", shown(title_dark, title_gray), title_dark,
             title_gray);
    DbgPrint("[msidlg] the description: %s (%d dark pixels, %d gray)\n", shown(description_dark, description_gray),
             description_dark, description_gray);
    DbgPrint("[msidlg] done\n");
    ExitProcess(0);
    return 0;
}
