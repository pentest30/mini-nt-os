/*
 * M5, console (and M6): a Win32 program (subsystem WINDOWS), compiled with
 * MinGW and linked to ReactOS's kernel32, user32 and gdi32, which the
 * scenario `bitmap` puts on the boot disk in the place of winlogon.exe
 * (like `gui`, see gui1.c). It takes a desktop like winlogon, then works with
 * what consrv paints its console with: the display's capabilities
 * (GetDeviceCaps), memory DCs (CreateCompatibleDC), DIB sections
 * (CreateDIBSection), whose pixels the program and the kernel both see,
 * SelectObject of a bitmap, a solid brush of its own (CreateSolidBrush),
 * PatBlt into a bitmap, and BitBlt from a bitmap to a window, within the
 * window (a scroll) and from the window to a bitmap; then DeleteObject and
 * DeleteDC. Each result goes to the debug port (DbgPrint), where the scenario
 * looks for it, and the drawing to the screen, where it checks pixels; the
 * program ends with EXIT_STATUS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned short WORD;
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
typedef void *HBITMAP;
typedef void *HDC;
typedef void *HGDIOBJ;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef DWORD COLORREF;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);

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
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;

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
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    unsigned char rgbReserved[32];
} PAINTSTRUCT;

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

typedef struct {
    BITMAPINFOHEADER bmiHeader;
    DWORD bmiColors[1];
} BITMAPINFO;

typedef struct {
    void *BaseAddress;
    void *AllocationBase;
    DWORD AllocationProtect;
    DWORD RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION;

#define WS_OVERLAPPED 0x00000000
#define WS_CAPTION 0x00C00000
#define WS_SYSMENU 0x00080000
#define WS_VISIBLE 0x10000000
#define WM_PAINT 0x000F
#define PM_REMOVE 1
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define HORZRES 8
#define VERTRES 10
#define BITSPIXEL 12
#define PLANES 14
#define NUMCOLORS 24
#define RASTERCAPS 38
#define LOGPIXELSX 88
#define RC_BITBLT 1
#define DEFAULT_BITMAP 21
#define BI_RGB 0
#define DIB_RGB_COLORS 0
#define OBJ_BRUSH 2
#define OBJ_BITMAP 7
#define MEM_COMMIT 0x1000
#define MEM_FREE 0x10000
#define MEM_MAPPED 0x40000
#define SRCCOPY 0x00CC0020
#define PATCOPY 0x00F00021
#define RGB(r, g, b) ((COLORREF)((r) | ((g) << 8) | ((b) << 16)))
#define EXIT_STATUS 0x600D

/* The DIB: 16 x 8 pixels, from the top row down. */
#define WIDTH 16
#define HEIGHT 8
/* The brush, as a DIB of 32 bits per pixel holds it: blue, green, red. */
#define BRUSH RGB(0x12, 0x34, 0x56)
#define BRUSH_PIXEL 0x00123456
#define RED_PIXEL 0x00FF0000

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) DWORD __stdcall VirtualQuery(const void *address, MEMORY_BASIC_INFORMATION *info, DWORD size);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

__declspec(dllimport) BOOL __stdcall BitBlt(HDC dest, int x, int y, int width, int height, HDC source, int x_source,
                                            int y_source, DWORD rop);
__declspec(dllimport) HDC __stdcall CreateCompatibleDC(HDC dc);
__declspec(dllimport) HBITMAP __stdcall CreateDIBSection(HDC dc, const BITMAPINFO *info, UINT usage, void **bits,
                                                         HANDLE section, DWORD offset);
__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(COLORREF color);
__declspec(dllimport) BOOL __stdcall DeleteDC(HDC dc);
__declspec(dllimport) BOOL __stdcall DeleteObject(HGDIOBJ object);
__declspec(dllimport) int __stdcall GetDeviceCaps(HDC dc, int index);
__declspec(dllimport) DWORD __stdcall GetObjectType(HGDIOBJ object);
__declspec(dllimport) HGDIOBJ __stdcall GetStockObject(int index);
__declspec(dllimport) BOOL __stdcall PatBlt(HDC dc, int x, int y, int width, int height, DWORD rop);
__declspec(dllimport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ object);

static const WCHAR CLASS_NAME[] = L"MinoBitmap";
static int painted;

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
    DbgPrint("[bitmap] on WinSta0\\Default\n");
    return 1;
}

/* A DIB section of 32 bits per pixel: `height` negative for rows from the
   top down. */
static HBITMAP dib_section(int width, int height, DWORD **bits)
{
    BITMAPINFO info;

    memset(&info, 0, sizeof info);
    info.bmiHeader.biSize = sizeof info.bmiHeader;
    info.bmiHeader.biWidth = width;
    info.bmiHeader.biHeight = height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    *bits = 0;
    return CreateDIBSection(0, &info, DIB_RGB_COLORS, (void **)bits, 0, 0);
}

/* The state and type of the memory at `address`: "mapped", "free" or what
   VirtualQuery says. */
static const char *memory_state(const void *address)
{
    MEMORY_BASIC_INFORMATION info;

    memset(&info, 0, sizeof info);
    if (!VirtualQuery(address, &info, sizeof info))
        return "unknown";
    if (info.State == MEM_COMMIT && info.Type == MEM_MAPPED)
        return "mapped";
    return info.State == MEM_FREE ? "free" : "WRONG";
}

/* What GetDeviceCaps says of a window's DC and of a memory DC. */
static void check_caps(HDC dc, HDC memory)
{
    DbgPrint("[bitmap] GetDeviceCaps: %dx%d, %d bits, %d plane, %d colours, %d dpi, BitBlt %s; memory DC %d bits\n",
             GetDeviceCaps(dc, HORZRES), GetDeviceCaps(dc, VERTRES), GetDeviceCaps(dc, BITSPIXEL),
             GetDeviceCaps(dc, PLANES), GetDeviceCaps(dc, NUMCOLORS), GetDeviceCaps(dc, LOGPIXELSX),
             GetDeviceCaps(dc, RASTERCAPS) & RC_BITBLT ? "yes" : "no", GetDeviceCaps(memory, BITSPIXEL));
}

/* A bottom-up DIB: its top row is the last in memory. */
static void check_bottom_up(HDC memory, HBRUSH brush)
{
    DWORD *bits;
    HBITMAP bitmap = dib_section(4, 4, &bits);
    HGDIOBJ old = SelectObject(memory, bitmap);
    HGDIOBJ old_brush = SelectObject(memory, brush);

    PatBlt(memory, 0, 0, 4, 1, PATCOPY);
    DbgPrint("[bitmap] bottom-up: the top row %s, the first in memory %s\n",
             bits && bits[12] == BRUSH_PIXEL ? "last" : "WRONG", bits && bits[0] == 0 ? "untouched" : "WRONG");
    SelectObject(memory, old_brush);
    SelectObject(memory, old);
    DeleteObject(bitmap);
}

/* Draws into a DIB section, reads it back, copies it to the window, within
   the window, and from the window into a second one. */
static void draw_bitmaps(HWND window, HDC dc)
{
    HDC memory = CreateCompatibleDC(0);
    HBRUSH brush = CreateSolidBrush(BRUSH);
    DWORD *bits, *copy_bits;
    HBITMAP bitmap = dib_section(WIDTH, -HEIGHT, &bits);
    HBITMAP copy = dib_section(WIDTH, -HEIGHT, &copy_bits);
    HGDIOBJ old, old_brush, previous;
    BOOL done, again, deleted[4];
    RECT outer, client;

    check_caps(dc, memory);
    DbgPrint("[bitmap] CreateCompatibleDC: %s, CreateSolidBrush: %s, CreateDIBSection: %s, bits %s\n",
             memory ? "a DC" : "none", brush ? "a brush" : "none", bitmap ? "a bitmap" : "none",
             bits ? "mapped" : "none");
    if (!memory || !brush || !bitmap || !bits || !copy || !copy_bits)
        return;
    old = SelectObject(memory, bitmap);
    DbgPrint("[bitmap] SelectObject: the old bitmap is %s\n",
             old == GetStockObject(DEFAULT_BITMAP) ? "the default bitmap" : "WRONG");
    {
        HDC other = CreateCompatibleDC(0);
        HGDIOBJ refused = SelectObject(other, bitmap);
        DbgPrint("[bitmap] SelectObject in a second DC: %s; the pixels: %s, type %lu\n", refused ? "WRONG" : "refused",
                 memory_state(bits), GetObjectType(bitmap));
        DeleteDC(other);
    }

    /* The kernel draws, the program reads. (The calls are made one by one:
       C does not say in which order a call's arguments are evaluated.) */
    old_brush = SelectObject(memory, brush);
    done = PatBlt(memory, 0, 0, WIDTH, HEIGHT, PATCOPY);
    DbgPrint("[bitmap] PatBlt: %d, pixel %08lx\n", done, bits[0]);
    SelectObject(memory, old_brush);
    /* The program draws, the kernel reads: a red pixel at (1, 1), copied to
       the window at (10, 10), then from there to (100, 10). */
    bits[WIDTH + 1] = RED_PIXEL;
    done = BitBlt(dc, 10, 10, WIDTH, HEIGHT, memory, 0, 0, SRCCOPY);
    again = BitBlt(dc, 100, 10, WIDTH, HEIGHT, dc, 10, 10, SRCCOPY);
    DbgPrint("[bitmap] BitBlt to the window: %d; within it: %d\n", done, again);
    /* From the window into the second DIB section. */
    previous = SelectObject(memory, copy);
    done = BitBlt(memory, 0, 0, WIDTH, HEIGHT, dc, 100, 10, SRCCOPY);
    DbgPrint("[bitmap] BitBlt from the window: %d, pixels %08lx %08lx\n", done, copy_bits[0], copy_bits[WIDTH + 1]);
    done = DeleteObject(copy);
    DbgPrint("[bitmap] SelectObject again: the old bitmap is %s; DeleteObject of the selected one: %d\n",
             previous == bitmap ? "the first DIB" : "WRONG", done);
    check_bottom_up(memory, brush);
    SelectObject(memory, old);
    deleted[0] = DeleteObject(copy);
    deleted[1] = DeleteObject(bitmap);
    deleted[2] = DeleteObject(brush);
    deleted[3] = DeleteDC(memory);
    DbgPrint("[bitmap] DeleteObject: %d %d %d, DeleteDC: %d\n", deleted[0], deleted[1], deleted[2], deleted[3]);
    DbgPrint("[bitmap] deleted: the pixels %s, types %lu %lu %lu\n", memory_state(bits), GetObjectType(bitmap),
             GetObjectType(brush), GetObjectType(memory));
    GetWindowRect(window, &outer);
    GetClientRect(window, &client);
    {
        LONG border = (outer.right - outer.left - client.right) / 2;
        DbgPrint("[bitmap] the client area at %ld %ld\n", outer.left + border, outer.bottom - border - client.bottom);
    }
}

static LRESULT __stdcall bitmap_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    if (message == WM_PAINT) {
        HDC dc = BeginPaint(window, &paint);
        if (!painted)
            draw_bitmaps(window, dc);
        EndPaint(window, &paint);
        painted = 1;
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
    MSG message;
    int round;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = bitmap_procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    window = CreateWindowExW(0, CLASS_NAME, L"Bitmap", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 300,
                             200, 200, 100, 0, 0, instance, 0);
    if (!window)
        ExitProcess(3);
    for (round = 0; round < 100 && !painted; round++)
        while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
            DispatchMessageW(&message);
    DbgPrint("[bitmap] painted: %s\n", painted ? "yes" : "no");
    DbgPrint("[bitmap] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
