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
 * DeleteDC; then what comctl32's image lists ask: StretchBlt, GetNearestColor,
 * GetDIBits, StretchDIBits of bit fields (check_stretch_and_dibits). Each
 * result goes to the debug port (DbgPrint), where the scenario
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
    LONG bmType;
    LONG bmWidth;
    LONG bmHeight;
    LONG bmWidthBytes;
    WORD bmPlanes;
    WORD bmBitsPixel;
    void *bmBits;
} BITMAP;

typedef struct {
    BITMAP dsBm;
    BITMAPINFOHEADER dsBmih;
    DWORD dsBitfields[3];
    HANDLE dshSection;
    DWORD dsOffset;
} DIBSECTION;

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
#define BI_BITFIELDS 3
#define CLR_INVALID 0xFFFFFFFF
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
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

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
__declspec(dllimport) int __stdcall GetObjectW(HGDIOBJ object, int size, void *buffer);
__declspec(dllimport) HBITMAP __stdcall CreateBitmap(int width, int height, UINT planes, UINT bits_pixel,
                                                     const void *bits);
__declspec(dllimport) HGDIOBJ __stdcall GetStockObject(int index);
__declspec(dllimport) BOOL __stdcall PatBlt(HDC dc, int x, int y, int width, int height, DWORD rop);
__declspec(dllimport) int __stdcall GetDIBits(HDC dc, HBITMAP bitmap, UINT start, UINT lines, void *bits, BITMAPINFO *info,
                                              UINT usage);
__declspec(dllimport) COLORREF __stdcall GetNearestColor(HDC dc, COLORREF color);
typedef struct {
    BYTE BlendOp;
    BYTE BlendFlags;
    BYTE SourceConstantAlpha;
    BYTE AlphaFormat;
} BLENDFUNCTION;
__declspec(dllimport) HBITMAP __stdcall CreateDIBitmap(HDC dc, const BITMAPINFOHEADER *header, DWORD init,
                                                       const void *bits, const BITMAPINFO *info, UINT usage);
__declspec(dllimport) BOOL __stdcall GdiAlphaBlend(HDC dest, int x, int y, int width, int height, HDC source,
                                                   int x_source, int y_source, int width_source, int height_source,
                                                   BLENDFUNCTION blend);
__declspec(dllimport) COLORREF __stdcall SetBkColor(HDC dc, COLORREF color);
__declspec(dllimport) COLORREF __stdcall SetTextColor(HDC dc, COLORREF color);
__declspec(dllimport) BOOL __stdcall StretchBlt(HDC dest, int x, int y, int width, int height, HDC source, int x_source,
                                                int y_source, int width_source, int height_source, DWORD rop);
__declspec(dllimport) int __stdcall StretchDIBits(HDC dc, int x, int y, int width, int height, int x_source,
                                                  int y_source, int width_source, int height_source, const void *bits,
                                                  const BITMAPINFO *info, UINT usage, DWORD rop);
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

/* GetObjectW of bitmaps: a DIB section's DIBSECTION, its pixels where the
   program sees them; its BITMAP when only that fits; a monochrome bitmap's
   BITMAP, rows of 16-bit words, without pixels. */
static void check_get_object(HBITMAP dib, const DWORD *bits)
{
    DIBSECTION section;
    BITMAP only, mono_info;
    HBITMAP mono = CreateBitmap(13, 4, 1, 1, 0);
    int whole, short_one, mono_size;

    memset(&section, 0, sizeof section);
    memset(&only, 0, sizeof only);
    memset(&mono_info, 0, sizeof mono_info);
    whole = GetObjectW(dib, sizeof section, &section);
    short_one = GetObjectW(dib, sizeof only, &only);
    mono_size = GetObjectW(mono, sizeof mono_info, &mono_info);
    DbgPrint("[bitmap] GetObjectW: DIBSECTION %d, %ldx%ld, %ld bytes a row, %u bits, pixels %s, header %lu %ld %ld %u, "
             "image %lu\n",
             whole, section.dsBm.bmWidth, section.dsBm.bmHeight, section.dsBm.bmWidthBytes, section.dsBm.bmBitsPixel,
             section.dsBm.bmBits == bits ? "its own" : "WRONG", section.dsBmih.biSize, section.dsBmih.biWidth,
             section.dsBmih.biHeight, section.dsBmih.biBitCount, section.dsBmih.biSizeImage);
    DbgPrint("[bitmap] GetObjectW: BITMAP %d, pixels %s; a monochrome one %d, %ld bytes a row, %u bit, pixels %s\n",
             short_one, only.bmBits == bits ? "its own" : "WRONG", mono_size, mono_info.bmWidthBytes,
             mono_info.bmBitsPixel, mono_info.bmBits ? "WRONG" : "none");
    DeleteObject(mono);
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
    check_get_object(bitmap, bits);

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

/* A BITMAPINFO with three entries after its header: two colours, or three
   masks. */
typedef struct {
    BITMAPINFOHEADER bmiHeader;
    DWORD bmiColors[3];
} BITMAPINFO3;

static void header(BITMAPINFO3 *info, LONG width, LONG height, WORD bit_count, DWORD compression)
{
    memset(info, 0, sizeof *info);
    info->bmiHeader.biSize = sizeof info->bmiHeader;
    info->bmiHeader.biWidth = width;
    info->bmiHeader.biHeight = height;
    info->bmiHeader.biPlanes = 1;
    info->bmiHeader.biBitCount = bit_count;
    info->bmiHeader.biCompression = compression;
}

/* What comctl32's image lists and toolbar ask of GDI: StretchBlt between
   DIB sections, larger then smaller; GetNearestColor; GetDIBits of a bitmap
   of 32 bits (its format alone, then its lines from the top and from the
   bottom) and of a monochrome one (its two colours, its lines from the
   bottom); StretchDIBits of a DIB of 16 bits with its 5-6-5 masks
   (BI_BITFIELDS). */
static void check_stretch_and_dibits(void)
{
    static const DWORD deep_pixels[8] = {RED_PIXEL, BRUSH_PIXEL, 0x0000FF00, 0x000000FF, 1, 2, 3, 4};
    static const BYTE mono_rows[4] = {0xA5, 0x0F, 0x00, 0xFF};
    HDC source_dc = CreateCompatibleDC(0), dest_dc = CreateCompatibleDC(0);
    DWORD *source_bits, *dest_bits, got[8], green_line = 0x07E0;
    BYTE mono_got[8];
    HBITMAP source = dib_section(2, -1, &source_bits), dest = dib_section(4, -2, &dest_bits);
    HBITMAP deep = CreateBitmap(4, 2, 1, 32, deep_pixels), mono = CreateBitmap(16, 2, 1, 1, mono_rows);
    HGDIOBJ old_source, old_dest;
    BITMAPINFO3 info;
    BOOL done;
    int lines;

    if (!source_dc || !dest_dc || !source || !dest || !deep || !mono) {
        DbgPrint("[bitmap] StretchBlt and GetDIBits: no DC or bitmap\n");
        return;
    }
    old_source = SelectObject(source_dc, source);
    old_dest = SelectObject(dest_dc, dest);
    source_bits[0] = RED_PIXEL;
    source_bits[1] = BRUSH_PIXEL;
    done = StretchBlt(dest_dc, 0, 0, 4, 2, source_dc, 0, 0, 2, 1, SRCCOPY);
    DbgPrint("[bitmap] StretchBlt 2x1 to 4x2: %d, %08lx %08lx %08lx %08lx, %08lx %08lx\n", done, dest_bits[0],
             dest_bits[1], dest_bits[2], dest_bits[3], dest_bits[4], dest_bits[7]);
    dest_bits[0] = 0x0000FF00;
    dest_bits[2] = 0x000000FF;
    done = StretchBlt(source_dc, 0, 0, 2, 1, dest_dc, 0, 0, 4, 2, SRCCOPY);
    DbgPrint("[bitmap] StretchBlt 4x2 to 2x1: %d, %08lx %08lx\n", done, source_bits[0], source_bits[1]);
    DbgPrint("[bitmap] GetNearestColor: %08lx; of no DC: %s\n", GetNearestColor(dest_dc, RGB(1, 2, 3)),
             GetNearestColor((HDC)0x0BAD0BAD, RGB(1, 2, 3)) == CLR_INVALID ? "CLR_INVALID" : "WRONG");

    header(&info, 0, 0, 0, BI_RGB);
    lines = GetDIBits(dest_dc, deep, 0, 0, 0, (BITMAPINFO *)&info, DIB_RGB_COLORS);
    DbgPrint("[bitmap] GetDIBits of a bitmap of 32 bits, its format: %d, %ldx%ld, %u bits, compression %lu, %lu bytes\n",
             lines, info.bmiHeader.biWidth, info.bmiHeader.biHeight, info.bmiHeader.biBitCount,
             info.bmiHeader.biCompression, info.bmiHeader.biSizeImage);
    header(&info, 4, -2, 32, BI_RGB);
    memset(got, 0, sizeof got);
    lines = GetDIBits(dest_dc, deep, 0, 2, got, (BITMAPINFO *)&info, DIB_RGB_COLORS);
    DbgPrint("[bitmap] GetDIBits from the top: %d, %08lx %08lx, then %08lx\n", lines, got[0], got[1], got[4]);
    header(&info, 4, 2, 32, BI_RGB);
    memset(got, 0, sizeof got);
    lines = GetDIBits(dest_dc, deep, 0, 2, got, (BITMAPINFO *)&info, DIB_RGB_COLORS);
    DbgPrint("[bitmap] GetDIBits from the bottom: %d, %08lx, then %08lx\n", lines, got[0], got[4]);
    header(&info, 16, 2, 1, BI_RGB);
    info.bmiColors[0] = info.bmiColors[1] = 0x00ABCDEF;
    memset(mono_got, 0, sizeof mono_got);
    lines = GetDIBits(dest_dc, mono, 0, 2, mono_got, (BITMAPINFO *)&info, DIB_RGB_COLORS);
    DbgPrint("[bitmap] GetDIBits of a monochrome bitmap: %d, colours %06lx %06lx, rows %02x%02x %02x%02x\n", lines,
             info.bmiColors[0], info.bmiColors[1], mono_got[0], mono_got[1], mono_got[4], mono_got[5]);

    header(&info, 1, 1, 16, BI_BITFIELDS);
    info.bmiColors[0] = 0xF800;
    info.bmiColors[1] = 0x07E0;
    info.bmiColors[2] = 0x001F;
    dest_bits[0] = 0;
    lines = StretchDIBits(dest_dc, 0, 0, 1, 1, 0, 0, 1, 1, &green_line, (BITMAPINFO *)&info, DIB_RGB_COLORS, SRCCOPY);
    DbgPrint("[bitmap] StretchDIBits of 5-6-5 bit fields: %d, pixel %08lx\n", lines, dest_bits[0]);

    SelectObject(source_dc, old_source);
    SelectObject(dest_dc, old_dest);
    DeleteObject(source);
    DeleteObject(dest);
    DeleteObject(deep);
    DeleteObject(mono);
    DeleteDC(source_dc);
    DeleteDC(dest_dc);
}

/* A BITMAPINFO with a table of 16 colours. */
typedef struct {
    BITMAPINFOHEADER bmiHeader;
    DWORD bmiColors[16];
} BITMAPINFO16;

/* What comctl32's toolbar, its image lists of 4 bits and alpha icons ask
   of GDI: BitBlt from colours to a monochrome bitmap (the source's
   background colour gives white) and back (black gives the destination's
   text colour, white its background colour); a DIB section of 4 bits
   (indices in its table, the nearest colour; GetObject; GetDIBits of 4
   bits: its own table, the VGA table of a bitmap without one);
   CreateDIBitmap keeping the alpha of a DIB of 32 bits; GdiAlphaBlend with
   the alpha of each pixel (premultiplied). */
static void check_mono_indexed_alpha(void)
{
    HDC colour_dc = CreateCompatibleDC(0), mono_dc = CreateCompatibleDC(0), four_dc = CreateCompatibleDC(0);
    DWORD *colour_bits, *source_bits, got = 0;
    BYTE *four_bits, mono_byte[4] = {0}, four_got[4] = {0};
    HBITMAP colour = dib_section(2, -1, &colour_bits), source = dib_section(2, -1, &source_bits);
    HBITMAP mono = CreateBitmap(2, 1, 1, 1, 0), four, made;
    HGDIOBJ old_colour, old_mono, old_four;
    HBRUSH red = CreateSolidBrush(RGB(250, 10, 0));
    BITMAPINFO16 info4;
    BITMAPINFO3 info;
    DIBSECTION section;
    BLENDFUNCTION blend = {0, 0, 255, 1};
    DWORD alpha_pixel = 0x80402010;
    BOOL blended;

    if (!colour_dc || !mono_dc || !four_dc || !colour || !source || !mono || !red) {
        DbgPrint("[bitmap] monochrome, indexed and alpha: no DC or bitmap\n");
        return;
    }
    old_colour = SelectObject(colour_dc, colour);
    old_mono = SelectObject(mono_dc, mono);
    colour_bits[0] = BRUSH_PIXEL;
    colour_bits[1] = RED_PIXEL;
    SetBkColor(colour_dc, BRUSH);
    BitBlt(mono_dc, 0, 0, 2, 1, colour_dc, 0, 0, SRCCOPY);
    header(&info, 2, 1, 1, BI_RGB);
    GetDIBits(mono_dc, mono, 0, 1, mono_byte, (BITMAPINFO *)&info, DIB_RGB_COLORS);
    SetTextColor(colour_dc, RGB(0, 0, 255));
    SetBkColor(colour_dc, RGB(0, 255, 0));
    BitBlt(colour_dc, 0, 0, 2, 1, mono_dc, 0, 0, SRCCOPY);
    DbgPrint("[bitmap] BitBlt to monochrome: %02x; back to colours: %08lx %08lx\n", mono_byte[0], colour_bits[0],
             colour_bits[1]);

    memset(&info4, 0, sizeof info4);
    info4.bmiHeader.biSize = sizeof info4.bmiHeader;
    info4.bmiHeader.biWidth = 2;
    info4.bmiHeader.biHeight = -1;
    info4.bmiHeader.biPlanes = 1;
    info4.bmiHeader.biBitCount = 4;
    info4.bmiHeader.biCompression = BI_RGB;
    info4.bmiColors[1] = 0x00FF0000;
    info4.bmiColors[2] = 0x0000FF00;
    four_bits = 0;
    four = CreateDIBSection(0, (BITMAPINFO *)&info4, DIB_RGB_COLORS, (void **)&four_bits, 0, 0);
    old_four = SelectObject(four_dc, four);
    SelectObject(four_dc, red);
    PatBlt(four_dc, 0, 0, 1, 1, PATCOPY);
    memset(&section, 0, sizeof section);
    GetObjectW(four, sizeof section, &section);
    info4.bmiColors[1] = 0;
    GetDIBits(four_dc, four, 0, 1, four_got, (BITMAPINFO *)&info4, DIB_RGB_COLORS);
    DbgPrint("[bitmap] a DIB section of 4 bits: %u bits, %lu colours; painted near red: %02x; GetDIBits: %02x, its "
             "red %06lx\n",
             section.dsBm.bmBitsPixel, section.dsBmih.biClrUsed, four_bits ? four_bits[0] : 0xEE, four_got[0],
             info4.bmiColors[1]);
    memset(&info4, 0, sizeof info4);
    info4.bmiHeader.biSize = sizeof info4.bmiHeader;
    info4.bmiHeader.biWidth = 2;
    info4.bmiHeader.biHeight = 1;
    info4.bmiHeader.biPlanes = 1;
    info4.bmiHeader.biBitCount = 4;
    GetDIBits(colour_dc, colour, 0, 0, 0, (BITMAPINFO *)&info4, DIB_RGB_COLORS);
    DbgPrint("[bitmap] the default table of 4 bits: %06lx %06lx %06lx\n", info4.bmiColors[7], info4.bmiColors[8],
             info4.bmiColors[9]);

    header(&info, 1, 1, 32, BI_RGB);
    made = CreateDIBitmap(colour_dc, &info.bmiHeader, 4 /* CBM_INIT */, &alpha_pixel, (BITMAPINFO *)&info,
                          DIB_RGB_COLORS);
    header(&info, 1, 1, 32, BI_RGB);
    GetDIBits(colour_dc, made, 0, 1, &got, (BITMAPINFO *)&info, DIB_RGB_COLORS);
    DbgPrint("[bitmap] CreateDIBitmap of 32 bits: %s, read back %08lx\n", made ? "a bitmap" : "none", got);

    SelectObject(mono_dc, source);
    source_bits[0] = 0x80404040;
    source_bits[1] = 0;
    colour_bits[0] = colour_bits[1] = 0x00C8C8C8;
    blended = GdiAlphaBlend(colour_dc, 0, 0, 2, 1, mono_dc, 0, 0, 2, 1, blend);
    DbgPrint("[bitmap] GdiAlphaBlend: %d, %08lx %08lx\n", blended, colour_bits[0], colour_bits[1]);

    SelectObject(colour_dc, old_colour);
    SelectObject(mono_dc, old_mono);
    SelectObject(four_dc, old_four);
    DeleteObject(colour);
    DeleteObject(source);
    DeleteObject(mono);
    DeleteObject(four);
    DeleteObject(made);
    DeleteObject(red);
    DeleteDC(colour_dc);
    DeleteDC(mono_dc);
    DeleteDC(four_dc);
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
    check_stretch_and_dibits();
    check_mono_indexed_alpha();
    DbgPrint("[bitmap] done\n");
    /* Its windows go with the process: the scenario captures the screen
     * meanwhile. */
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
