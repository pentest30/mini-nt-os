/*
 * A 24-bit BMP loaded as msi.dll loads the pictures of its dialogs
 * (load_picture in dll/win32/msi/dialog.c): a Win32 program (subsystem
 * WINDOWS), compiled with MinGW and linked to ReactOS's kernel32, user32,
 * gdi32, ole32 and oleaut32, which the scenario `ole-picture` runs as the
 * shell of a session (userinit, "/session"), after minoinit's registrations.
 * The welcome page of an MSI made with WiX (7-Zip 9.20) showed no picture:
 * msi.dll logged "Failed to load bitmap WixUI_Bmp_Dialog". oleaut32 decodes
 * every picture, a BMP too, through WIC (windowscodecs), which syssetup.inf
 * registers and minoinit did not: OleLoadPicture failed with
 * REGDB_E_CLASSNOTREG. Each step's result:
 * 1. the BMP in a stream (CreateStreamOnHGlobal), OleLoadPicture, its
 *    handle, GetObject of the bitmap;
 * 2. the copy at another size: two memory DCs, CreateCompatibleBitmap of
 *    the DC that holds the picture, StretchBlt, a pixel of the copy.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef LONG HRESULT;
typedef void *HANDLE;
typedef void *HGLOBAL;
typedef void *HDC;
typedef void *HBITMAP;
typedef void *HGDIOBJ;
typedef void *HWINSTA;
typedef void *HDESK;
typedef DWORD COLORREF;

typedef struct {
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[8];
} GUID;

typedef struct {
    LONG bmType;
    LONG bmWidth;
    LONG bmHeight;
    LONG bmWidthBytes;
    WORD bmPlanes;
    WORD bmBitsPixel;
    void *bmBits;
} BITMAP;

/* The first slots of IStream and IPicture: IUnknown, then get_Handle. */
typedef struct Unknown Unknown;
typedef struct {
    HRESULT(__stdcall *QueryInterface)(Unknown *self, const GUID *iid, void **out);
    DWORD(__stdcall *AddRef)(Unknown *self);
    DWORD(__stdcall *Release)(Unknown *self);
    HRESULT(__stdcall *get_Handle)(Unknown *self, UINT *handle);
} UnknownVtbl;
struct Unknown {
    const UnknownVtbl *vtbl;
};

#define GMEM_MOVEABLE 0x0002
#define SRCCOPY 0x00CC0020
#define MAXIMUM_ALLOWED 0x02000000
#define RGB(r, g, b) ((COLORREF)((r) | ((g) << 8) | ((b) << 16)))

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) WCHAR *__stdcall GetCommandLineW(void);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HGLOBAL __stdcall GlobalAlloc(UINT flags, DWORD bytes);
__declspec(dllimport) void *__stdcall GlobalLock(HGLOBAL memory);
__declspec(dllimport) BOOL __stdcall GlobalUnlock(HGLOBAL memory);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

__declspec(dllimport) HDC __stdcall CreateCompatibleDC(HDC dc);
__declspec(dllimport) HBITMAP __stdcall CreateCompatibleBitmap(HDC dc, int width, int height);
__declspec(dllimport) BOOL __stdcall DeleteDC(HDC dc);
__declspec(dllimport) int __stdcall GetObjectW(HGDIOBJ object, int size, void *buffer);
__declspec(dllimport) COLORREF __stdcall GetPixel(HDC dc, int x, int y);
__declspec(dllimport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ object);
__declspec(dllimport) BOOL __stdcall StretchBlt(HDC destination, int x, int y, int width, int height, HDC source,
                                                int source_x, int source_y, int source_width, int source_height,
                                                DWORD rop);

__declspec(dllimport) HRESULT __stdcall CoInitialize(void *reserved);
__declspec(dllimport) HRESULT __stdcall CreateStreamOnHGlobal(HGLOBAL memory, BOOL delete_on_release,
                                                              Unknown **stream);
__declspec(dllimport) HRESULT __stdcall OleLoadPicture(Unknown *stream, LONG size, BOOL run_mode, const GUID *iid,
                                                       void **picture);

static const GUID IID_IPicture = {0x7BF80980, 0xBF32, 0x101A, {0x8B, 0xBB, 0x00, 0xAA, 0x00, 0x30, 0x0C, 0xAB}};

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

/* Launched by userinit as the session's shell: "/session" ends its command
 * line, the desktop is the user's. */
static int in_session(void)
{
    const WCHAR *line = GetCommandLineW();
    static const WCHAR WORD_SESSION[] = L"/session";
    for (; *line; line++) {
        int i;
        for (i = 0; WORD_SESSION[i] && line[i] == WORD_SESSION[i]; i++)
            ;
        if (!WORD_SESSION[i])
            return 1;
    }
    return 0;
}

static void put16(BYTE *at, unsigned value)
{
    at[0] = (BYTE)value;
    at[1] = (BYTE)(value >> 8);
}

static void put32(BYTE *at, unsigned value)
{
    put16(at, value & 0xFFFF);
    put16(at + 2, value >> 16);
}

/* An 8 x 4 BMP of 24 bits, every pixel RGB(10, 20, 200). */
#define WIDTH 8
#define HEIGHT 4
#define BMP_SIZE (54 + WIDTH * 3 * HEIGHT)

static void make_bmp(BYTE *bmp)
{
    int i;
    memset(bmp, 0, BMP_SIZE);
    bmp[0] = 'B';
    bmp[1] = 'M';
    put32(bmp + 2, BMP_SIZE);
    put32(bmp + 10, 54);
    put32(bmp + 14, 40);
    put32(bmp + 18, WIDTH);
    put32(bmp + 22, HEIGHT);
    put16(bmp + 26, 1);
    put16(bmp + 28, 24);
    put32(bmp + 34, WIDTH * 3 * HEIGHT);
    for (i = 0; i < WIDTH * HEIGHT; i++) {
        bmp[54 + 3 * i] = 200; /* blue */
        bmp[54 + 3 * i + 1] = 20;
        bmp[54 + 3 * i + 2] = 10; /* red */
    }
}

DWORD __stdcall GuiStartup(void)
{
    HGLOBAL memory;
    Unknown *stream = 0, *picture = 0;
    HRESULT co, loaded, handled;
    UINT handle = 0;
    BITMAP bm;
    int got, blitted;
    HDC source, destination;
    HBITMAP copy;
    HGDIOBJ old_source = 0;
    COLORREF pixel = 0xFFFFFFFF;

    if (!in_session() && !take_a_desktop())
        ExitProcess(1);
    co = CoInitialize(0);

    /* 1. The picture. */
    memory = GlobalAlloc(GMEM_MOVEABLE, BMP_SIZE);
    if (!memory)
        ExitProcess(2);
    make_bmp(GlobalLock(memory));
    GlobalUnlock(memory);
    if (CreateStreamOnHGlobal(memory, 1, &stream) < 0 || !stream)
        ExitProcess(3);
    loaded = OleLoadPicture(stream, 0, 1, &IID_IPicture, (void **)&picture);
    handled = picture ? picture->vtbl->get_Handle(picture, &handle) : -1;
    memset(&bm, 0, sizeof bm);
    got = handle ? GetObjectW((HGDIOBJ)handle, sizeof bm, &bm) : 0;
    DbgPrint("[olepic] step 1: CoInitialize %lx; OleLoadPicture %lx; get_Handle %lx, a bitmap %d; GetObject %d: %ld x "
             "%ld, %u bits\n",
             co, loaded, handled, handle != 0, got, bm.bmWidth, bm.bmHeight, bm.bmBitsPixel);

    /* 2. Copied at twice its size, as msi.dll's load_picture does. */
    source = CreateCompatibleDC(0);
    if (handle)
        old_source = SelectObject(source, (HGDIOBJ)handle);
    destination = CreateCompatibleDC(0);
    copy = CreateCompatibleBitmap(source, 2 * WIDTH, 2 * HEIGHT);
    blitted = 0;
    if (copy) {
        SelectObject(destination, copy);
        blitted = StretchBlt(destination, 0, 0, 2 * WIDTH, 2 * HEIGHT, source, 0, 0, WIDTH, HEIGHT, SRCCOPY);
        pixel = GetPixel(destination, 3, 3);
    }
    DbgPrint("[olepic] step 2: selected %d; CreateCompatibleBitmap %d; StretchBlt %d; the copy's pixel %06lx (the "
             "BMP's %d)\n",
             old_source != 0, copy != 0, blitted, pixel, pixel == RGB(10, 20, 200));
    DeleteDC(source);
    DeleteDC(destination);
    DbgPrint("[olepic] done\n");
    ExitProcess(0);
    return 0;
}
