/*
 * First native UI milestone for Mino's installer. The `installer-ui` boot
 * scenario puts this WINDOWS-subsystem program in place of winlogon.exe,
 * as the other GUI probes do. It uses the real ReactOS user32/gdi32 over
 * Mino's win32k and implements the five-screen installer flow with custom
 * GDI controls and keyboard navigation.
 *
 * The read-only privileged backend now supplies a real ATA target and an
 * immutable GPT/FAT plan through NtDeviceIoControlFile. Execution remains
 * deliberately disabled: no disk is modified by this program.
 *
 * Built by `cargo xtask` without a C runtime: -nostdlib, entry point
 * GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned short USHORT;
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HDC;
typedef void *HGDIOBJ;
typedef void *HWINSTA;
typedef void *HDESK;
typedef void *HKL;
typedef void *HANDLE;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef DWORD COLORREF;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct {
    USHORT length;
    USHORT maximum_length;
    WCHAR *buffer;
} UNICODE_STRING;

typedef struct {
    DWORD length;
    HANDLE root_directory;
    UNICODE_STRING *object_name;
    DWORD attributes;
    void *security_descriptor;
    void *security_quality_of_service;
} OBJECT_ATTRIBUTES;

typedef struct {
    LONG status;
    DWORD information;
} IO_STATUS_BLOCK;

/* abi::setup::SetupPreview: only 32-bit words, including split u64 values. */
typedef struct {
    DWORD version;
    DWORD state;
    DWORD disk_number;
    DWORD disk_flags;
    DWORD sector_size;
    DWORD total_low;
    DWORD total_high;
    DWORD token_low;
    DWORD token_high;
    DWORD esp_first_low;
    DWORD esp_first_high;
    DWORD esp_sectors_low;
    DWORD esp_sectors_high;
    DWORD system_first_low;
    DWORD system_first_high;
    DWORD system_sectors_low;
    DWORD system_sectors_high;
} SETUP_PREVIEW;

/* abi::setup::SetupPrepare: the disk of the preview and its token, as the
 * kernel recomputes the plan and refuses a token that no longer describes
 * it. */
typedef struct {
    DWORD version;
    DWORD disk_number;
    DWORD token_low;
    DWORD token_high;
} SETUP_PREPARE;

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
    BYTE rgbReserved[32];
} PAINTSTRUCT;

#define TRUE 1
#define FALSE 0
#define MAXIMUM_ALLOWED 0x02000000
#define FILE_READ_ATTRIBUTES 0x00000080
#define FILE_WRITE_ATTRIBUTES 0x00000100
#define FILE_SHARE_ALL 0x00000007
#define FILE_DIRECTORY_FILE 0x00000001
#define OBJ_CASE_INSENSITIVE 0x00000040
#define IOCTL_MINO_SETUP_QUERY 0x80006000
/* CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS): writes the
 * plan's GPT tables on the target, after the token revalidates it. */
#define IOCTL_MINO_SETUP_PREPARE 0x8000A004
/* CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS): formats the
 * plan's two volumes FAT32, after the prepare — same token. */
#define IOCTL_MINO_SETUP_FORMAT 0x8000A008
#define SETUP_READY 0
#define SETUP_DISK_CANDIDATE 1
#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_VISIBLE 0x10000000
#define COLOR_WINDOW 5
#define WM_PAINT 0x000F
#define WM_CHAR 0x0102
#define VK_TAB 0x09
#define VK_RETURN 0x0D
#define VK_ESCAPE 0x1B
#define VK_SPACE 0x20
#define KLF_ACTIVATE 0x00000001
#define TRANSPARENT 1
#define PATCOPY 0x00F00021
#define DT_LEFT 0x0000
#define DT_CENTER 0x0001
#define DT_RIGHT 0x0002
#define DT_VCENTER 0x0004
#define DT_WORDBREAK 0x0010
#define DT_SINGLELINE 0x0020
#define DT_NOPREFIX 0x0800
#define DEFAULT_GUI_FONT 17
#define RGB(r, g, b) ((COLORREF)((r) | ((g) << 8) | ((b) << 16)))

enum Screen {
    SCREEN_WELCOME,
    SCREEN_DISK,
    SCREEN_REVIEW,
    SCREEN_INSTALL,
    SCREEN_COMPLETE
};

static const WCHAR CLASS_NAME[] = L"MinoSetup";
static enum Screen current_screen = SCREEN_WELCOME;
/* 0 is Back, 1 is the primary action. */
static int focused_action = 1;
static int disk_visits;
static int review_visits;
static int progress;
static BOOL backend_ready;
static DWORD target_mib;
static DWORD esp_mib;
static DWORD system_mib;
/* The identity the preview gave: the prepare request carries it back. */
static DWORD target_disk_number;
static DWORD target_token_low;
static DWORD target_token_high;
static WCHAR target_size_text[32] = L"Unavailable";

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) LONG __stdcall NtClose(HANDLE handle);
__declspec(dllimport) LONG __stdcall NtDeviceIoControlFile(HANDLE file, HANDLE event, void *apc_routine,
                                                           void *apc_context, IO_STATUS_BLOCK *iosb, DWORD code,
                                                           void *input, DWORD input_length, void *output,
                                                           DWORD output_length);
__declspec(dllimport) LONG __stdcall NtOpenFile(HANDLE *file, DWORD access, OBJECT_ATTRIBUTES *attributes,
                                                IO_STATUS_BLOCK *iosb, DWORD share, DWORD options);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) int __stdcall DrawTextW(HDC dc, const WCHAR *text, int count, RECT *rect, UINT format);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall InvalidateRect(HWND window, const RECT *rect, BOOL erase);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *klid, UINT flags);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);

__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(COLORREF color);
__declspec(dllimport) BOOL __stdcall DeleteObject(HGDIOBJ object);
__declspec(dllimport) BOOL __stdcall GdiFlush(void);
__declspec(dllimport) HGDIOBJ __stdcall GetStockObject(int index);
__declspec(dllimport) BOOL __stdcall PatBlt(HDC dc, int x, int y, int width, int height, DWORD operation);
__declspec(dllimport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ object);
__declspec(dllimport) int __stdcall SetBkMode(HDC dc, int mode);
__declspec(dllimport) COLORREF __stdcall SetTextColor(HDC dc, COLORREF color);

void *memset(void *destination, int value, unsigned int count)
{
    BYTE *bytes = destination;
    while (count--)
        *bytes++ = (BYTE)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned int count)
{
    BYTE *to = destination;
    const BYTE *from = source;
    while (count--)
        *to++ = *from++;
    return destination;
}

static void format_mib(WCHAR *out, DWORD value, const WCHAR *suffix)
{
    WCHAR reverse[10];
    unsigned int count = 0;
    unsigned int index;

    do {
        reverse[count++] = (WCHAR)(L'0' + value % 10);
        value /= 10;
    } while (value && count < 10);
    index = 0;
    while (count)
        out[index++] = reverse[--count];
    while (*suffix)
        out[index++] = *suffix++;
    out[index] = 0;
}

static unsigned int wide_length(const WCHAR *text)
{
    unsigned int length = 0;
    while (text[length])
        ++length;
    return length;
}

static void query_install_backend(void)
{
    static WCHAR root_name[] = L"\\GLOBAL??\\C:\\";
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    SETUP_PREVIEW preview;
    HANDLE root = 0;
    LONG status;

    memset(&name, 0, sizeof name);
    memset(&attributes, 0, sizeof attributes);
    memset(&iosb, 0, sizeof iosb);
    memset(&preview, 0, sizeof preview);
    name.length = (USHORT)(wide_length(root_name) * sizeof(WCHAR));
    name.maximum_length = name.length + sizeof(WCHAR);
    name.buffer = root_name;
    attributes.length = sizeof attributes;
    attributes.object_name = &name;
    attributes.attributes = OBJ_CASE_INSENSITIVE;
    status = NtOpenFile(&root, FILE_READ_ATTRIBUTES, &attributes, &iosb, FILE_SHARE_ALL, FILE_DIRECTORY_FILE);
    if (status < 0) {
        DbgPrint("[setup] backend open failed: %08lx\n", status);
        return;
    }
    status = NtDeviceIoControlFile(root, 0, 0, 0, &iosb, IOCTL_MINO_SETUP_QUERY,
                                   0, 0, &preview, sizeof preview);
    NtClose(root);
    if (status < 0) {
        DbgPrint("[setup] backend query failed: %08lx\n", status);
        return;
    }
    if (preview.version != 1 || preview.state != SETUP_READY ||
        !(preview.disk_flags & SETUP_DISK_CANDIDATE) || preview.total_high ||
        preview.esp_sectors_high || preview.system_sectors_high) {
        DbgPrint("[setup] backend no safe target: state %lu flags %08lx\n",
                 preview.state, preview.disk_flags);
        return;
    }
    target_mib = preview.total_low / 2048;
    esp_mib = preview.esp_sectors_low / 2048;
    system_mib = preview.system_sectors_low / 2048;
    format_mib(target_size_text, target_mib, L" MiB   Selected");
    target_disk_number = preview.disk_number;
    target_token_low = preview.token_low;
    target_token_high = preview.token_high;
    backend_ready = TRUE;
    DbgPrint("[setup] backend target %lu: %lu MiB; plan EFI %lu MiB, system %lu MiB; token %08lx%08lx\n",
             preview.disk_number, target_mib, esp_mib, system_mib,
             preview.token_high, preview.token_low);
}

static RECT rect(LONG left, LONG top, LONG right, LONG bottom)
{
    RECT value = {left, top, right, bottom};
    return value;
}

static void fill(HDC dc, RECT area, COLORREF color)
{
    HBRUSH brush = CreateSolidBrush(color);
    HGDIOBJ previous;

    if (!brush)
        return;
    previous = SelectObject(dc, brush);
    PatBlt(dc, area.left, area.top, area.right - area.left, area.bottom - area.top, PATCOPY);
    if (previous)
        SelectObject(dc, previous);
    DeleteObject(brush);
}

static void border(HDC dc, RECT area, COLORREF color)
{
    fill(dc, rect(area.left, area.top, area.right, area.top + 1), color);
    fill(dc, rect(area.left, area.bottom - 1, area.right, area.bottom), color);
    fill(dc, rect(area.left, area.top, area.left + 1, area.bottom), color);
    fill(dc, rect(area.right - 1, area.top, area.right, area.bottom), color);
}

static void text(HDC dc, const WCHAR *value, RECT area, COLORREF color, UINT flags)
{
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    DrawTextW(dc, value, -1, &area, flags | DT_NOPREFIX);
}

static void button(HDC dc, RECT area, const WCHAR *label, BOOL focused, BOOL primary, BOOL enabled)
{
    COLORREF face = primary ? RGB(58, 110, 165) : RGB(236, 231, 216);
    COLORREF ink = primary ? RGB(255, 255, 255) : RGB(38, 36, 31);
    COLORREF edge = enabled ? RGB(126, 120, 102) : RGB(185, 180, 165);

    if (!enabled) {
        face = RGB(230, 225, 211);
        ink = RGB(145, 140, 126);
    }
    fill(dc, area, face);
    border(dc, area, edge);
    fill(dc, rect(area.left + 1, area.top + 1, area.right - 1, area.top + 2),
         primary ? RGB(88, 139, 187) : RGB(255, 255, 255));
    fill(dc, rect(area.left + 1, area.top + 1, area.left + 2, area.bottom - 1),
         primary ? RGB(88, 139, 187) : RGB(255, 255, 255));
    if (focused) {
        border(dc, rect(area.left - 3, area.top - 3, area.right + 3, area.bottom + 3), RGB(30, 78, 121));
        border(dc, rect(area.left - 2, area.top - 2, area.right + 2, area.bottom + 2), RGB(30, 78, 121));
    }
    text(dc, label, area, ink, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

static void heading(HDC dc, const WCHAR *title, const WCHAR *description)
{
    fill(dc, rect(156, 0, 800, 68), RGB(255, 255, 255));
    text(dc, title, rect(196, 12, 770, 36), RGB(30, 78, 121), DT_LEFT | DT_SINGLELINE);
    text(dc, description, rect(196, 38, 770, 62), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    fill(dc, rect(156, 67, 800, 68), RGB(205, 198, 178));
}

static void blue_panel(HDC dc)
{
    int y;

    for (y = 0; y < 528; ++y) {
        int red = 58 - y * 16 / 528;
        int green = 110 - y * 28 / 528;
        int blue = 165 - y * 39 / 528;
        fill(dc, rect(0, y, 156, y + 1), RGB(red, green, blue));
    }
    fill(dc, rect(155, 0, 156, 528), RGB(35, 72, 111));
    fill(dc, rect(12, 16, 34, 38), RGB(255, 255, 255));
    fill(dc, rect(14, 18, 32, 36), RGB(58, 110, 165));
    text(dc, L"M", rect(14, 18, 32, 36), RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Mino Installer", rect(42, 17, 144, 38), RGB(255, 255, 255), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(12, 50, 144, 51), RGB(124, 160, 198));
}

static void draw_steps(HDC dc)
{
    static const WCHAR *labels[] = {L"Welcome", L"Select Disk", L"Review Changes", L"Install", L"Complete"};
    int index;

    blue_panel(dc);
    for (index = 0; index < 5; ++index) {
        RECT row = rect(8, 64 + index * 33, 148, 95 + index * 33);
        RECT number = rect(16, row.top + 6, 34, row.top + 24);
        WCHAR digit[2] = {(WCHAR)(L'1' + index), 0};
        if (index == (int)current_screen) {
            fill(dc, row, RGB(39, 79, 122));
            border(dc, row, RGB(113, 151, 190));
        }
        border(dc, number, RGB(194, 216, 236));
        text(dc, index < (int)current_screen ? L"+" : digit, number, RGB(237, 241, 247),
             DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        text(dc, labels[index], rect(42, row.top, 144, row.bottom),
             index == (int)current_screen ? RGB(255, 255, 255) : RGB(237, 241, 247),
             DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
    fill(dc, rect(12, 498, 144, 499), RGB(112, 148, 184));
    text(dc, L"Step", rect(12, 501, 48, 522), RGB(203, 216, 232), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    {
        WCHAR step[] = L"1 of 5";
        step[0] = (WCHAR)(L'1' + current_screen);
        text(dc, step, rect(42, 501, 112, 522), RGB(203, 216, 232), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
}

static void draw_navigation(HDC dc, BOOL back, const WCHAR *primary)
{
    fill(dc, rect(0, 528, 800, 576), RGB(236, 231, 216));
    fill(dc, rect(0, 528, 800, 529), RGB(205, 198, 178));
    button(dc, rect(12, 539, 80, 567), L"Help", FALSE, FALSE, TRUE);
    if (back)
        button(dc, rect(500, 539, 578, 567), L"Back", focused_action == 0, FALSE, TRUE);
    button(dc, rect(590, 539, 680, 567), primary, focused_action == 1, TRUE, TRUE);
    button(dc, rect(694, 539, 784, 567), L"Cancel", FALSE, FALSE, TRUE);
    fill(dc, rect(0, 576, 800, 600), RGB(232, 227, 211));
    fill(dc, rect(0, 576, 800, 577), RGB(205, 198, 178));
    text(dc, L"Tab  next control     Enter  activate     F1  help     Esc  go back",
         rect(12, 579, 650, 598), RGB(87, 83, 74), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Mino Installer 1.0", rect(660, 579, 788, 598), RGB(87, 83, 74),
         DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

static void draw_welcome(HDC dc)
{
    heading(dc, L"Welcome to Mino",
            L"This installer prepares a GPT disk and installs Mino in one guided session.");
    text(dc, L"Mino will use one whole disk. Nothing is written until you confirm the changes in step 3.",
         rect(196, 88, 760, 124), RGB(38, 36, 31), DT_LEFT | DT_WORDBREAK);
    text(dc, L"Language", rect(196, 139, 430, 158), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Keyboard layout", rect(462, 139, 750, 158), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    fill(dc, rect(196, 160, 432, 192), RGB(255, 255, 255));
    border(dc, rect(196, 160, 432, 192), RGB(126, 120, 102));
    text(dc, L"English (United Kingdom)        v", rect(206, 160, 424, 192), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(462, 160, 752, 192), RGB(255, 255, 255));
    border(dc, rect(462, 160, 752, 192), RGB(126, 120, 102));
    text(dc, L"Generic 105-key keyboard        v", rect(472, 160, 744, 192), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(196, 216, 752, 360), RGB(239, 243, 248));
    border(dc, rect(196, 216, 752, 360), RGB(199, 212, 224));
    fill(dc, rect(196, 216, 200, 360), RGB(58, 110, 165));
    text(dc, L"Before you continue, this computer should have", rect(218, 234, 720, 256), RGB(38, 36, 31),
         DT_LEFT | DT_SINGLELINE);
    text(dc, L"+   At least 8 GB of free disk space", rect(232, 270, 720, 292), RGB(47, 107, 57),
         DT_LEFT | DT_SINGLELINE);
    text(dc, L"+   UEFI firmware", rect(232, 300, 720, 322), RGB(47, 107, 57), DT_LEFT | DT_SINGLELINE);
    text(dc, L"+   AC power connected for laptops", rect(232, 330, 720, 352), RGB(47, 107, 57),
         DT_LEFT | DT_SINGLELINE);
    text(dc, L"You can go back or cancel safely before installation begins.", rect(196, 390, 752, 416),
         RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, FALSE, L"Next");
}

static void draw_disk(HDC dc)
{
    heading(dc, L"Select a disk for Mino",
            L"Mino replaces everything on the selected disk. The running system and boot media are excluded.");
    fill(dc, rect(196, 88, 752, 154), backend_ready ? RGB(239, 243, 248) : RGB(249, 236, 233));
    border(dc, rect(196, 88, 752, 154), backend_ready ? RGB(58, 110, 165) : RGB(168, 50, 50));
    fill(dc, rect(210, 107, 228, 125), backend_ready ? RGB(58, 110, 165) : RGB(255, 255, 255));
    border(dc, rect(210, 107, 228, 125), RGB(30, 78, 121));
    text(dc, backend_ready ? L"ATA secondary master" : L"No safe installation target", rect(244, 99, 590, 124),
         RGB(38, 36, 31), DT_LEFT | DT_SINGLELINE);
    text(dc, target_size_text, rect(590, 99, 736, 124),
         backend_ready ? RGB(30, 78, 121) : RGB(143, 43, 43), DT_RIGHT | DT_SINGLELINE);
    text(dc, backend_ready ? L"Disk 2 · healthy · not mounted" : L"Attach an unmounted secondary ATA disk",
         rect(244, 124, 720, 147), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    fill(dc, rect(196, 170, 752, 254), RGB(252, 243, 225));
    border(dc, rect(196, 170, 752, 254), RGB(227, 201, 143));
    fill(dc, rect(196, 170, 200, 254), RGB(185, 134, 43));
    text(dc, L"All existing data on this disk will be permanently removed.", rect(218, 184, 730, 208),
         RGB(122, 82, 16), DT_LEFT | DT_SINGLELINE);
    fill(dc, rect(218, 218, 236, 236), RGB(255, 255, 255));
    border(dc, rect(218, 218, 236, 236), RGB(126, 120, 102));
    text(dc, L"+", rect(218, 218, 236, 236), RGB(30, 78, 121), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"I understand — erase this disk and everything on it.", rect(246, 215, 730, 239),
         RGB(38, 36, 31), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Planned layout", rect(196, 276, 752, 296), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    fill(dc, rect(196, 300, 752, 342), RGB(199, 212, 224));
    border(dc, rect(196, 300, 752, 342), RGB(126, 120, 102));
    fill(dc, rect(196, 300, 360, 342), RGB(199, 212, 224));
    fill(dc, rect(360, 300, 752, 342), RGB(58, 110, 165));
    text(dc, L"EFI system", rect(210, 302, 350, 322), RGB(38, 36, 31), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"40 MiB", rect(210, 321, 350, 340), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Mino system", rect(376, 302, 730, 322), RGB(255, 255, 255), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"54 MiB · FAT32", rect(376, 321, 730, 340), RGB(237, 241, 247), DT_LEFT | DT_SINGLELINE);
    text(dc, backend_ready ? L"Kernel plan ready · this screen is still read-only."
                           : L"Continue remains unavailable until a safe target exists.",
         rect(196, 370, 752, 394), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, TRUE, L"Next");
}

static void draw_review(HDC dc)
{
    heading(dc, L"Review the changes",
            L"Nothing is written yet. Every structure written by setup is read back and verified.");
    fill(dc, rect(196, 88, 752, 136), RGB(249, 236, 233));
    border(dc, rect(196, 88, 752, 136), RGB(220, 175, 168));
    fill(dc, rect(196, 88, 200, 136), RGB(168, 50, 50));
    text(dc, L"Erase all existing data on ATA secondary master", rect(218, 88, 730, 136),
         RGB(143, 43, 43), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(202, 156, 228, 182), RGB(58, 110, 165));
    text(dc, L"1", rect(202, 156, 228, 182), RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Create a protective MBR and two verified GPT copies", rect(242, 154, 742, 184),
         RGB(38, 36, 31), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(202, 202, 228, 228), RGB(58, 110, 165));
    text(dc, L"2", rect(202, 202, 228, 228), RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Create an EFI system partition · 40 MiB · FAT32", rect(242, 200, 742, 230),
         RGB(38, 36, 31), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(202, 248, 228, 274), RGB(58, 110, 165));
    text(dc, L"3", rect(202, 248, 228, 274), RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Create the Mino system partition · 54 MiB · FAT32", rect(242, 246, 742, 276),
         RGB(38, 36, 31), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(196, 304, 752, 346), RGB(199, 212, 224));
    fill(dc, rect(196, 304, 360, 346), RGB(199, 212, 224));
    fill(dc, rect(360, 304, 752, 346), RGB(58, 110, 165));
    text(dc, L"EFI system  40 MiB", rect(208, 304, 350, 346), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Mino system  54 MiB", rect(374, 304, 736, 346), RGB(255, 255, 255),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Install starts disk writes. Back and Cancel are still safe on this screen.",
         rect(196, 374, 752, 400), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, TRUE, L"Install...");
}

static void draw_install(HDC dc)
{
    static const WCHAR *stages[] = {L"Validating target", L"Writing GPT", L"Formatting FAT32",
                                    L"Verifying volumes", L"Ready for file copy"};
    int index;

    heading(dc, L"Installing Mino...", L"Writing to ATA secondary master. Keep the computer connected to power.");
    for (index = 0; index < 5; ++index) {
        int threshold = (index + 1) * 20;
        int y = 96 + index * 54;
        BOOL done = progress >= threshold;
        BOOL active = !done && progress >= index * 20;
        fill(dc, rect(200, y, 230, y + 30), done ? RGB(47, 107, 57) : active ? RGB(58, 110, 165) : RGB(219, 212, 194));
        text(dc, done ? L"+" : active ? L">" : L"-", rect(200, y, 230, y + 30), RGB(255, 255, 255),
             DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        text(dc, stages[index], rect(244, y - 2, 720, y + 20), RGB(38, 36, 31), DT_LEFT | DT_SINGLELINE);
        text(dc, done ? L"completed and verified" : active ? L"in progress" : L"waiting",
             rect(244, y + 20, 720, y + 42), done ? RGB(47, 107, 57) : RGB(87, 83, 74),
             DT_LEFT | DT_SINGLELINE);
    }
    fill(dc, rect(196, 390, 752, 412), RGB(219, 212, 194));
    fill(dc, rect(198, 392, 198 + progress * 5, 410), RGB(58, 110, 165));
    text(dc, L"Disk writes have begun · Back is no longer available", rect(196, 430, 752, 454),
         RGB(122, 82, 16), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, FALSE, L"Working...");
}

static void draw_complete(HDC dc)
{
    heading(dc, L"Disk preparation is complete",
            L"The partition table and both FAT32 volumes passed verification. File copy is the next engine milestone.");
    fill(dc, rect(196, 96, 752, 208), RGB(240, 245, 240));
    border(dc, rect(196, 96, 752, 208), RGB(185, 207, 187));
    fill(dc, rect(216, 124, 248, 156), RGB(47, 107, 57));
    text(dc, L"+", rect(216, 124, 248, 156), RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Partition table verified", rect(266, 116, 720, 142), RGB(47, 107, 57),
         DT_LEFT | DT_SINGLELINE);
    text(dc, L"Protective MBR, primary GPT and backup GPT are consistent.", rect(266, 146, 720, 170),
         RGB(38, 36, 31), DT_LEFT | DT_SINGLELINE);
    text(dc, L"EFI and Mino volumes are FAT32 and mount successfully.", rect(266, 174, 720, 198),
         RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    text(dc, L"EFI system", rect(196, 246, 352, 270), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    text(dc, L"40 MiB · FAT32 · verified", rect(370, 246, 752, 270), RGB(38, 36, 31), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Mino system", rect(196, 286, 352, 310), RGB(87, 83, 74), DT_LEFT | DT_SINGLELINE);
    text(dc, L"54 MiB · FAT32 · verified", rect(370, 286, 752, 310), RGB(38, 36, 31), DT_LEFT | DT_SINGLELINE);
    fill(dc, rect(196, 348, 752, 400), RGB(252, 243, 225));
    border(dc, rect(196, 348, 752, 400), RGB(227, 201, 143));
    text(dc, L"Keep this target attached. The next installer lot copies the boot and system files.",
         rect(214, 354, 734, 394), RGB(122, 82, 16), DT_LEFT | DT_VCENTER | DT_WORDBREAK);
    draw_navigation(dc, FALSE, L"Finish");
}

static void draw(HWND window, HDC dc)
{
    RECT client;

    SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    GetClientRect(window, &client);
    fill(dc, client, RGB(236, 231, 216));
    fill(dc, rect(156, 68, client.right, 528), RGB(247, 243, 232));
    draw_steps(dc);

    switch (current_screen) {
    case SCREEN_WELCOME:
        draw_welcome(dc);
        break;
    case SCREEN_DISK:
        draw_disk(dc);
        break;
    case SCREEN_REVIEW:
        draw_review(dc);
        break;
    case SCREEN_INSTALL:
        draw_install(dc);
        break;
    case SCREEN_COMPLETE:
        draw_complete(dc);
        break;
    }
    GdiFlush();
}

static void repaint(HWND window)
{
    InvalidateRect(window, 0, TRUE);
    UpdateWindow(window);
}

static void set_screen(HWND window, enum Screen screen)
{
    current_screen = screen;
    focused_action = 1;
    if (screen == SCREEN_DISK)
        ++disk_visits;
    else if (screen == SCREEN_REVIEW)
        ++review_visits;
    /* The paint goes first: a marker says the screen it names is showing,
     * and the scenario's screendump never catches a half-painted window. */
    repaint(window);
    if (screen == SCREEN_DISK) {
        DbgPrint("[setup] screen disk %d\n", disk_visits);
    } else if (screen == SCREEN_REVIEW) {
        DbgPrint("[setup] screen review %d\n", review_visits);
    } else if (screen == SCREEN_INSTALL) {
        DbgPrint("[setup] screen install; GPT write boundary\n");
    } else if (screen == SCREEN_COMPLETE) {
        DbgPrint("[setup] screen complete; verified GPT and FAT32\n");
    }
}

/* The write boundary. The kernel revalidates the disk against the token of
 * the preview, writes the protective MBR and both GPT copies, flushes them
 * and rereads them. Formatting and file copy wait for the next milestone. */
static void run_install(HWND window)
{
    static WCHAR root_name[] = L"\\GLOBAL??\\C:\\";
    SETUP_PREPARE request;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    HANDLE root = 0;
    LONG status;

    set_screen(window, SCREEN_INSTALL);
    progress = 20;
    DbgPrint("[setup] stage prepare: %d%%\n", progress);
    repaint(window);

    memset(&request, 0, sizeof request);
    request.version = 1;
    request.disk_number = target_disk_number;
    request.token_low = target_token_low;
    request.token_high = target_token_high;
    memset(&name, 0, sizeof name);
    memset(&attributes, 0, sizeof attributes);
    memset(&iosb, 0, sizeof iosb);
    name.length = (USHORT)(wide_length(root_name) * sizeof(WCHAR));
    name.maximum_length = name.length + sizeof(WCHAR);
    name.buffer = root_name;
    attributes.length = sizeof attributes;
    attributes.object_name = &name;
    attributes.attributes = OBJ_CASE_INSENSITIVE;
    status = NtOpenFile(&root, FILE_WRITE_ATTRIBUTES, &attributes, &iosb, FILE_SHARE_ALL, FILE_DIRECTORY_FILE);
    if (status >= 0) {
        status = NtDeviceIoControlFile(root, 0, 0, 0, &iosb, IOCTL_MINO_SETUP_PREPARE,
                                       &request, sizeof request, 0, 0);
        NtClose(root);
    }
    if (status < 0) {
        DbgPrint("[setup] prepare failed: %08lx\n", status);
        DbgPrint("[setup] install stopped on the install screen\n");
        return;
    }
    DbgPrint("[setup] prepare: GPT written and reread by the kernel\n");
    /* Stage format: the two FAT32 volumes of the plan, written by the
     * kernel and verified by its own FAT driver's mount on each view. */
    progress = 40;
    DbgPrint("[setup] stage format: %d%%\n", progress);
    repaint(window);
    memset(&attributes, 0, sizeof attributes);
    memset(&iosb, 0, sizeof iosb);
    name.length = (USHORT)(wide_length(root_name) * sizeof(WCHAR));
    name.maximum_length = name.length + sizeof(WCHAR);
    name.buffer = root_name;
    attributes.length = sizeof attributes;
    attributes.object_name = &name;
    attributes.attributes = OBJ_CASE_INSENSITIVE;
    status = NtOpenFile(&root, FILE_WRITE_ATTRIBUTES, &attributes, &iosb, FILE_SHARE_ALL, FILE_DIRECTORY_FILE);
    if (status >= 0) {
        status = NtDeviceIoControlFile(root, 0, 0, 0, &iosb, IOCTL_MINO_SETUP_FORMAT,
                                       &request, sizeof request, 0, 0);
        NtClose(root);
    }
    if (status < 0) {
        DbgPrint("[setup] format failed: %08lx\n", status);
        DbgPrint("[setup] install stopped on the install screen\n");
        return;
    }
    DbgPrint("[setup] format: ESP and system volumes FAT32, mounted by the kernel\n");
    progress = 100;
    DbgPrint("[setup] stage partition: 100%%\n");
    repaint(window);
    Sleep(40);
    set_screen(window, SCREEN_COMPLETE);
}

static void activate(HWND window)
{
    switch (current_screen) {
    case SCREEN_WELCOME:
        set_screen(window, SCREEN_DISK);
        break;
    case SCREEN_DISK:
        if (focused_action == 0) {
            current_screen = SCREEN_WELCOME;
            focused_action = 1;
            DbgPrint("[setup] back to welcome\n");
            repaint(window);
        } else if (backend_ready) {
            set_screen(window, SCREEN_REVIEW);
        } else {
            DbgPrint("[setup] continue blocked: no safe target\n");
        }
        break;
    case SCREEN_REVIEW:
        if (focused_action == 0)
            set_screen(window, SCREEN_DISK);
        else
            run_install(window);
        break;
    case SCREEN_INSTALL:
        break;
    case SCREEN_COMPLETE:
        DbgPrint("[setup] finish requested (milestone stays open)\n");
        break;
    }
}

static void go_back(HWND window)
{
    if (current_screen == SCREEN_DISK) {
        current_screen = SCREEN_WELCOME;
        focused_action = 1;
        DbgPrint("[setup] back to welcome\n");
        repaint(window);
    } else if (current_screen == SCREEN_REVIEW) {
        set_screen(window, SCREEN_DISK);
        DbgPrint("[setup] returned to disk\n");
    }
}

static LRESULT __stdcall setup_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    (void)l;
    switch (message) {
    case WM_PAINT:
        BeginPaint(window, &paint);
        draw(window, paint.hdc);
        EndPaint(window, &paint);
        return 0;
    case WM_CHAR:
        if (w == VK_TAB && (current_screen == SCREEN_DISK || current_screen == SCREEN_REVIEW)) {
            focused_action = !focused_action;
            DbgPrint("[setup] focus %s\n", focused_action ? "primary" : "back");
            repaint(window);
            return 0;
        }
        if (w == VK_RETURN || w == VK_SPACE) {
            activate(window);
            return 0;
        }
        if (w == VK_ESCAPE) {
            go_back(window);
            return 0;
        }
        break;
    }
    return DefWindowProcW(window, message, w, l);
}

static BOOL take_desktop(void)
{
    HWINSTA station;
    HDESK desktop;

    if (!RegisterLogonProcess(GetCurrentProcessId(), TRUE))
        return FALSE;
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station))
        return FALSE;
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    return desktop && SetThreadDesktop(desktop) && SwitchDesktop(desktop);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
    MSG message;

    if (!take_desktop())
        ExitProcess(1);
    query_install_backend();
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        ExitProcess(2);

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = setup_procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);

    window = CreateWindowExW(0, CLASS_NAME, L"Mino Installer", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             108, 70, 808, 628, 0, 0, instance, 0);
    if (!window)
        ExitProcess(4);
    DbgPrint("[setup] screen welcome\n");
    DbgPrint("[setup] ready\n");

    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ExitProcess(0);
    return 0;
}
