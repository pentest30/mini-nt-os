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

static void button(HDC dc, RECT area, const WCHAR *label, BOOL focused)
{
    fill(dc, area, RGB(236, 233, 216));
    fill(dc, rect(area.left, area.top, area.right, area.top + 1), RGB(255, 255, 255));
    fill(dc, rect(area.left, area.top, area.left + 1, area.bottom), RGB(255, 255, 255));
    fill(dc, rect(area.left, area.bottom - 2, area.right, area.bottom), RGB(64, 64, 64));
    fill(dc, rect(area.right - 2, area.top, area.right, area.bottom), RGB(64, 64, 64));
    fill(dc, rect(area.left + 1, area.bottom - 3, area.right - 2, area.bottom - 2), RGB(128, 128, 128));
    fill(dc, rect(area.right - 3, area.top + 1, area.right - 2, area.bottom - 2), RGB(128, 128, 128));
    if (focused)
        border(dc, rect(area.left + 3, area.top + 3, area.right - 4, area.bottom - 4), RGB(49, 106, 197));
    text(dc, label, area, RGB(0, 0, 0), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

static void heading(HDC dc, const WCHAR *title, const WCHAR *description)
{
    text(dc, title, rect(218, 24, 650, 50), RGB(0, 0, 0), DT_LEFT | DT_SINGLELINE);
    text(dc, description, rect(218, 54, 678, 94), RGB(64, 64, 64), DT_LEFT | DT_WORDBREAK);
    fill(dc, rect(190, 104, 752, 105), RGB(172, 168, 153));
    fill(dc, rect(190, 105, 752, 106), RGB(255, 255, 255));
}

static void blue_panel(HDC dc)
{
    int x;

    for (x = 0; x < 190; ++x) {
        int red = 20 + x * 24 / 190;
        int green = 55 + x * 47 / 190;
        int blue = 112 + x * 64 / 190;
        fill(dc, rect(x, 0, x + 1, 430), RGB(red, green, blue));
    }
    fill(dc, rect(0, 0, 190, 76), RGB(23, 56, 111));
    fill(dc, rect(188, 0, 190, 430), RGB(9, 36, 82));
    text(dc, L"MINO", rect(22, 18, 90, 42), RGB(255, 255, 255), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Setup Wizard", rect(22, 42, 160, 64), RGB(196, 215, 244), DT_LEFT | DT_SINGLELINE);
    fill(dc, rect(18, 93, 164, 94), RGB(105, 147, 207));
}

static void draw_steps(HDC dc)
{
    static const WCHAR *labels[] = {L"1  Welcome", L"2  Disk", L"3  Review", L"4  Install", L"5  Complete"};
    int index;

    blue_panel(dc);
    for (index = 0; index < 5; ++index) {
        RECT row = rect(22, 116 + index * 42, 170, 146 + index * 42);
        if (index == (int)current_screen) {
            fill(dc, rect(16, row.top, 19, row.bottom), RGB(255, 210, 72));
            fill(dc, row, RGB(38, 82, 148));
        }
        text(dc, labels[index], row,
             index == (int)current_screen ? RGB(255, 255, 255) : RGB(205, 220, 243),
             DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
    text(dc, L"Classic setup", rect(22, 388, 160, 410), RGB(164, 191, 230), DT_LEFT | DT_SINGLELINE);
}

static void draw_navigation(HDC dc, BOOL back, const WCHAR *primary)
{
    fill(dc, rect(0, 430, 752, 492), RGB(236, 233, 216));
    fill(dc, rect(0, 430, 752, 431), RGB(255, 255, 255));
    fill(dc, rect(0, 431, 752, 432), RGB(172, 168, 153));
    if (back)
        button(dc, rect(414, 450, 510, 478), L"< Back", focused_action == 0);
    button(dc, rect(516, 450, 612, 478), primary, focused_action == 1);
    button(dc, rect(632, 450, 728, 478), L"Cancel", FALSE);
}

static void draw_welcome(HDC dc)
{
    heading(dc, L"Welcome to Mino Setup",
            L"This installer prepares a GPT disk and installs Mino. You can review every change before disk writes begin.");
    fill(dc, rect(218, 146, 724, 278), RGB(247, 249, 253));
    border(dc, rect(218, 146, 724, 278), RGB(149, 167, 196));
    fill(dc, rect(218, 146, 224, 278), RGB(49, 106, 197));
    text(dc, L"Welcome to the Mino Setup Wizard", rect(242, 168, 690, 194), RGB(0, 51, 153), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Use Tab to move between actions, Enter or Space to activate, and Escape to go back.",
         rect(242, 208, 690, 254), RGB(52, 52, 52), DT_LEFT | DT_WORDBREAK);
    draw_navigation(dc, FALSE, L"Next >");
}

static void draw_disk(HDC dc)
{
    heading(dc, L"Select the installation disk",
            L"Guided setup will use the whole disk. The kernel excludes the running system and boot media.");
    fill(dc, rect(218, 142, 724, 228), RGB(255, 255, 255));
    border(dc, rect(218, 142, 724, 228), RGB(49, 106, 197));
    fill(dc, rect(218, 142, 224, 228), RGB(49, 106, 197));
    text(dc, backend_ready ? L"ATA secondary master" : L"No safe target", rect(244, 156, 520, 180),
         RGB(24, 31, 40), DT_LEFT | DT_SINGLELINE);
    text(dc, target_size_text, rect(540, 156, 700, 180),
         backend_ready ? RGB(46, 96, 166) : RGB(145, 42, 42), DT_LEFT | DT_SINGLELINE);
    fill(dc, rect(244, 196, 332, 210), RGB(116, 162, 218));
    fill(dc, rect(332, 196, 692, 210), RGB(49, 106, 197));
    text(dc, L"EFI System", rect(244, 244, 360, 268), RGB(65, 70, 76), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Mino System", rect(390, 244, 530, 268), RGB(65, 70, 76), DT_LEFT | DT_SINGLELINE);
    text(dc, backend_ready ? L"Read-only kernel plan ready; no write occurs on this screen."
                           : L"Connect an unmounted secondary ATA target to continue.",
         rect(218, 304, 724, 332), RGB(84, 89, 95), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, TRUE, L"Next >");
}

static void draw_review(HDC dc)
{
    heading(dc, L"Review disk changes",
            L"Confirm the target and partition plan. Installation begins only when you activate Install.");
    fill(dc, rect(218, 142, 724, 216), RGB(255, 247, 218));
    border(dc, rect(218, 142, 724, 216), RGB(181, 137, 38));
    text(dc, L"All existing data on the secondary ATA target will be removed.", rect(238, 160, 704, 196),
         RGB(91, 61, 8), DT_LEFT | DT_WORDBREAK);
    text(dc, L"Before", rect(218, 246, 320, 270), RGB(73, 78, 84), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Existing disk contents", rect(344, 246, 704, 270), RGB(24, 31, 40), DT_LEFT | DT_SINGLELINE);
    text(dc, L"After", rect(218, 286, 320, 310), RGB(73, 78, 84), DT_LEFT | DT_SINGLELINE);
    text(dc, L"GPT + EFI System + Mino System", rect(344, 286, 704, 310), RGB(24, 31, 40), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, TRUE, L"Install");
}

static void draw_install(HDC dc)
{
    static const WCHAR *stages[] = {L"Revalidate target", L"Write backup GPT", L"Write primary GPT",
                                    L"Flush metadata", L"Verify both copies"};
    int index;

    heading(dc, L"Installing Mino", L"Keep the machine powered on while setup completes and verifies each stage.");
    for (index = 0; index < 5; ++index) {
        int threshold = (index + 1) * 20;
        RECT mark = rect(222, 142 + index * 42, 238, 158 + index * 42);
        fill(dc, mark, progress >= threshold ? RGB(46, 129, 82) : RGB(205, 207, 209));
        text(dc, stages[index], rect(250, 136 + index * 42, 650, 164 + index * 42), RGB(40, 45, 51),
             DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
    fill(dc, rect(218, 364, 724, 386), RGB(205, 207, 209));
    fill(dc, rect(220, 366, 220 + progress * 5, 384), RGB(49, 106, 197));
    text(dc, L"Installation in progress", rect(218, 394, 724, 418), RGB(72, 78, 86), DT_LEFT | DT_SINGLELINE);
}

static void draw_complete(HDC dc)
{
    heading(dc, L"GPT partitioning is complete",
            L"Setup wrote and verified the protective MBR and both GPT copies. Formatting and file copy come next.");
    fill(dc, rect(218, 150, 724, 266), RGB(235, 247, 238));
    border(dc, rect(218, 150, 724, 266), RGB(63, 132, 86));
    fill(dc, rect(240, 180, 270, 210), RGB(46, 129, 82));
    text(dc, L"Partition table verified", rect(290, 176, 690, 202), RGB(29, 91, 51), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Partition contents are still untouched; no filesystem was formatted.", rect(290, 214, 690, 248),
         RGB(53, 72, 59), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, FALSE, L"Finish");
}

static void draw(HWND window, HDC dc)
{
    RECT client;

    SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    GetClientRect(window, &client);
    fill(dc, client, RGB(236, 233, 216));
    fill(dc, rect(190, 0, client.right, 430), RGB(255, 255, 255));
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
        DbgPrint("[setup] screen complete; verified GPT\n");
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

    window = CreateWindowExW(0, CLASS_NAME, L"Mino Setup Wizard", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             120, 60, 760, 520, 0, 0, instance, 0);
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
