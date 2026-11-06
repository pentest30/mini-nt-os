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
#define FILE_SHARE_ALL 0x00000007
#define FILE_DIRECTORY_FILE 0x00000001
#define OBJ_CASE_INSENSITIVE 0x00000040
#define IOCTL_MINO_SETUP_QUERY 0x80006000
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
    COLORREF face = focused ? RGB(46, 96, 166) : RGB(224, 223, 216);
    COLORREF ink = focused ? RGB(255, 255, 255) : RGB(31, 35, 41);

    fill(dc, area, face);
    border(dc, area, focused ? RGB(24, 61, 111) : RGB(95, 99, 104));
    if (focused)
        border(dc, rect(area.left + 2, area.top + 2, area.right - 2, area.bottom - 2), RGB(255, 255, 255));
    text(dc, label, area, ink, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

static void heading(HDC dc, const WCHAR *title, const WCHAR *description)
{
    text(dc, title, rect(218, 90, 724, 122), RGB(24, 31, 40), DT_LEFT | DT_SINGLELINE);
    text(dc, description, rect(218, 128, 724, 176), RGB(72, 78, 86), DT_LEFT | DT_WORDBREAK);
}

static void draw_steps(HDC dc)
{
    static const WCHAR *labels[] = {L"1  Welcome", L"2  Disk", L"3  Review", L"4  Install", L"5  Complete"};
    int index;

    fill(dc, rect(0, 64, 190, 492), RGB(222, 225, 229));
    for (index = 0; index < 5; ++index) {
        RECT row = rect(18, 88 + index * 44, 172, 120 + index * 44);
        if (index == (int)current_screen)
            fill(dc, row, RGB(46, 96, 166));
        text(dc, labels[index], row,
             index == (int)current_screen ? RGB(255, 255, 255) : RGB(50, 56, 64),
             DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
}

static void draw_navigation(HDC dc, BOOL back, const WCHAR *primary)
{
    fill(dc, rect(190, 430, 752, 492), RGB(238, 237, 232));
    fill(dc, rect(190, 430, 752, 431), RGB(174, 174, 169));
    if (back)
        button(dc, rect(518, 446, 616, 478), L"Back", focused_action == 0);
    button(dc, rect(628, 446, 734, 478), primary, focused_action == 1);
}

static void draw_welcome(HDC dc)
{
    heading(dc, L"Welcome to Mino Setup",
            L"This installer prepares a GPT disk and installs Mino. You can review every change before disk writes begin.");
    fill(dc, rect(218, 196, 724, 310), RGB(244, 247, 251));
    border(dc, rect(218, 196, 724, 310), RGB(168, 180, 196));
    text(dc, L"Keyboard navigation", rect(238, 214, 690, 238), RGB(30, 60, 96), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Use Tab to move between actions, Enter or Space to activate, and Escape to go back.",
         rect(238, 246, 690, 292), RGB(55, 61, 69), DT_LEFT | DT_WORDBREAK);
    draw_navigation(dc, FALSE, L"Continue");
}

static void draw_disk(HDC dc)
{
    heading(dc, L"Select the installation disk",
            L"Guided setup will use the whole disk. The kernel excludes the running system and boot media.");
    fill(dc, rect(218, 190, 724, 272), RGB(248, 248, 246));
    border(dc, rect(218, 190, 724, 272), RGB(46, 96, 166));
    fill(dc, rect(218, 190, 224, 272), RGB(46, 96, 166));
    text(dc, backend_ready ? L"ATA secondary master" : L"No safe target", rect(244, 204, 520, 228),
         RGB(24, 31, 40), DT_LEFT | DT_SINGLELINE);
    text(dc, target_size_text, rect(540, 204, 700, 228),
         backend_ready ? RGB(46, 96, 166) : RGB(145, 42, 42), DT_LEFT | DT_SINGLELINE);
    fill(dc, rect(244, 240, 332, 254), RGB(103, 147, 203));
    fill(dc, rect(332, 240, 692, 254), RGB(74, 116, 174));
    text(dc, L"EFI System", rect(244, 278, 360, 302), RGB(65, 70, 76), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Mino System", rect(390, 278, 530, 302), RGB(65, 70, 76), DT_LEFT | DT_SINGLELINE);
    text(dc, backend_ready ? L"Read-only kernel plan ready; no write occurs on this screen."
                           : L"Connect an unmounted secondary ATA target to continue.",
         rect(218, 336, 724, 364), RGB(84, 89, 95), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, TRUE, L"Continue");
}

static void draw_review(HDC dc)
{
    heading(dc, L"Review disk changes",
            L"Confirm the target and partition plan. Installation begins only when you activate Install.");
    fill(dc, rect(218, 190, 724, 264), RGB(255, 246, 218));
    border(dc, rect(218, 190, 724, 264), RGB(181, 137, 38));
    text(dc, L"All existing data on the secondary ATA target will be removed.", rect(238, 208, 704, 244),
         RGB(91, 61, 8), DT_LEFT | DT_WORDBREAK);
    text(dc, L"Before", rect(218, 286, 320, 310), RGB(73, 78, 84), DT_LEFT | DT_SINGLELINE);
    text(dc, L"Existing disk contents", rect(344, 286, 704, 310), RGB(24, 31, 40), DT_LEFT | DT_SINGLELINE);
    text(dc, L"After", rect(218, 322, 320, 346), RGB(73, 78, 84), DT_LEFT | DT_SINGLELINE);
    text(dc, L"GPT + EFI System + Mino System", rect(344, 322, 704, 346), RGB(24, 31, 40), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, TRUE, L"Install");
}

static void draw_install(HDC dc)
{
    static const WCHAR *stages[] = {L"Prepare disk", L"Create partitions", L"Copy files", L"Configure system",
                                    L"Verify installation"};
    int index;

    heading(dc, L"Installing Mino", L"Keep the machine powered on while setup completes and verifies each stage.");
    for (index = 0; index < 5; ++index) {
        int threshold = (index + 1) * 20;
        RECT mark = rect(222, 196 + index * 36, 238, 212 + index * 36);
        fill(dc, mark, progress >= threshold ? RGB(46, 129, 82) : RGB(205, 207, 209));
        text(dc, stages[index], rect(250, 190 + index * 36, 650, 218 + index * 36), RGB(40, 45, 51),
             DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
    fill(dc, rect(218, 386, 724, 408), RGB(205, 207, 209));
    fill(dc, rect(220, 388, 220 + progress * 5, 406), RGB(46, 96, 166));
    text(dc, L"Installation in progress", rect(218, 414, 724, 438), RGB(72, 78, 86), DT_LEFT | DT_SINGLELINE);
}

static void draw_complete(HDC dc)
{
    heading(dc, L"Mino is ready",
            L"Setup verified the immutable kernel plan. The write engine remains disabled in this development milestone.");
    fill(dc, rect(218, 196, 724, 300), RGB(229, 244, 234));
    border(dc, rect(218, 196, 724, 300), RGB(63, 132, 86));
    fill(dc, rect(240, 220, 268, 248), RGB(46, 129, 82));
    text(dc, L"Verified", rect(286, 218, 690, 244), RGB(29, 91, 51), DT_LEFT | DT_SINGLELINE);
    text(dc, L"No physical disk was modified; only the target and plan were queried.", rect(286, 250, 690, 280),
         RGB(53, 72, 59), DT_LEFT | DT_SINGLELINE);
    draw_navigation(dc, FALSE, L"Restart");
}

static void draw(HWND window, HDC dc)
{
    RECT client;

    SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    GetClientRect(window, &client);
    fill(dc, client, RGB(246, 245, 241));
    fill(dc, rect(0, 0, client.right, 64), RGB(43, 82, 137));
    text(dc, L"MINO", rect(20, 14, 118, 50), RGB(255, 255, 255), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Setup", rect(122, 14, 300, 50), RGB(218, 230, 245), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    draw_steps(dc);
    fill(dc, rect(190, 64, client.right, 430), RGB(255, 255, 255));

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
    if (screen == SCREEN_DISK) {
        ++disk_visits;
        DbgPrint("[setup] screen disk %d\n", disk_visits);
    } else if (screen == SCREEN_REVIEW) {
        ++review_visits;
        DbgPrint("[setup] screen review %d\n", review_visits);
    } else if (screen == SCREEN_INSTALL) {
        DbgPrint("[setup] screen install; simulated write boundary\n");
    } else if (screen == SCREEN_COMPLETE) {
        DbgPrint("[setup] screen complete; verified simulation\n");
    }
    repaint(window);
}

static void simulate_install(HWND window)
{
    static const char *stages[] = {"prepare", "partition", "copy", "configure", "verify"};
    int index;

    set_screen(window, SCREEN_INSTALL);
    for (index = 0; index < 5; ++index) {
        progress = (index + 1) * 20;
        DbgPrint("[setup] stage %s: %d%%\n", stages[index], progress);
        repaint(window);
        Sleep(40);
    }
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
            simulate_install(window);
        break;
    case SCREEN_INSTALL:
        break;
    case SCREEN_COMPLETE:
        DbgPrint("[setup] restart requested (simulation stays open)\n");
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

    window = CreateWindowExW(0, CLASS_NAME, L"Mino Setup", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
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
