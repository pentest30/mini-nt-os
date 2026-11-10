/*
 * The pre-installation choice shown before Mino Setup. It owns
 * WinSta0\Default like winlogon, then lets the user either start SETUP1.EXE
 * or enter the DESKTOP1.EXE live session without touching a disk.
 *
 * Built freestanding by xtask with theme.c; every pixel belongs to Mino's
 * original blue theme.
 */

#include "theme.h"

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

#define SW_HIDE 0
#define SW_SHOW 5
#define INFINITE 0xFFFFFFFF
#define KLF_ACTIVATE 0x00000001

static const WCHAR CLASS_NAME[] = L"MinoBootChoice";
static CANVAS canvas;
static int selected;

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line,
                                                    void *process_attributes, void *thread_attributes,
                                                    BOOL inherit_handles, DWORD flags, void *environment,
                                                    const WCHAR *directory, STARTUPINFOW *startup_info,
                                                    PROCESS_INFORMATION *information);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);

static void option_card(RECT area, const WCHAR *title, const WCHAR *description, BOOL active, BOOL install)
{
    PIXEL background = active ? PX(226, 239, 255) : C_WHITE;
    PIXEL border = active ? PX(38, 94, 196) : PX(170, 188, 220);
    PIXEL accent = active ? PX(35, 92, 202) : PX(132, 154, 196);
    int icon_x = area.left + 34;
    int icon_y = (area.top + area.bottom) / 2;

    card(&canvas, area, background, border, accent);
    if (install) {
        disc(&canvas, icon_x, icon_y, 19, PX(106, 174, 255), PX(30, 90, 214));
        line(&canvas, icon_x, icon_y - 10, icon_x, icon_y + 7, 3, C_WHITE);
        line(&canvas, icon_x - 7, icon_y + 1, icon_x, icon_y + 8, 3, C_WHITE);
        line(&canvas, icon_x + 7, icon_y + 1, icon_x, icon_y + 8, 3, C_WHITE);
    } else {
        round_fill(&canvas, rect(icon_x - 21, icon_y - 15, icon_x + 21, icon_y + 13), 3, CORNERS_ALL,
                   PX(228, 236, 250), PX(158, 180, 220));
        round_frame(&canvas, rect(icon_x - 21, icon_y - 15, icon_x + 21, icon_y + 13), 3, CORNERS_ALL,
                    PX(62, 86, 142));
        gradient(&canvas, rect(icon_x - 17, icon_y - 11, icon_x + 17, icon_y + 9), PX(80, 150, 250),
                 PX(20, 72, 184));
        fill(&canvas, rect(icon_x - 8, icon_y + 14, icon_x + 8, icon_y + 18), PX(104, 120, 154));
    }
    text(&canvas, title, rect(area.left + 72, area.top + 12, area.right - 20, area.top + 39), C_INK_BLUE,
         font(17, TRUE), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(&canvas, description, rect(area.left + 72, area.top + 39, area.right - 24, area.bottom - 10), C_INK_SOFT,
         font(11, FALSE), DT_LEFT | DT_VCENTER | DT_WORDBREAK);
    if (active)
        text(&canvas, L"Press Enter", rect(area.right - 130, area.top + 10, area.right - 18, area.top + 32),
             PX(30, 84, 184), font(10, TRUE), DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

static void draw(HDC target)
{
    static const STOP sky[] = {{0, PX(7, 35, 109)}, {118, PX(23, 78, 174)}, {256, PX(64, 128, 218)}};
    int width = canvas.width;
    int height = canvas.height;
    int panel_width = 650;
    int left = (width - panel_width) / 2;
    int top = height / 2 - 185;

    gradient_stops(&canvas, rect(0, 0, width, height), sky, 3);
    glow(&canvas, width / 2, height / 2, 540, PX(120, 184, 255), 58);
    emblem(&canvas, width / 2, top - 54, 38);
    text_shadow(&canvas, L"MinoOS", rect(left, top - 26, left + panel_width, top + 14), C_WHITE, font(28, TRUE),
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(&canvas, L"Choose how you want to start", rect(left, top + 10, left + panel_width, top + 42),
         PX(214, 232, 255), font(13, FALSE), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    option_card(rect(left, top + 58, left + panel_width, top + 144), L"Install MinoOS",
                L"Prepare a disk and install MinoOS on this computer.", selected == 0, TRUE);
    option_card(rect(left, top + 158, left + panel_width, top + 244), L"Try MinoOS",
                L"Start the desktop without installing or changing your disks.", selected == 1, FALSE);

    text(&canvas, L"Use Up and Down to choose, then press Enter",
         rect(left, top + 262, left + panel_width, top + 292), PX(220, 235, 255), font(11, FALSE),
         DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(&canvas, L"The live session keeps all disks unchanged",
         rect(left, height - 46, left + panel_width, height - 18), PX(180, 210, 250), font(10, FALSE),
         DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    canvas_present(&canvas, target);
}

static void repaint(HWND window)
{
    InvalidateRect(window, 0, FALSE);
    UpdateWindow(window);
}

static BOOL launch(HWND window, const WCHAR *program, const char *choice)
{
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;

    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    DbgPrint("[bootmenu] selected %s\n", choice);
    ShowWindow(window, SW_HIDE);
    if (!CreateProcessW(program, 0, 0, 0, FALSE, 0, 0, L"C:\\", &startup, &process)) {
        DbgPrint("[bootmenu] launch failed: %lu\n", GetLastError());
        ShowWindow(window, SW_SHOW);
        repaint(window);
        return FALSE;
    }
    DbgPrint("[bootmenu] child started\n");
    CloseHandle(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    CloseHandle(process.hProcess);
    DbgPrint("[bootmenu] child ended; menu restored\n");
    ShowWindow(window, SW_SHOW);
    repaint(window);
    return TRUE;
}

static LRESULT __stdcall boot_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    if (message == WM_ERASEBKGND)
        return 1;
    if (message == WM_PAINT) {
        BeginPaint(window, &paint);
        draw(paint.hdc);
        EndPaint(window, &paint);
        return 0;
    }
    if (message == WM_KEYDOWN && (w == VK_UP || w == VK_DOWN)) {
        selected = !selected;
        DbgPrint("[bootmenu] focus %s\n", selected ? "live" : "install");
        repaint(window);
        return 0;
    }
    if (message == WM_CHAR) {
        if (w == VK_TAB) {
            selected = !selected;
            DbgPrint("[bootmenu] focus %s\n", selected ? "live" : "install");
            repaint(window);
            return 0;
        }
        if (w == VK_RETURN || w == VK_SPACE) {
            if (selected)
                launch(window, L"C:\\DESKTOP1.EXE", "live");
            else
                launch(window, L"C:\\SETUP1.EXE", "install");
            return 0;
        }
    }
    return DefWindowProcW(window, message, w, l);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
    MSG message;
    int width;
    int height;

    if (!take_desktop())
        ExitProcess(1);
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        ExitProcess(2);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = boot_procedure;
    class_info.hInstance = instance;
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);
    width = GetSystemMetrics(SM_CXSCREEN);
    height = GetSystemMetrics(SM_CYSCREEN);
    if (!canvas_create(&canvas, width, height))
        ExitProcess(4);
    window = CreateWindowExW(0, CLASS_NAME, L"MinoOS startup", WS_POPUP | WS_VISIBLE, 0, 0, width, height, 0, 0,
                             instance, 0);
    if (!window)
        ExitProcess(5);
    UpdateWindow(window);
    DbgPrint("[bootmenu] ready; default install\n");
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ExitProcess(0);
    return 0;
}
