/* WH_CBT hooks at window creation (HCBT_CREATEWND), as MFC uses them: a Win32
   program (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's
   kernel32 and user32, which the scenario `cbt-hook` puts on the boot disk
   in the place of winlogon.exe. MFC sets a WH_CBT hook around each
   CreateWindowEx and CreateDialog: in HCBT_CREATEWND, it ties its CWnd to
   the new window and subclasses it, before any message. Without the call,
   a dialog-based MFC program (KeePass 1.x) showed its dialog but never ran
   its OnInitDialog: no accelerators, Close and Ctrl+N did nothing. As
   ReactOS (co_UserCreateWindowEx, co_IntCallHookProc):
   1. the hook gets the window (wParam) and a CBT_CREATEWND: the real style,
      the place and size given, the caller's name and class pointers; it
      subclasses the window, whose procedure then gets the first messages
      (WM_GETMINMAXINFO, WM_NCCREATE, WM_CREATE); the width it sets is the
      window's;
   2. a hook that returns non-zero refuses the window: CreateWindowEx gives
      NULL and the window is gone;
   3. two hooks: the last set is called first; CallNextHookEx calls the
      other with the CBT_CREATEWND changed by the first (a height), and
      gives what it returned;
   4. a dialog (CreateDialogIndirectParam): the hook sees class #32770 (the
      atom 0x8002) and subclasses it before WM_INITDIALOG;
   5. unhooked, the hook is not called.
   Each step goes to the debug port (DbgPrint); the program ends with 0.

   Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
   -nostdlib, entry point GuiStartup. */
#include "app_probe.h"

#define TAG "[cbt] "

static const WCHAR class_name[] = L"CbtTest";
static const WCHAR first_name[] = L"Cbt one";

/* What the hooks saw. */
static HWND seen_window;
static DWORD seen_style, seen_calls;
static int seen_x, seen_y, seen_cx, seen_cy, next_saw_cy;
static BOOL seen_name, seen_class, refuse;
static char order[8];
static unsigned int order_length;
static HHOOK first_hook, second_hook;
static LPCWSTR seen_class_pointer;

/* The subclass a hook gives: the messages it sees first. */
static WNDPROC old_proc;
static UINT first_message;
static BOOL saw_nccreate, saw_create, saw_initdialog;
static LRESULT CALLBACK subclass(HWND window, UINT message, WPARAM w_param, LPARAM l_param)
{
    if (!first_message) first_message = message;
    if (message == WM_NCCREATE) saw_nccreate = TRUE;
    if (message == WM_CREATE) saw_create = TRUE;
    if (message == WM_INITDIALOG) saw_initdialog = TRUE;
    return CallWindowProcW(old_proc, window, message, w_param, l_param);
}

static void note(char c)
{
    if (order_length < sizeof(order) - 1) order[order_length++] = c;
    order[order_length] = 0;
}

/* The first hook: records, subclasses, sets the width; refuses on demand. */
static LRESULT CALLBACK first(int code, WPARAM w_param, LPARAM l_param)
{
    if (code == HCBT_CREATEWND) {
        CBT_CREATEWNDW *create = (CBT_CREATEWNDW *)l_param;
        ++seen_calls;
        note('A');
        seen_window = (HWND)w_param;
        seen_style = create->lpcs->style;
        seen_x = create->lpcs->x;
        seen_y = create->lpcs->y;
        seen_cx = create->lpcs->cx;
        seen_cy = create->lpcs->cy;
        next_saw_cy = create->lpcs->cy;
        seen_name = create->lpcs->lpszName == first_name;
        seen_class = create->lpcs->lpszClass == class_name;
        seen_class_pointer = create->lpcs->lpszClass;
        first_message = 0;
        saw_nccreate = saw_create = saw_initdialog = FALSE;
        old_proc = (WNDPROC)SetWindowLongW((HWND)w_param, GWL_WNDPROC, (LONG)subclass);
        create->lpcs->cx = 321;
        if (refuse) return 1;
    }
    return CallNextHookEx(first_hook, code, w_param, l_param);
}

/* The second hook, set last: called first, it sets the height and calls
   the next. */
static LRESULT CALLBACK second(int code, WPARAM w_param, LPARAM l_param)
{
    if (code == HCBT_CREATEWND) {
        note('B');
        ((CBT_CREATEWNDW *)l_param)->lpcs->cy = 111;
        return CallNextHookEx(second_hook, code, w_param, l_param);
    }
    return CallNextHookEx(second_hook, code, w_param, l_param);
}

static INT_PTR CALLBACK dialog_proc(HWND dialog, UINT message, WPARAM w_param, LPARAM l_param)
{
    (void)dialog, (void)w_param, (void)l_param;
    return message == WM_INITDIALOG;
}

DWORD WINAPI GuiStartup(void)
{
    app_desktop();
    DbgPrint(TAG "on WinSta0\\Default\n");
    WNDCLASSW wc = {0};
    HINSTANCE module = GetModuleHandleW(0);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = module;
    wc.lpszClassName = class_name;
    app_check(RegisterClassW(&wc) != 0, "RegisterClassW");

    /* 1. HCBT_CREATEWND: what the hook sees, its subclass, its width. */
    first_hook = SetWindowsHookExW(WH_CBT, first, 0, GetCurrentThreadId());
    DbgPrint(TAG "WH_CBT set: %d\n", first_hook != 0);
    HWND window = CreateWindowExW(0, class_name, first_name, WS_OVERLAPPEDWINDOW, 10, 20, 300, 200, 0, 0, module, 0);
    DWORD error = window ? 0 : GetLastError();
    RECT rect = {0};
    GetWindowRect(window, &rect);
    DbgPrint(TAG "step 1: called %lu, the window %d, style %08lx, at %d,%d %dx%d, name %d, class %d; "
                 "subclassed: first message %x, WM_NCCREATE %d, WM_CREATE %d; width %ld (error %lu)\n",
             seen_calls, seen_window == window && window != 0, seen_style, seen_x, seen_y, seen_cx, seen_cy, seen_name,
             seen_class, first_message, saw_nccreate, saw_create, rect.right - rect.left, error);
    DestroyWindow(window);

    /* 2. Refused. */
    refuse = TRUE;
    seen_calls = 0;
    window = CreateWindowExW(0, class_name, L"Cbt refused", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, 0, 0, module, 0);
    DbgPrint(TAG "step 2: refused: called %lu, CreateWindowEx %d, the window gone %d\n", seen_calls, window != 0,
             seen_window != 0 && !IsWindow(seen_window));
    refuse = FALSE;

    /* 3. Two hooks, the last called first. */
    second_hook = SetWindowsHookExW(WH_CBT, second, 0, GetCurrentThreadId());
    order_length = 0;
    order[0] = 0;
    window = CreateWindowExW(0, class_name, first_name, WS_OVERLAPPEDWINDOW, 10, 20, 300, 200, 0, 0, module, 0);
    GetWindowRect(window, &rect);
    DbgPrint(TAG "step 3: two hooks: called %s, the next saw cy %d, the window %ldx%ld\n", order, next_saw_cy,
             rect.right - rect.left, rect.bottom - rect.top);
    DestroyWindow(window);
    UnhookWindowsHookEx(second_hook);

    /* 4. A dialog: #32770, subclassed before WM_INITDIALOG. */
    static WORD template_words[16] __attribute__((aligned(4)));
    DLGTEMPLATE *template = (DLGTEMPLATE *)template_words;
    template->style = WS_POPUP | WS_CAPTION | DS_MODALFRAME;
    template->cx = 120;
    template->cy = 60;
    /* No menu, the default class, no title: three zero words after it. */
    seen_calls = 0;
    HWND dialog = CreateDialogIndirectParamW(0, template, 0, dialog_proc, 0);
    DbgPrint(TAG "step 4: a dialog: called %lu, the window %d, class %lx, subclassed before WM_INITDIALOG %d\n",
             seen_calls, seen_window == dialog && dialog != 0, (DWORD)(ULONG_PTR)seen_class_pointer, saw_initdialog);
    DestroyWindow(dialog);

    /* 5. Unhooked. */
    BOOL unhooked = UnhookWindowsHookEx(first_hook);
    seen_calls = 0;
    window = CreateWindowExW(0, class_name, first_name, WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, 0, 0, module, 0);
    DbgPrint(TAG "step 5: unhooked %d: called %lu\n", unhooked, seen_calls);
    DestroyWindow(window);
    DbgPrint(TAG "done\n");
    ExitProcess(0);
    return 0;
}
