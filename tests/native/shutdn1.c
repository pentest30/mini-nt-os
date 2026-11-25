/* A session that ends by shutting the system down, from a program of the
   session (M7, the second criterion): started by userinit as the shell of
   the logged-on user (a scenario's `session`), it shows a window, enables
   SeShutdownPrivilege in its token and asks ExitWindowsEx for a shutdown
   that powers the machine off. user32 hands it to csrss (winsrv's
   SrvExitWindowsEx), which asks win32k (NtUserSetInformationThread): the
   caller is not winlogon, so win32k posts WM_LOGONNOTIFY (LN_LOGOFF and the
   flags) to winlogon's SAS window and answers STATUS_PENDING. winlogon then
   logs the user off (its own ExitWindowsEx: winsrv sends WM_CLIENTSHUTDOWN
   to this window, which DefWindowProc turns into WM_QUERYENDSESSION, then
   WM_ENDSESSION, before csrss ends the process), and shuts the system down
   (NtShutdownSystem). The window says what it receives; while the system
   does not go down, the program says so every 10 s. */
#include "app_probe.h"

#define TAG "[shutdown] "

__declspec(dllimport) LONG NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

/* SE_SHUTDOWN_PRIVILEGE. */
#define SHUTDOWN_PRIVILEGE 19

static int seconds;

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_QUERYENDSESSION:
        DbgPrint(TAG "WM_QUERYENDSESSION, lParam %lx\n", (DWORD)lparam);
        return TRUE;
    case WM_ENDSESSION:
        DbgPrint(TAG "WM_ENDSESSION %u, lParam %lx\n", (unsigned)wparam, (DWORD)lparam);
        return 0;
    case WM_TIMER:
        seconds += 10;
        DbgPrint(TAG "still running after %d s\n", seconds);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

DWORD WINAPI GuiStartup(void)
{
    WNDCLASSW class = {0};
    class.lpfnWndProc = procedure;
    class.hInstance = GetModuleHandleW(0);
    class.lpszClassName = L"ShutdownProbe";
    RegisterClassW(&class);
    HWND window = CreateWindowExW(0, L"ShutdownProbe", L"Shutdown probe", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 40,
                                  320, 200, 0, 0, class.hInstance, 0);
    DbgPrint(TAG "in the session, a window: %d\n", window != 0);
    SetTimer(window, 1, 10000, 0);
    BOOLEAN was = FALSE;
    LONG status = RtlAdjustPrivilege(SHUTDOWN_PRIVILEGE, TRUE, FALSE, &was);
    DbgPrint(TAG "SeShutdownPrivilege enabled: %08lx (it was %d)\n", status, was);
    BOOL asked = ExitWindowsEx(EWX_SHUTDOWN | EWX_POWEROFF, 0);
    DbgPrint(TAG "ExitWindowsEx: %d (last error %lu)\n", asked, GetLastError());
    MSG message;
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint(TAG "the message loop ended\n");
    ExitProcess(0);
    return 0;
}
