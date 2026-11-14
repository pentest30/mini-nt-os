/* Original Win32 application probes. Built with the MinGW public headers,
   without a C runtime; applications themselves are the pinned ReactOS binaries. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *, ...);
__declspec(dllimport) BOOL WINAPI RegisterLogonProcess(DWORD, BOOL);

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *p = destination;
    while (count--) *p++ = (unsigned char)value;
    return destination;
}
static inline void app_check(BOOL ok, const char *where)
{
    if (!ok) {
        DbgPrint("[apps] FAIL: %s (error %lu)\n", where, GetLastError());
        ExitProcess(1);
    }
}
static inline void app_desktop(void)
{
    app_check(RegisterLogonProcess(GetCurrentProcessId(), TRUE), "logon process");
    HWINSTA station=CreateWindowStationW(L"WinSta0",0,MAXIMUM_ALLOWED,0);
    app_check(station && SetProcessWindowStation(station), "window station");
    HDESK desktop=CreateDesktopW(L"Default",0,0,0,MAXIMUM_ALLOWED,0);
    app_check(desktop && SetThreadDesktop(desktop) && SwitchDesktop(desktop), "desktop");
    app_check(LoadKeyboardLayoutW(L"00000409",KLF_ACTIVATE)!=0, "keyboard layout");
}
static inline PROCESS_INFORMATION app_start(const WCHAR *path, WCHAR *command)
{
    STARTUPINFOW startup={0}; PROCESS_INFORMATION process={0};
    startup.cb=sizeof(startup); startup.lpDesktop=L"WinSta0\\Default";
    app_check(CreateProcessW(path,command,0,0,FALSE,0,0,L"C:\\",&startup,&process), "CreateProcessW");
    return process;
}
struct app_find { DWORD pid; const WCHAR *title; HWND window; };
static BOOL CALLBACK app_find_window(HWND window, LPARAM argument)
{
    struct app_find *find=(struct app_find *)argument;
    DWORD pid=0; WCHAR title[128];
    GetWindowThreadProcessId(window,&pid);
    if(pid!=find->pid) return TRUE;
    GetWindowTextW(window,title,128);
    unsigned int i=0;
    while(title[i] && title[i]==find->title[i]) ++i;
    if(title[i]==find->title[i]) {find->window=window;return FALSE;}
    return TRUE;
}
static inline HWND app_window(DWORD pid, const WCHAR *title)
{
    struct app_find find={pid,title,0}; EnumWindows(app_find_window,(LPARAM)&find); return find.window;
}
static inline void app_alive(const PROCESS_INFORMATION *process)
{
    DWORD code=0;
    if(WaitForSingleObject(process->hProcess,0)!=WAIT_TIMEOUT) {
        GetExitCodeProcess(process->hProcess,&code);
        DbgPrint("[apps] unexpected process exit: %08lx\n",code);
        app_check(FALSE,"application exited early");
    }
}
static inline HWND app_wait_window(const PROCESS_INFORMATION *process, const WCHAR *title)
{
    for(unsigned int n=0;n<240;++n) {
        HWND window=app_window(process->dwProcessId,title);
        if(window) return window;
        app_alive(process); Sleep(50);
    }
    app_check(FALSE,"window timed out");return 0;
}
/* The file view of a file dialog (comdlg32 with shell32's view): the shell
   view window has comdlg32's control id lst2, its list view the id 1. Waits
   until the list view of `dialog` lists something, its process alive, and
   returns how many items: shell32 fills it before the dialog takes messages
   (CDefView::FillList), so the first count is the whole folder. Without
   GetIconInfo the icon cache of shell32 failed and retried forever; without
   the SendMessage result of a missing header the view asserted. */
#define APP_LST2 0x0461
#define APP_LVM_GETITEMCOUNT 0x1004
static inline int app_file_view_count(HWND dialog)
{
    HWND list=GetDlgItem(GetDlgItem(dialog,APP_LST2),1);
    return list ? (int)SendMessageW(list,APP_LVM_GETITEMCOUNT,0,0) : 0;
}
static inline int app_file_view(const PROCESS_INFORMATION *process, HWND dialog)
{
    for(unsigned int n=0;n<240;++n) {
        int count=app_file_view_count(dialog);
        if(count>0) return count;
        app_alive(process); Sleep(50);
    }
    app_check(FALSE,"the file view lists nothing");return 0;
}
static inline void app_closed(PROCESS_INFORMATION *process)
{
    app_check(WaitForSingleObject(process->hProcess,5000)==WAIT_OBJECT_0,"close timed out");
    DWORD code=1; app_check(GetExitCodeProcess(process->hProcess,&code) && code==0,"clean application exit");
    CloseHandle(process->hThread);CloseHandle(process->hProcess);
}
