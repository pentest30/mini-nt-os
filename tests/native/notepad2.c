/* Save As through the actual ReactOS Notepad/comdlg32, followed by a fresh
   Notepad process reading the saved file. Only the application writes it. */
#include "app_probe.h"
static const WCHAR path[]=L"C:\\MINO-NOTE.TXT";
static const char expected[]="Hello, Mino!\r\nLine 2";
static BOOL saved(void)
{
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                            0,OPEN_EXISTING,0,0);
    if(file==INVALID_HANDLE_VALUE) return FALSE;
    char bytes[64];DWORD count=0;
    BOOL ok=ReadFile(file,bytes,sizeof(bytes),&count,0);CloseHandle(file);
    if(!ok || count!=sizeof(expected)-1) return FALSE;
    for(DWORD i=0;i<count;++i) if(bytes[i]!=expected[i]) return FALSE;
    return TRUE;
}
static WNDPROC previous_proc;
static LRESULT CALLBACK original_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    if(message==WM_APP+1) return 41;
    return DefWindowProcW(window,message,wparam,lparam);
}
static LRESULT CALLBACK replacement_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    return CallWindowProcW(previous_proc,window,message,wparam,lparam)+(message==WM_APP+1);
}
static void check_subclass(void)
{
    WNDCLASSEXW cls={0};cls.cbSize=sizeof(cls);cls.lpfnWndProc=original_proc;
    cls.hInstance=GetModuleHandleW(0);cls.lpszClassName=L"MinoSaveSubclass";
    app_check(RegisterClassExW(&cls)!=0,"register subclass probe");
    HWND window=CreateWindowExW(0,cls.lpszClassName,L"",0,0,0,0,0,0,0,cls.hInstance,0);
    app_check(window!=0,"create subclass probe");
    previous_proc=(WNDPROC)SetWindowLongW(window,GWL_WNDPROC,(LONG)replacement_proc);
    app_check(previous_proc==original_proc,"subclass returns previous procedure");
    app_check(SendMessageW(window,WM_APP+1,0,0)==42,"replacement delegates to previous procedure");
    app_check((WNDPROC)SetWindowLongW(window,GWL_WNDPROC,(LONG)previous_proc)==replacement_proc,"restore procedure");
    app_check(SendMessageW(window,WM_APP+1,0,0)==41,"restored procedure");
    app_check(DestroyWindow(window),"destroy subclass probe");
    cls.style=CS_NOCLOSE;cls.lpszClassName=L"MinoNoClose";
    app_check(RegisterClassExW(&cls)!=0,"register CS_NOCLOSE probe");
    window=CreateWindowExW(0,cls.lpszClassName,L"",0,0,0,0,0,0,0,cls.hInstance,0);
    app_check(window!=0,"create CS_NOCLOSE probe");
    SendMessageW(window,WM_SYSKEYDOWN,VK_F4,(1u<<29)|1);
    MSG message;
    app_check(!PeekMessageW(&message,window,WM_SYSCOMMAND,WM_SYSCOMMAND,PM_REMOVE),"Alt+F4 respects CS_NOCLOSE");
    app_check(DestroyWindow(window),"destroy CS_NOCLOSE probe");
    DbgPrint("[note-save] client procedure replaced and restored\n");
}
DWORD WINAPI GuiStartup(void)
{
    app_desktop();
    check_subclass();
    HANDLE absent=CreateFileW(path,GENERIC_READ,7,0,OPEN_EXISTING,0,0);
    app_check(absent==INVALID_HANDLE_VALUE && GetLastError()==ERROR_FILE_NOT_FOUND,"fresh file fixture");
    WCHAR command[]=L"notepad.exe";
    PROCESS_INFORMATION process=app_start(L"C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",command);
    HWND first=app_wait_window(&process,L"Untitled - Notepad");
    SetLastError(0);
    app_check(SetWindowLongW(first,GWL_WNDPROC,(LONG)original_proc)==0
              && GetLastError()==ERROR_ACCESS_DENIED,"cannot subclass another process");
    DbgPrint("[note-save] ready for typing\n");
    app_wait_window(&process,L"Save As");
    DbgPrint("[note-save] Save As ready\n");
    BOOL found=FALSE;
    for(unsigned int n=0;n<240;++n) {
        if(saved()) {found=TRUE;break;}
        app_alive(&process);Sleep(50);
    }
    app_check(found,"saved file contents");
    DbgPrint("[note-save] exact file bytes verified, close now\n");
    app_closed(&process);
    DbgPrint("[note-save] first process closed cleanly\n");
    WCHAR reopen[]=L"notepad.exe C:\\MINO-NOTE.TXT";
    process=app_start(L"C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",reopen);
    HWND window=app_wait_window(&process,L"MINO-NOTE.TXT - Notepad");
    app_check(SetWindowPos(window,0,0,0,800,600,SWP_NOZORDER|SWP_NOACTIVATE),"reopened window placement");
    Sleep(500);app_alive(&process);app_check(saved(),"file unchanged after reopen");
    DbgPrint("[note-save] reopened in a new process; PASS\n");
    Sleep(5000); /* Keep the reopened document alive for the screen checks. */
    ExitProcess(0x6012);return 0;
}
