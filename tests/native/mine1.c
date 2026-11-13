/* WineMine's real board: first covered tile -> flag -> new game -> close.
   Tile geometry comes from ReactOS 51bfc703 winmine/main.h (16x16, 5,33).
   The probe only reads rendered pixels; QEMU supplies the input. */
#include "app_probe.h"
static void tile(HWND window, COLORREF *pixels)
{
    HDC dc=GetDC(window);app_check(dc!=0,"mine board DC");
    for(unsigned int y=0;y<16;++y) for(unsigned int x=0;x<16;++x) {
        COLORREF color=GetPixel(dc,5+x,33+y);
        app_check(color!=CLR_INVALID,"read mine tile");pixels[y*16+x]=color;
    }
    ReleaseDC(window,dc);
}
static BOOL same_tile(const COLORREF *a,const COLORREF *b)
{
    for(unsigned int n=0;n<256;++n) if(a[n]!=b[n]) return FALSE;
    return TRUE;
}
static void wait_tile(PROCESS_INFORMATION *process, HWND window, const COLORREF *before, BOOL same)
{
    COLORREF pixels[256];
    for(unsigned int n=0;n<120;++n) {
        tile(window,pixels);
        BOOL red=FALSE;
        for(unsigned int i=0;i<256;++i) if(pixels[i]==RGB(255,0,0)) red=TRUE;
        if(same_tile(before,pixels)==same && (same || red)) return;
        app_alive(process);Sleep(50);
    }
    app_check(FALSE,same?"new game restores covered tile":"flag changes tile");
}
DWORD WINAPI GuiStartup(void)
{
    app_desktop();
    WCHAR command[]=L"winmine.exe";
    PROCESS_INFORMATION process=app_start(L"C:\\WINDOWS\\SYSTEM32\\WINMINE.EXE",command);
    HWND window=app_wait_window(&process,L"WineMine");
    app_check(SetWindowPos(window,0,0,0,0,0,SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE),"mine placement");
    Sleep(500);
    COLORREF before[256];tile(window,before);
    app_check(before[0]==RGB(255,255,255) && before[8*16+8]==RGB(192,192,192)
              && before[255]==RGB(128,128,128),"covered tile rendered before input");
    DbgPrint("[mine] ready for right click\n");
    wait_tile(&process,window,before,FALSE);
    Sleep(300);app_alive(&process);
    DbgPrint("[mine] flagged tile changed; new game now\n");
    wait_tile(&process,window,before,TRUE);
    DbgPrint("[mine] F2 restored covered tile; close now\n");
    app_closed(&process);
    DbgPrint("[mine] first process closed cleanly\n");
    process=app_start(L"C:\\WINDOWS\\SYSTEM32\\WINMINE.EXE",command);
    window=app_wait_window(&process,L"WineMine");
    app_check(SetWindowPos(window,0,0,0,0,0,SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE),"reopened mine placement");
    Sleep(500);wait_tile(&process,window,before,TRUE);
    DbgPrint("[mine] reopened with covered board; PASS\n");
    Sleep(5000);ExitProcess(0x6014);return 0;
}
