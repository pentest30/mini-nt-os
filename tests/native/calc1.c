/* Actual calc.exe, keyboard arithmetic, the static display's text, normal
   close and fresh process. Control ID: ReactOS 51bfc703 calc/resource.h. */
#include "app_probe.h"
static void check_class_name(void)
{
    HWND button=CreateWindowExW(0,L"Button",L"",0,0,0,10,10,0,0,GetModuleHandleW(0),0);
    app_check(button!=0,"class name fixture");
    WCHAR wide[8]={0};char narrow[8]={0};
    app_check(GetClassNameW(button,wide,8)==6 && wide[0]=='B' && wide[5]=='n' && wide[6]==0,"button Unicode class name");
    app_check(GetClassNameA(button,narrow,8)==6 && narrow[0]=='B' && narrow[5]=='n' && narrow[6]==0,"button ANSI class name");
    wide[0]=wide[1]=wide[2]=0x5555;
    app_check(GetClassNameW(button,wide,2)==1 && wide[0]=='B' && wide[1]==0 && wide[2]==0x5555,"class name bounded truncation");
    wide[0]=0x5555;
    app_check(GetClassNameW(button,wide,1)==0 && wide[0]==0,"class name terminator only");
    app_check(GetClassNameW(button,0,8)==0,"class name invalid output pointer");
    app_check(GetClassNameW((HWND)0x12345678,wide,8)==0 && GetLastError()==ERROR_INVALID_WINDOW_HANDLE,"class name invalid handle");
    app_check(DestroyWindow(button),"destroy class name fixture");
    DbgPrint("[calc] class names and bounds verified\n");
}
static void result(PROCESS_INFORMATION *process, HWND window, const WCHAR *expected)
{
    HWND display=0;WCHAR text[128]={0};
    for(unsigned int n=0;n<120;++n) {
        /* The top-level title can be published before the dialog children
           exist. Wait for the display and its value, including on reopen. */
        display=GetDlgItem(window,1074);text[0]=0;
        if(display && GetWindowTextW(display,text,128)>0) {
            unsigned int i=0;while(text[i] && text[i]==expected[i]) ++i;
            if(text[i]==expected[i]) {
                DWORD_PTR reply=0;
                app_check(SendMessageTimeoutW(window,WM_NULL,0,0,SMTO_NORMAL,3000,&reply)!=0,
                          "calculator message loop ready");
                return;
            }
        }
        app_alive(process);Sleep(50);
    }
    char ascii[128];
    unsigned int i=0;for(;i<127 && text[i];++i) ascii[i]=(char)text[i];ascii[i]=0;
    DbgPrint("[calc] unexpected display: '%s'\n",ascii);
    app_check(FALSE,"calculator result");
}
DWORD WINAPI GuiStartup(void)
{
    app_desktop();
    check_class_name();
    WCHAR command[]=L"calc.exe";
    PROCESS_INFORMATION process=app_start(L"C:\\WINDOWS\\SYSTEM32\\CALC.EXE",command);
    HWND window=app_wait_window(&process,L"Calculator");
    result(&process,window,L"0.");
    DbgPrint("[calc] ready for 12 + 30\n");
    result(&process,window,L"42.");
    DbgPrint("[calc] result 42 verified; close now\n");
    app_closed(&process);
    DbgPrint("[calc] first process closed cleanly\n");
    process=app_start(L"C:\\WINDOWS\\SYSTEM32\\CALC.EXE",command);
    window=app_wait_window(&process,L"Calculator");
    result(&process,window,L"0.");
    app_check(SetWindowPos(window,0,0,0,0,0,SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE),"calculator placement");
    DbgPrint("[calc] reopened; calculate again\n");
    result(&process,window,L"42.");
    Sleep(500);app_alive(&process);
    DbgPrint("[calc] keyboard result 42 after reopen; PASS\n");
    Sleep(5000);ExitProcess(0x6013);return 0;
}
