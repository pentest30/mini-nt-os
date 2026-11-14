/* The Save As dialog of the actual ReactOS Notepad (comdlg32 with shell32's
   file view): its view lists the folders and text files of C:\ with their
   icons (shell32's icon cache: NtUserGetIconInfo and its bitmap copies,
   comctl32's image lists: GetDIBits, StretchBlt), without looping.

   The probe first registers shell32 (DllRegisterServer), as minoinit.exe
   does at the end of the installation (syssetup.inf, RegistrationPhase2):
   the places bar then finds the icons of My Documents and My Computer under
   HKCR\CLSID, and the dialog opens in My Documents, which the registration
   creates (SHELL_RegisterShellFolders); the scenario types C:\ to go to the
   root. The dialog stays up while the scenario captures the screen. */
#include "app_probe.h"
static void register_shell32(void)
{
    typedef HRESULT (WINAPI *RegisterFn)(void);
    HMODULE shell32=LoadLibraryW(L"shell32.dll");
    RegisterFn reg=shell32?(RegisterFn)GetProcAddress(shell32,"DllRegisterServer"):0;
    app_check(reg!=0,"shell32's DllRegisterServer");
    DbgPrint("[saveas] shell32's DllRegisterServer: %08lx\n",(DWORD)reg());
}
DWORD WINAPI GuiStartup(void)
{
    app_desktop();
    register_shell32();
    WCHAR command[]=L"notepad.exe";
    PROCESS_INFORMATION process=app_start(L"C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",command);
    app_wait_window(&process,L"Untitled - Notepad");
    DbgPrint("[saveas] Notepad is up\n");
    HWND dialog=app_wait_window(&process,L"Save As");
    Sleep(1000); /* The dialog fills its view before it takes keys. */
    DbgPrint("[saveas] the dialog is up\n");
    for(unsigned int n=0;n<200 && app_file_view_count(dialog)!=5;++n) {app_alive(&process);Sleep(50);}
    DbgPrint("[saveas] the view lists %d files and folders\n",app_file_view(&process,dialog));
    Sleep(5000); /* The scenario captures the screen meanwhile. */
    app_alive(&process);
    DbgPrint("[saveas] done\n");
    ExitProcess(0x6013);return 0;
}
