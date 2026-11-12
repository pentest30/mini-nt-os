/* The Save As dialog of the actual ReactOS Notepad (comdlg32 with shell32's
   file view): its view lists the folders and text files of C:\ with their
   icons (shell32's icon cache: NtUserGetIconInfo and its bitmap copies,
   comctl32's image lists: GetDIBits, StretchBlt), without looping. The
   dialog stays up while the scenario captures the screen. */
#include "app_probe.h"
DWORD WINAPI GuiStartup(void)
{
    app_desktop();
    WCHAR command[]=L"notepad.exe";
    PROCESS_INFORMATION process=app_start(L"C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",command);
    app_wait_window(&process,L"Untitled - Notepad");
    DbgPrint("[saveas] Notepad is up\n");
    HWND dialog=app_wait_window(&process,L"Save As");
    DbgPrint("[saveas] the view lists %d files and folders\n",app_file_view(&process,dialog));
    Sleep(5000); /* The scenario captures the screen meanwhile. */
    app_alive(&process);
    DbgPrint("[saveas] done\n");
    ExitProcess(0x6013);return 0;
}
