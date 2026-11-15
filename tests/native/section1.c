/*
 * The sections of a file share what was read of it (io::section_cache) and
 * the file is read in runs of sectors (io::fat): a Win32 program (subsystem
 * WINDOWS), compiled with MinGW and linked to ReactOS's kernel32, which the
 * scenario `section-cache` puts on the boot disk in the place of
 * winlogon.exe, C: being the ATA system disk:
 * - it writes C:\SECTION.BIN, 2 MiB of a pattern no two sectors share;
 * - a first section of it (CreateFileMappingW: NtCreateSection) reads it
 *   from the disk; a second, the first still open, takes the bytes the
 *   first holds; once both are closed, a third reads it again; each view
 *   holds the pattern;
 * - a write to the file, then a new section: it sees the write;
 * - shell32.dll as a data file (a section of \KnownDlls holds it).
 * Each step goes to the debug port (DbgPrint, a line each), with the time
 * NtCreateSection took (QueryPerformanceCounter), which the scenario reads
 * but does not judge, except that the second section, which reads
 * nothing, takes less than a tenth of the first. The program ends with
 * EXIT_STATUS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long long LONGLONG;
typedef void *HANDLE;

#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define FILE_ATTRIBUTE_NORMAL 0x80
#define PAGE_READONLY 0x02
#define FILE_MAP_READ 0x0004
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)
#define SIZE (2 * 1024 * 1024)
#define EXIT_STATUS 0x6015

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateFileMappingW(HANDLE file, void *attributes, DWORD protect, DWORD high,
                                                          DWORD low, const WCHAR *name);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR *name, DWORD access, DWORD share, void *attributes,
                                                   DWORD disposition, DWORD flags, HANDLE model);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void *__stdcall MapViewOfFile(HANDLE mapping, DWORD access, DWORD high, DWORD low,
                                                    unsigned long size);
__declspec(dllimport) BOOL __stdcall QueryPerformanceCounter(LONGLONG *counter);
__declspec(dllimport) BOOL __stdcall QueryPerformanceFrequency(LONGLONG *frequency);
__declspec(dllimport) BOOL __stdcall UnmapViewOfFile(const void *view);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE file, const void *data, DWORD length, DWORD *written,
                                               void *overlapped);

static const WCHAR PATH[] = L"C:\\SECTION.BIN";
static unsigned char pattern[SIZE];
static LONGLONG frequency;

/* The byte at `at` of the pattern. */
static unsigned char byte_at(DWORD at)
{
    return (unsigned char)((at * 2654435761UL) >> 24);
}

/* The view holds the pattern (every 509th byte, and the last), with
 * `first` in place of its first 8 bytes when it is not null. */
static int holds_pattern(const unsigned char *view, const char *first)
{
    DWORD at;
    for (at = 0; at < SIZE; at += 509)
        if (!(first && at < 8) && view[at] != byte_at(at))
            return 0;
    if (first)
        for (at = 0; at < 8; ++at)
            if (view[at] != (unsigned char)first[at])
                return 0;
    return view[SIZE - 1] == byte_at(SIZE - 1);
}

/* Without a C runtime, no 64-bit division: both values halved until the
 * frequency fits 20 bits, then counts per millisecond in 32 bits. */
static DWORD elapsed_ms(LONGLONG since)
{
    LONGLONG now;
    unsigned long long ticks, rate = (unsigned long long)frequency;
    QueryPerformanceCounter(&now);
    ticks = (unsigned long long)(now - since);
    while (rate >= (1u << 20)) {
        rate >>= 1;
        ticks >>= 1;
    }
    if (rate < 1000)
        return 0;
    return (DWORD)ticks / ((DWORD)rate / 1000);
}

/* A section of the file at `path` (read-only), timed; its handle in
 * `mapping`, its file's in `file`, its view in `view`. */
static DWORD map(const WCHAR *path, HANDLE *file, HANDLE *mapping, const unsigned char **view)
{
    LONGLONG start;
    DWORD ms;
    *file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, 0);
    QueryPerformanceCounter(&start);
    *mapping = CreateFileMappingW(*file, 0, PAGE_READONLY, 0, 0, 0);
    ms = elapsed_ms(start);
    *view = *mapping ? MapViewOfFile(*mapping, FILE_MAP_READ, 0, 0, 0) : 0;
    if (!*view)
        DbgPrint("[section] no view (error %lu)\n", GetLastError());
    return ms;
}

static void unmap(HANDLE file, HANDLE mapping, const unsigned char *view)
{
    if (view)
        UnmapViewOfFile(view);
    if (mapping)
        CloseHandle(mapping);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
}

DWORD __stdcall GuiStartup(void)
{
    HANDLE writer, file1, map1, file2, map2, file3, map3;
    const unsigned char *view1, *view2, *view3;
    DWORD at, written = 0, first, second, third;

    QueryPerformanceFrequency(&frequency);
    for (at = 0; at < SIZE; ++at)
        pattern[at] = byte_at(at);
    writer = CreateFileW(PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, 0);
    if (writer == INVALID_HANDLE_VALUE || !WriteFile(writer, pattern, SIZE, &written, 0)) {
        DbgPrint("[section] C:\\SECTION.BIN not written (error %lu)\n", GetLastError());
        ExitProcess(1);
    }
    DbgPrint("[section] C:\\SECTION.BIN written: %lu bytes\n", written);
    CloseHandle(writer);

    first = map(PATH, &file1, &map1, &view1);
    DbgPrint("[section] first section: its bytes %d, in %lu ms\n", view1 && holds_pattern(view1, 0), first);
    second = map(PATH, &file2, &map2, &view2);
    DbgPrint("[section] second section, the first open: its bytes %d, in %lu ms\n",
             view2 && holds_pattern(view2, 0), second);
    DbgPrint("[section] the second took less than a tenth of the first: %d\n", second * 10 < first);
    unmap(file1, map1, view1);
    unmap(file2, map2, view2);
    third = map(PATH, &file3, &map3, &view3);
    DbgPrint("[section] both closed, a third: its bytes %d, in %lu ms\n", view3 && holds_pattern(view3, 0), third);

    /* A write at its start, the third section still open: a new section
     * sees it. */
    writer = CreateFileW(PATH, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, 0);
    if (writer == INVALID_HANDLE_VALUE || !WriteFile(writer, "CHANGED!", 8, &written, 0)) {
        DbgPrint("[section] the write failed (error %lu)\n", GetLastError());
        ExitProcess(1);
    }
    {
        HANDLE file4, map4;
        const unsigned char *view4;
        DWORD fourth = map(PATH, &file4, &map4, &view4);
        DbgPrint("[section] after a write at its start, a new section sees it: %d (%lu ms)\n",
                 view4 && holds_pattern(view4, "CHANGED!"), fourth);
        unmap(file4, map4, view4);
    }
    unmap(file3, map3, view3);
    CloseHandle(writer);

    {
        HANDLE file5, map5;
        const unsigned char *view5;
        DWORD shell = map(L"C:\\WINDOWS\\system32\\shell32.dll", &file5, &map5, &view5);
        DbgPrint("[section] shell32.dll as a data file: MZ %d, in %lu ms\n",
                 view5 && view5[0] == 'M' && view5[1] == 'Z', shell);
        unmap(file5, map5, view5);
    }
    DbgPrint("[section] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
