/*
 * The data sections of a file read nothing when they are made; a fault
 * reads a page of a view from the file, and the sections of an unchanged
 * file share what was read (ADR-024, mm::section::FileSegment,
 * io::section_cache): a Win32 program (subsystem WINDOWS), compiled with
 * MinGW and linked to ReactOS's kernel32, which the scenario `section-cache`
 * puts on the boot disk in the place of winlogon.exe, C: being the ATA
 * system disk:
 * - it writes C:\SECTION.BIN, 3 MiB of a pattern no two sectors share (the
 *   disk has 4 MiB free);
 * - a first section of it (CreateFileMappingW: NtCreateSection) is timed,
 *   then a byte in the middle of its view (the fault that reads its page):
 *   together they take less than a quarter of the whole view, which reads
 *   the rest (reading the whole file at its creation made it the reverse);
 * - a second section, the first still open, takes the pages the first
 *   read: its whole view takes less than a tenth of the first's;
 * - once both are closed, a third reads the file again; each view holds
 *   the pattern;
 * - a write to the file, then a new section: it sees the write;
 * - a copy-on-write view keeps its write to itself; a write in a shared
 *   view is seen by another view, and by another section of the file;
 * - a file that ends inside a page: zeros after its end, and a view past
 *   its end is refused;
 * - shell32.dll as a data file.
 * Each step goes to the debug port (DbgPrint, a line each), with its time
 * (QueryPerformanceCounter). The program ends with EXIT_STATUS.
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
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define FILE_MAP_COPY 0x0001
#define FILE_MAP_WRITE 0x0002
#define FILE_MAP_READ 0x0004
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)
#define SIZE (3 * 1024 * 1024)
#define SHORT_SIZE 5000
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
static const WCHAR SHORT_PATH[] = L"C:\\SHORT.BIN";
static unsigned char pattern[SIZE];
static LONGLONG frequency;

/* The byte at `at` of the pattern. */
static unsigned char byte_at(DWORD at)
{
    return (unsigned char)((at * 2654435761UL) >> 24);
}

/* The view holds the pattern (every 509th byte, and the last), with
 * `first` in place of its first 8 bytes when it is not null. */
static int holds_pattern(const volatile unsigned char *view, const char *first)
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

static HANDLE open_file(const WCHAR *path, DWORD access)
{
    return CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
}

/* A section of the file at `path` (read-only), timed; its handle in
 * `mapping`, its file's in `file`, its view in `view`. */
static DWORD map(const WCHAR *path, HANDLE *file, HANDLE *mapping, const unsigned char **view)
{
    LONGLONG start;
    DWORD ms;
    *file = open_file(path, GENERIC_READ);
    QueryPerformanceCounter(&start);
    *mapping = CreateFileMappingW(*file, 0, PAGE_READONLY, 0, 0, 0);
    ms = elapsed_ms(start);
    *view = *mapping ? MapViewOfFile(*mapping, FILE_MAP_READ, 0, 0, 0) : 0;
    if (!*view)
        DbgPrint("[section] no view (error %lu)\n", GetLastError());
    return ms;
}

static void unmap(HANDLE file, HANDLE mapping, const void *view)
{
    if (view)
        UnmapViewOfFile(view);
    if (mapping)
        CloseHandle(mapping);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
}

/* The whole view holds the pattern, timed in `ms`. */
static int timed_pattern(const unsigned char *view, DWORD *ms)
{
    LONGLONG start;
    int holds;
    QueryPerformanceCounter(&start);
    holds = view && holds_pattern(view, 0);
    *ms = elapsed_ms(start);
    return holds;
}

static void write_file(const WCHAR *path, const void *data, DWORD length, DWORD disposition)
{
    DWORD written = 0;
    HANDLE writer =
        CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, disposition, FILE_ATTRIBUTE_NORMAL, 0);
    if (writer == INVALID_HANDLE_VALUE || !WriteFile(writer, data, length, &written, 0) || written != length) {
        DbgPrint("[section] the write failed (error %lu)\n", GetLastError());
        ExitProcess(1);
    }
    CloseHandle(writer);
}

/* Copy-on-write and shared views of C:\SECTION.BIN. */
static void views(void)
{
    HANDLE file, copy, map_shared, file2, map2;
    volatile unsigned char *own, *shared;
    const volatile unsigned char *seen, *again;
    const unsigned char *other;
    int kept, unchanged, written, reached;

    file = open_file(PATH, GENERIC_READ);
    copy = CreateFileMappingW(file, 0, PAGE_WRITECOPY, 0, 0, 0);
    own = copy ? MapViewOfFile(copy, FILE_MAP_COPY, 0, 0, 0) : 0;
    seen = copy ? MapViewOfFile(copy, FILE_MAP_READ, 0, 0, 0) : 0;
    if (!own || !seen) {
        DbgPrint("[section] no copy-on-write view (error %lu)\n", GetLastError());
        return;
    }
    own[0x3000] = (unsigned char)~byte_at(0x3000);
    kept = own[0x3000] == (unsigned char)~byte_at(0x3000);
    unchanged = seen[0x3000] == byte_at(0x3000);
    DbgPrint("[section] a copy-on-write view keeps its write to itself: %d\n", kept && unchanged);
    UnmapViewOfFile((const void *)own);
    UnmapViewOfFile((const void *)seen);
    CloseHandle(copy);
    CloseHandle(file);

    file = open_file(PATH, GENERIC_READ | GENERIC_WRITE);
    map_shared = CreateFileMappingW(file, 0, PAGE_READWRITE, 0, 0, 0);
    shared = map_shared ? MapViewOfFile(map_shared, FILE_MAP_WRITE, 0, 0, 0) : 0;
    again = map_shared ? MapViewOfFile(map_shared, FILE_MAP_READ, 0, 0, 0) : 0;
    if (!shared || !again) {
        DbgPrint("[section] no shared view (error %lu)\n", GetLastError());
        return;
    }
    shared[0x5000] = 0x5A;
    written = again[0x5000] == 0x5A;
    /* Another section of the unchanged file: the same pages. */
    map(PATH, &file2, &map2, &other);
    reached = other && other[0x5000] == 0x5A;
    DbgPrint("[section] a shared write is seen by the other view: %d, and by another section: %d\n", written,
             reached);
    unmap(file2, map2, other);
    UnmapViewOfFile((const void *)shared);
    UnmapViewOfFile((const void *)again);
    CloseHandle(map_shared);
    CloseHandle(file);
}

/* A file that ends inside a page. */
static void short_file(void)
{
    HANDLE file, mapping;
    const unsigned char *view;
    const void *past;
    DWORD at;
    int last, zeros = 1;

    write_file(SHORT_PATH, pattern, SHORT_SIZE, CREATE_ALWAYS);
    map(SHORT_PATH, &file, &mapping, &view);
    if (!view)
        return;
    last = view[SHORT_SIZE - 1] == byte_at(SHORT_SIZE - 1) && view[0] == byte_at(0);
    for (at = SHORT_SIZE; at < 8192; ++at)
        zeros &= view[at] == 0;
    past = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 8192);
    DbgPrint("[section] a file of 5000 bytes: its last byte %d, zeros after it %d, a view past its end refused %d\n",
             last, zeros, past == 0);
    if (past)
        UnmapViewOfFile(past);
    unmap(file, mapping, view);
}

DWORD __stdcall GuiStartup(void)
{
    HANDLE file1, map1, file2, map2, file3, map3;
    const unsigned char *view1, *view2, *view3;
    DWORD at, first, page, whole, second, second_whole, third;
    LONGLONG start;
    int middle;

    QueryPerformanceFrequency(&frequency);
    for (at = 0; at < SIZE; ++at)
        pattern[at] = byte_at(at);
    write_file(PATH, pattern, SIZE, CREATE_ALWAYS);
    DbgPrint("[section] C:\\SECTION.BIN written: %lu bytes\n", (DWORD)SIZE);

    first = map(PATH, &file1, &map1, &view1);
    QueryPerformanceCounter(&start);
    middle = view1 && ((const volatile unsigned char *)view1)[SIZE / 2 + 123] == byte_at(SIZE / 2 + 123);
    page = elapsed_ms(start);
    DbgPrint("[section] first section: made in %lu ms, a byte in its middle %d, read in %lu ms\n", first, middle,
             page);
    {
        int found = middle;
        middle = timed_pattern(view1, &whole);
        DbgPrint("[section] first section: its bytes %d, in %lu ms\n", middle, whole);
        /* Reading the whole file at the section's creation made `first`
         * the cost of the file, and `whole` a walk through memory. */
        DbgPrint("[section] the section read nothing, a fault read its page: %d\n",
                 found && (first + page) * 4 < whole);
    }
    second = map(PATH, &file2, &map2, &view2);
    middle = timed_pattern(view2, &second_whole);
    DbgPrint("[section] second section, the first open: its bytes %d, in %lu ms (made in %lu ms)\n", middle,
             second_whole, second);
    DbgPrint("[section] the second's pages are the first's: %d\n", second_whole * 10 < whole);
    unmap(file1, map1, view1);
    unmap(file2, map2, view2);
    map(PATH, &file3, &map3, &view3);
    middle = timed_pattern(view3, &third);
    DbgPrint("[section] both closed, a third: its bytes %d, in %lu ms\n", middle, third);

    /* A write at its start, the third section still open: a new section
     * sees it. */
    {
        HANDLE writer = open_file(PATH, GENERIC_WRITE);
        DWORD written = 0;
        if (writer == INVALID_HANDLE_VALUE || !WriteFile(writer, "CHANGED!", 8, &written, 0)) {
            DbgPrint("[section] the write failed (error %lu)\n", GetLastError());
            ExitProcess(1);
        }
        CloseHandle(writer);
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

    views();
    short_file();

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
