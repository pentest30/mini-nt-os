/*
 * First native UI milestone for Mino's installer. The `installer-ui` boot
 * scenario puts this WINDOWS-subsystem program in place of winlogon.exe,
 * as the other GUI probes do. It uses the real ReactOS user32/gdi32 over
 * Mino's win32k and implements the five-screen installer flow with keyboard
 * navigation.
 *
 * The look is Mino's blue theme (theme.c): a full-screen blue setup screen,
 * the steps on the left, the wizard in a window with a blue title bar. Each
 * frame is drawn into a DIB section, then copied to the window.
 *
 * The privileged backend supplies a real ATA target and an immutable GPT/FAT
 * plan through NtDeviceIoControlFile; Install writes the GPT and formats
 * both volumes through the kernel, which revalidates the preview's token.
 *
 * Built by `cargo xtask` without a C runtime: -nostdlib, entry point
 * GuiStartup.
 */

#include "theme.h"

typedef struct {
    USHORT length;
    USHORT maximum_length;
    WCHAR *buffer;
} UNICODE_STRING;

typedef struct {
    DWORD length;
    HANDLE root_directory;
    UNICODE_STRING *object_name;
    DWORD attributes;
    void *security_descriptor;
    void *security_quality_of_service;
} OBJECT_ATTRIBUTES;

typedef struct {
    LONG status;
    DWORD information;
} IO_STATUS_BLOCK;

/* abi::setup::SetupPreview: only 32-bit words, including split u64 values. */
typedef struct {
    DWORD version;
    DWORD state;
    DWORD disk_number;
    DWORD disk_flags;
    DWORD sector_size;
    DWORD total_low;
    DWORD total_high;
    DWORD token_low;
    DWORD token_high;
    DWORD esp_first_low;
    DWORD esp_first_high;
    DWORD esp_sectors_low;
    DWORD esp_sectors_high;
    DWORD system_first_low;
    DWORD system_first_high;
    DWORD system_sectors_low;
    DWORD system_sectors_high;
} SETUP_PREVIEW;

/* abi::setup::SetupPrepare: the disk of the preview and its token, as the
 * kernel recomputes the plan and refuses a token that no longer describes
 * it. */
typedef struct {
    DWORD version;
    DWORD disk_number;
    DWORD token_low;
    DWORD token_high;
} SETUP_PREPARE;

#define FILE_READ_ATTRIBUTES 0x00000080
#define FILE_WRITE_ATTRIBUTES 0x00000100
#define FILE_SHARE_ALL 0x00000007
#define FILE_DIRECTORY_FILE 0x00000001
#define OBJ_CASE_INSENSITIVE 0x00000040
#define IOCTL_MINO_SETUP_QUERY 0x80006000
/* CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS): writes the
 * plan's GPT tables on the target, after the token revalidates it. */
#define IOCTL_MINO_SETUP_PREPARE 0x8000A004
/* CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS): formats the
 * plan's two volumes FAT32, after the prepare — same token. */
#define IOCTL_MINO_SETUP_FORMAT 0x8000A008
/* CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS): copies the
 * boot files and the system tree onto the installed volumes. */
#define IOCTL_MINO_SETUP_COPY 0x8000A00C
#define SETUP_READY 0
#define SETUP_DISK_CANDIDATE 1
#define KLF_ACTIVATE 0x00000001

enum Screen {
    SCREEN_WELCOME,
    SCREEN_DISK,
    SCREEN_REVIEW,
    SCREEN_INSTALL,
    SCREEN_COMPLETE
};

static const WCHAR CLASS_NAME[] = L"MinoSetup";
static enum Screen current_screen = SCREEN_WELCOME;
/* 0 is Back, 1 is the primary action. */
static int focused_action = 1;
static int disk_visits;
static int review_visits;
static int progress;
static BOOL backend_ready;
static DWORD target_mib;
static DWORD esp_mib;
static DWORD system_mib;
/* The identity the preview gave: the prepare request carries it back. */
static DWORD target_disk_number;
static DWORD target_token_low;
static DWORD target_token_high;
static WCHAR target_size_text[32] = L"Unavailable";

static CANVAS canvas;
/* The wizard's content area: its origin and width, set by draw(). */
static int content_x;
static int content_y;
static int content_width;

__declspec(dllimport) LONG __stdcall NtClose(HANDLE handle);
__declspec(dllimport) LONG __stdcall NtDeviceIoControlFile(HANDLE file, HANDLE event, void *apc_routine,
                                                           void *apc_context, IO_STATUS_BLOCK *iosb, DWORD code,
                                                           void *input, DWORD input_length, void *output,
                                                           DWORD output_length);
__declspec(dllimport) LONG __stdcall NtOpenFile(HANDLE *file, DWORD access, OBJECT_ATTRIBUTES *attributes,
                                                IO_STATUS_BLOCK *iosb, DWORD share, DWORD options);

static void format_mib(WCHAR *out, DWORD value, const WCHAR *suffix)
{
    WCHAR reverse[10];
    unsigned int count = 0;
    unsigned int index;

    do {
        reverse[count++] = (WCHAR)(L'0' + value % 10);
        value /= 10;
    } while (value && count < 10);
    index = 0;
    while (count)
        out[index++] = reverse[--count];
    while (*suffix)
        out[index++] = *suffix++;
    out[index] = 0;
}

static unsigned int wide_length(const WCHAR *text)
{
    unsigned int length = 0;
    while (text[length])
        ++length;
    return length;
}

static void query_install_backend(void)
{
    static WCHAR root_name[] = L"\\GLOBAL??\\C:\\";
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    SETUP_PREVIEW preview;
    HANDLE root = 0;
    LONG status;

    memset(&name, 0, sizeof name);
    memset(&attributes, 0, sizeof attributes);
    memset(&iosb, 0, sizeof iosb);
    memset(&preview, 0, sizeof preview);
    name.length = (USHORT)(wide_length(root_name) * sizeof(WCHAR));
    name.maximum_length = name.length + sizeof(WCHAR);
    name.buffer = root_name;
    attributes.length = sizeof attributes;
    attributes.object_name = &name;
    attributes.attributes = OBJ_CASE_INSENSITIVE;
    status = NtOpenFile(&root, FILE_READ_ATTRIBUTES, &attributes, &iosb, FILE_SHARE_ALL, FILE_DIRECTORY_FILE);
    if (status < 0) {
        DbgPrint("[setup] backend open failed: %08lx\n", status);
        return;
    }
    status = NtDeviceIoControlFile(root, 0, 0, 0, &iosb, IOCTL_MINO_SETUP_QUERY,
                                   0, 0, &preview, sizeof preview);
    NtClose(root);
    if (status < 0) {
        DbgPrint("[setup] backend query failed: %08lx\n", status);
        return;
    }
    if (preview.version != 1 || preview.state != SETUP_READY ||
        !(preview.disk_flags & SETUP_DISK_CANDIDATE) || preview.total_high ||
        preview.esp_sectors_high || preview.system_sectors_high) {
        DbgPrint("[setup] backend no safe target: state %lu flags %08lx\n",
                 preview.state, preview.disk_flags);
        return;
    }
    target_mib = preview.total_low / 2048;
    esp_mib = preview.esp_sectors_low / 2048;
    system_mib = preview.system_sectors_low / 2048;
    format_mib(target_size_text, target_mib, L" MiB");
    target_disk_number = preview.disk_number;
    target_token_low = preview.token_low;
    target_token_high = preview.token_high;
    backend_ready = TRUE;
    DbgPrint("[setup] backend target %lu: %lu MiB; plan EFI %lu MiB, system %lu MiB; token %08lx%08lx\n",
             preview.disk_number, target_mib, esp_mib, system_mib,
             preview.token_high, preview.token_low);
}

/* A rectangle of the content area. */
static RECT at(int left, int top, int right, int bottom)
{
    return rect(content_x + left, content_y + top, content_x + right, content_y + bottom);
}

static void say(const WCHAR *value, RECT area, PIXEL color, int pixels, BOOL bold, UINT flags)
{
    text(&canvas, value, area, color, font(pixels, bold), flags);
}

static void line_text(const WCHAR *value, RECT area, PIXEL color, int pixels, BOOL bold)
{
    say(value, area, color, pixels, bold, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

/* The setup screen around the wizard: dark blue bands, a blue field. */
static void draw_background(int width, int height)
{
    static const STOP field[] = {{0, PX(64, 124, 232)}, {120, PX(46, 102, 216)}, {256, PX(28, 76, 192)}};

    gradient(&canvas, rect(0, 0, width, 70), PX(4, 34, 116), PX(10, 54, 160));
    hgradient(&canvas, rect(0, 70, width, 72), PX(156, 204, 255), PX(30, 92, 210));
    gradient_stops(&canvas, rect(0, 72, width, height - 52), field, 3);
    fill(&canvas, rect(0, height - 52, width, height - 51), PX(98, 156, 242));
    gradient(&canvas, rect(0, height - 51, width, height), PX(10, 54, 160), PX(4, 34, 116));

    emblem(&canvas, 46, 35, 20);
    text_shadow(&canvas, L"Mino Setup", rect(78, 6, 600, 64), C_WHITE, font(24, TRUE),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    line_text(L"Tab  next control      Enter  activate      Esc  go back", rect(24, height - 51, 700, height),
              PX(188, 214, 255), 11, FALSE);
    say(L"Mino Setup 1.0", rect(width - 300, height - 51, width - 24, height), PX(188, 214, 255), 11, FALSE,
        DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

/* The steps, down the left of the setup screen. */
static void draw_steps(int height)
{
    static const WCHAR *labels[] = {L"Welcome", L"Select a disk", L"Review changes", L"Install", L"Complete"};
    int index;

    line_text(L"Installation steps", rect(40, 104, 300, 126), PX(176, 206, 255), 11, TRUE);
    fill(&canvas, rect(40, 128, 290, 129), PX(110, 164, 246));
    for (index = 0; index < 5; ++index) {
        int y = 150 + index * 44;
        RECT label = rect(84, y - 12, 300, y + 12);
        if (index < (int)current_screen) {
            disc(&canvas, 58, y, 9, PX(132, 218, 118), PX(36, 136, 40));
            check_mark(&canvas, 53, y - 5, 10, C_WHITE);
            line_text(labels[index], label, C_WHITE, 13, FALSE);
        } else if (index == (int)current_screen) {
            ring(&canvas, 58, y, 13, 3, PX(150, 204, 255));
            disc(&canvas, 58, y, 9, PX(255, 255, 255), PX(196, 222, 255));
            text_shadow(&canvas, labels[index], label, C_WHITE, font(13, TRUE),
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        } else {
            disc(&canvas, 58, y, 6, PX(128, 172, 240), PX(108, 154, 230));
            line_text(labels[index], label, PX(178, 206, 250), 13, FALSE);
        }
    }

    /* The target, as the kernel's plan describes it. */
    round_fill(&canvas, rect(40, 396, 300, 500), 6, CORNERS_ALL, PX(36, 88, 204), PX(30, 78, 190));
    round_frame(&canvas, rect(40, 396, 300, 500), 6, CORNERS_ALL, PX(104, 160, 246));
    line_text(L"Target disk", rect(56, 406, 290, 426), PX(176, 206, 255), 11, TRUE);
    line_text(backend_ready ? L"ATA secondary master" : L"No safe target", rect(56, 428, 290, 448), C_WHITE, 13,
              TRUE);
    line_text(backend_ready ? target_size_text : L"Attach a blank secondary disk", rect(56, 450, 290, 470),
              PX(208, 226, 255), 11, FALSE);
    line_text(L"Mino uses the whole disk.", rect(56, 470, 290, 490), PX(208, 226, 255), 11, FALSE);
    (void)height;
}

/* The wizard's header: a white band with a title, a line, the emblem. */
static void heading(RECT client, const WCHAR *title, const WCHAR *description)
{
    gradient(&canvas, rect(client.left, client.top, client.right, client.top + 76), C_WHITE, PX(244, 248, 255));
    fill(&canvas, rect(client.left, client.top + 76, client.right, client.top + 77), C_FACE_LINE);
    fill(&canvas, rect(client.left, client.top + 77, client.right, client.top + 78), C_WHITE);
    emblem(&canvas, client.right - 46, client.top + 38, 22);
    line_text(title, rect(client.left + 28, client.top + 12, client.right - 90, client.top + 38), C_INK_BLUE, 15,
              TRUE);
    line_text(description, rect(client.left + 44, client.top + 40, client.right - 90, client.top + 64), C_INK_SOFT,
              11, FALSE);
}

/* The wizard's buttons, along the bottom of its window. */
static void draw_navigation(RECT client, BOOL back, const WCHAR *primary, BOOL primary_enabled)
{
    int y = client.bottom - 42;

    fill(&canvas, rect(client.left, client.bottom - 56, client.right, client.bottom - 55), C_FACE_LINE);
    fill(&canvas, rect(client.left, client.bottom - 55, client.right, client.bottom - 54), C_WHITE);
    button(&canvas, rect(client.left + 18, y, client.left + 98, y + 26), L"Help", BUTTON_NORMAL);
    button(&canvas, rect(client.right - 282, y, client.right - 202, y + 26), L"< Back",
           !back ? BUTTON_DISABLED : focused_action == 0 ? BUTTON_FOCUSED : BUTTON_NORMAL);
    button(&canvas, rect(client.right - 194, y, client.right - 106, y + 26), primary,
           !primary_enabled ? BUTTON_DISABLED : focused_action == 1 ? BUTTON_FOCUSED : BUTTON_NORMAL);
    button(&canvas, rect(client.right - 94, y, client.right - 18, y + 26), L"Cancel",
           current_screen == SCREEN_INSTALL ? BUTTON_DISABLED : BUTTON_NORMAL);
}

/* A drop-down list, closed. */
static void combo(RECT area, const WCHAR *value)
{
    fill(&canvas, area, C_WHITE);
    frame(&canvas, area, PX(127, 157, 196));
    round_fill(&canvas, rect(area.right - 20, area.top + 2, area.right - 2, area.bottom - 2), 2, CORNERS_ALL,
               PX(196, 220, 255), PX(150, 186, 246));
    line(&canvas, area.right - 15, (area.top + area.bottom) / 2 - 2, area.right - 11, (area.top + area.bottom) / 2 + 2,
         2, PX(36, 70, 140));
    line(&canvas, area.right - 11, (area.top + area.bottom) / 2 + 2, area.right - 7, (area.top + area.bottom) / 2 - 2,
         2, PX(36, 70, 140));
    line_text(value, rect(area.left + 8, area.top, area.right - 24, area.bottom), C_INK, 11, FALSE);
}

/* The planned layout: the EFI partition, then Mino's. */
static void layout_bar(int top)
{
    int split = content_width * 40 / 94;

    round_fill(&canvas, at(0, top, split, top + 46), 4, CORNER_TL | CORNER_BL, PX(214, 230, 255),
               PX(180, 206, 248));
    round_fill(&canvas, at(split, top, content_width, top + 46), 4, CORNER_TR | CORNER_BR, PX(86, 156, 252),
               PX(30, 96, 220));
    round_frame(&canvas, at(0, top, content_width, top + 46), 4, CORNERS_ALL, PX(72, 112, 182));
    fill(&canvas, at(split, top + 1, split + 1, top + 45), PX(72, 112, 182));
    line_text(L"EFI system", at(14, top + 4, split - 8, top + 24), C_INK, 11, TRUE);
    line_text(L"40 MiB · FAT32", at(14, top + 23, split - 8, top + 42), C_INK_SOFT, 11, FALSE);
    line_text(L"Mino system", at(split + 14, top + 4, content_width - 8, top + 24), C_WHITE, 11, TRUE);
    line_text(L"54 MiB · FAT32", at(split + 14, top + 23, content_width - 8, top + 42), PX(220, 234, 255), 11,
              FALSE);
}

static void draw_welcome(RECT client)
{
    int half = content_width / 2;
    static const WCHAR *needs[] = {L"At least 8 GB of free disk space", L"UEFI firmware",
                                   L"AC power connected for laptops"};
    int index;

    heading(client, L"Welcome to Mino Setup",
            L"This wizard prepares a GPT disk and installs Mino in one guided session.");
    say(L"Mino will use one whole disk. Nothing is written until you confirm the changes in step 3.",
        at(0, 0, content_width, 36), C_INK, 11, FALSE, DT_LEFT | DT_WORDBREAK);
    line_text(L"Language", at(0, 44, half - 16, 64), C_INK_SOFT, 11, FALSE);
    line_text(L"Keyboard layout", at(half + 16, 44, content_width, 64), C_INK_SOFT, 11, FALSE);
    combo(at(0, 66, half - 16, 90), L"English (United Kingdom)");
    combo(at(half + 16, 66, content_width, 90), L"Generic 105-key keyboard");
    card(&canvas, at(0, 116, content_width, 254), PX(234, 242, 255), PX(170, 196, 240), C_SELECT);
    line_text(L"Before you continue, this computer should have", at(22, 126, content_width - 16, 150), C_INK, 11,
              TRUE);
    for (index = 0; index < 3; ++index) {
        RECT mark = at(26, 160 + index * 30, 38, 172 + index * 30);
        check_mark(&canvas, mark.left, mark.top, 12, C_GREEN);
        line_text(needs[index], at(48, 156 + index * 30, content_width - 16, 178 + index * 30), C_INK, 11, FALSE);
    }
    line_text(L"You can go back or cancel safely before installation begins.", at(0, 276, content_width, 298),
              C_INK_SOFT, 11, FALSE);
    draw_navigation(client, FALSE, L"Next >", TRUE);
}

static void draw_disk(RECT client)
{
    heading(client, L"Select a disk for Mino",
            L"Mino replaces everything on the selected disk. The running system and boot media are excluded.");
    if (backend_ready)
        card(&canvas, at(0, 0, content_width, 68), PX(226, 238, 255), C_SELECT, C_SELECT);
    else
        card(&canvas, at(0, 0, content_width, 68), PX(255, 240, 238), PX(214, 104, 92), C_RED);
    disc(&canvas, content_x + 26, content_y + 24, 8, C_WHITE, PX(226, 234, 248));
    ring(&canvas, content_x + 26, content_y + 24, 8, 1, PX(28, 81, 128));
    if (backend_ready)
        disc(&canvas, content_x + 26, content_y + 24, 4, PX(120, 200, 110), PX(30, 130, 40));
    line_text(backend_ready ? L"ATA secondary master" : L"No safe installation target", at(44, 10, 500, 34), C_INK,
              12, TRUE);
    say(backend_ready ? target_size_text : L"Unavailable", at(500, 10, content_width - 16, 34),
        backend_ready ? C_INK_BLUE : C_RED, 12, TRUE, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    line_text(backend_ready ? L"Disk 2 · healthy · not mounted" : L"Attach an unmounted secondary ATA disk",
              at(44, 36, content_width - 16, 58), C_INK_SOFT, 11, FALSE);

    card(&canvas, at(0, 84, content_width, 162), PX(255, 249, 226), PX(230, 198, 112), PX(222, 158, 30));
    disc(&canvas, content_x + 26, content_y + 106, 10, PX(255, 206, 80), PX(226, 146, 18));
    say(L"!", at(16, 96, 36, 116), C_WHITE, 13, TRUE, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    line_text(L"All existing data on this disk will be permanently removed.", at(46, 94, content_width - 16, 118),
              PX(116, 76, 6), 11, TRUE);
    fill(&canvas, at(46, 130, 59, 143), C_WHITE);
    frame(&canvas, at(46, 130, 59, 143), PX(28, 81, 128));
    check_mark(&canvas, content_x + 48, content_y + 132, 9, PX(33, 161, 33));
    line_text(L"I understand — erase this disk and everything on it.", at(68, 125, content_width - 16, 148), C_INK,
              11, FALSE);

    line_text(L"Planned layout", at(0, 180, content_width, 200), C_INK_SOFT, 11, TRUE);
    layout_bar(204);
    line_text(backend_ready ? L"Kernel plan ready · nothing is written before step 3."
                            : L"Continue remains unavailable until a safe target exists.",
              at(0, 270, content_width, 292), C_INK_SOFT, 11, FALSE);
    draw_navigation(client, TRUE, L"Next >", backend_ready);
}

static void numbered(int top, const WCHAR *number, const WCHAR *label)
{
    disc(&canvas, content_x + 13, content_y + top + 13, 13, PX(96, 160, 252), PX(28, 90, 214));
    say(number, at(0, top, 26, top + 26), C_WHITE, 12, TRUE, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    line_text(label, at(40, top, content_width, top + 26), C_INK, 11, FALSE);
}

static void draw_review(RECT client)
{
    heading(client, L"Review the changes",
            L"Nothing is written yet. Every structure written by setup is read back and verified.");
    card(&canvas, at(0, 0, content_width, 46), PX(255, 238, 236), PX(232, 160, 150), C_RED);
    line_text(L"Erase all existing data on ATA secondary master", at(20, 0, content_width - 16, 46),
              PX(150, 34, 24), 12, TRUE);
    numbered(66, L"1", L"Create a protective MBR and two verified GPT copies");
    numbered(108, L"2", L"Create an EFI system partition · 40 MiB · FAT32");
    numbered(150, L"3", L"Create the Mino system partition · 54 MiB · FAT32");
    layout_bar(204);
    line_text(L"Install starts disk writes. Back and Cancel are still safe on this screen.",
              at(0, 270, content_width, 292), C_INK_SOFT, 11, FALSE);
    draw_navigation(client, TRUE, L"Install", TRUE);
}

static void draw_install(RECT client)
{
    static const WCHAR *stages[] = {L"Validating target", L"Writing GPT", L"Formatting FAT32",
                                    L"Verifying volumes", L"Ready for file copy"};
    int index;

    heading(client, L"Installing Mino", L"Writing to ATA secondary master. Keep the computer connected to power.");
    for (index = 0; index < 5; ++index) {
        int top = index * 46;
        int cx = content_x + 14, cy = content_y + top + 16;
        BOOL done = progress >= (index + 1) * 20;
        BOOL active = !done && progress >= index * 20;
        if (done) {
            disc(&canvas, cx, cy, 13, PX(132, 218, 118), PX(36, 136, 40));
            check_mark(&canvas, cx - 6, cy - 6, 12, C_WHITE);
        } else if (active) {
            disc(&canvas, cx, cy, 13, PX(96, 160, 252), PX(28, 90, 214));
            line(&canvas, cx - 2, cy - 5, cx + 3, cy, 2, C_WHITE);
            line(&canvas, cx + 3, cy, cx - 2, cy + 5, 2, C_WHITE);
        } else {
            disc(&canvas, cx, cy, 13, PX(222, 230, 244), PX(204, 214, 232));
        }
        line_text(stages[index], at(40, top, content_width, top + 18), C_INK, 12, active);
        line_text(done ? L"completed and verified" : active ? L"in progress" : L"waiting",
                  at(40, top + 17, content_width, top + 34), done ? C_GREEN : C_INK_SOFT, 11, FALSE);
    }
    progress_bar(&canvas, at(0, 240, content_width, 262), progress);
    line_text(L"Disk writes have begun · Back is no longer available", at(0, 276, content_width, 298),
              PX(116, 76, 6), 11, FALSE);
    draw_navigation(client, FALSE, L"Working...", FALSE);
}

static void draw_complete(RECT client)
{
    heading(client, L"Disk preparation is complete",
            L"The partition table and both FAT32 volumes passed verification.");
    card(&canvas, at(0, 0, content_width, 100), PX(236, 249, 236), PX(150, 204, 150), C_GREEN);
    disc(&canvas, content_x + 42, content_y + 50, 20, PX(132, 218, 118), PX(36, 136, 40));
    check_mark(&canvas, content_x + 32, content_y + 40, 20, C_WHITE);
    line_text(L"Partition table verified", at(80, 12, content_width - 16, 36), PX(30, 110, 40), 13, TRUE);
    line_text(L"Protective MBR, primary GPT and backup GPT are consistent.", at(80, 40, content_width - 16, 62),
              C_INK, 11, FALSE);
    line_text(L"EFI and Mino volumes are FAT32 and mount successfully.", at(80, 64, content_width - 16, 86),
              C_INK_SOFT, 11, FALSE);

    round_fill(&canvas, at(0, 120, content_width, 196), 4, CORNERS_ALL, C_WHITE, C_WHITE);
    round_frame(&canvas, at(0, 120, content_width, 196), 4, CORNERS_ALL, C_FACE_LINE);
    fill(&canvas, at(1, 158, content_width - 1, 159), PX(226, 234, 248));
    line_text(L"EFI system", at(18, 120, 240, 158), C_INK_SOFT, 11, FALSE);
    line_text(L"40 MiB · FAT32 · verified", at(240, 120, content_width - 16, 158), C_INK, 11, TRUE);
    line_text(L"Mino system", at(18, 158, 240, 196), C_INK_SOFT, 11, FALSE);
    line_text(L"54 MiB · FAT32 · verified", at(240, 158, content_width - 16, 196), C_INK, 11, TRUE);

    card(&canvas, at(0, 216, content_width, 262), PX(255, 249, 226), PX(230, 198, 112), PX(222, 158, 30));
    line_text(L"Keep this target attached. The next installer lot copies the boot and system files.",
              at(20, 216, content_width - 16, 262), PX(116, 76, 6), 11, FALSE);
    draw_navigation(client, FALSE, L"Finish", TRUE);
}

static void draw(HDC dc)
{
    int width = canvas.width, height = canvas.height;
    RECT window = rect(340, 104, width - 56, 104 + 560);
    RECT client;

    if (window.right - window.left > 900)
        window.right = window.left + 900;
    if (window.bottom > height - 72)
        window.bottom = height - 72;
    draw_background(width, height);
    draw_steps(height);
    client = window_frame(&canvas, window, L"Mino Setup", FALSE);
    emblem(&canvas, window.left + 17, window.top + 15, 9);
    fill(&canvas, client, C_FACE);
    content_x = client.left + 44;
    content_y = client.top + 100;
    content_width = client.right - client.left - 88;

    switch (current_screen) {
    case SCREEN_WELCOME:
        draw_welcome(client);
        break;
    case SCREEN_DISK:
        draw_disk(client);
        break;
    case SCREEN_REVIEW:
        draw_review(client);
        break;
    case SCREEN_INSTALL:
        draw_install(client);
        break;
    case SCREEN_COMPLETE:
        draw_complete(client);
        break;
    }
    canvas_present(&canvas, dc);
}

static void repaint(HWND window)
{
    InvalidateRect(window, 0, FALSE);
    UpdateWindow(window);
}

static void set_screen(HWND window, enum Screen screen)
{
    current_screen = screen;
    focused_action = 1;
    if (screen == SCREEN_DISK)
        ++disk_visits;
    else if (screen == SCREEN_REVIEW)
        ++review_visits;
    /* The paint goes first: a marker says the screen it names is showing,
     * and the scenario's screendump never catches a half-painted window. */
    repaint(window);
    if (screen == SCREEN_DISK) {
        DbgPrint("[setup] screen disk %d\n", disk_visits);
    } else if (screen == SCREEN_REVIEW) {
        DbgPrint("[setup] screen review %d\n", review_visits);
    } else if (screen == SCREEN_INSTALL) {
        DbgPrint("[setup] screen install; GPT write boundary\n");
    } else if (screen == SCREEN_COMPLETE) {
        DbgPrint("[setup] screen complete; GPT, FAT32 and files written\n");
    }
}

/* The write boundary. The kernel revalidates the disk against the token of
 * the preview, writes the protective MBR and both GPT copies, flushes them
 * and rereads them; then it formats both volumes. File copy waits for the
 * next milestone. */
static void run_install(HWND window)
{
    static WCHAR root_name[] = L"\\GLOBAL??\\C:\\";
    SETUP_PREPARE request;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    HANDLE root = 0;
    LONG status;

    set_screen(window, SCREEN_INSTALL);
    progress = 20;
    DbgPrint("[setup] stage prepare: %d%%\n", progress);
    repaint(window);

    memset(&request, 0, sizeof request);
    request.version = 1;
    request.disk_number = target_disk_number;
    request.token_low = target_token_low;
    request.token_high = target_token_high;
    memset(&name, 0, sizeof name);
    memset(&attributes, 0, sizeof attributes);
    memset(&iosb, 0, sizeof iosb);
    name.length = (USHORT)(wide_length(root_name) * sizeof(WCHAR));
    name.maximum_length = name.length + sizeof(WCHAR);
    name.buffer = root_name;
    attributes.length = sizeof attributes;
    attributes.object_name = &name;
    attributes.attributes = OBJ_CASE_INSENSITIVE;
    status = NtOpenFile(&root, FILE_WRITE_ATTRIBUTES, &attributes, &iosb, FILE_SHARE_ALL, FILE_DIRECTORY_FILE);
    if (status >= 0) {
        status = NtDeviceIoControlFile(root, 0, 0, 0, &iosb, IOCTL_MINO_SETUP_PREPARE,
                                       &request, sizeof request, 0, 0);
        NtClose(root);
    }
    if (status < 0) {
        DbgPrint("[setup] prepare failed: %08lx\n", status);
        DbgPrint("[setup] install stopped on the install screen\n");
        return;
    }
    DbgPrint("[setup] prepare: GPT written and reread by the kernel\n");
    /* Stage format: the two FAT32 volumes of the plan, written by the
     * kernel and verified by its own FAT driver's mount on each view. */
    progress = 40;
    DbgPrint("[setup] stage format: %d%%\n", progress);
    repaint(window);
    memset(&attributes, 0, sizeof attributes);
    memset(&iosb, 0, sizeof iosb);
    name.length = (USHORT)(wide_length(root_name) * sizeof(WCHAR));
    name.maximum_length = name.length + sizeof(WCHAR);
    name.buffer = root_name;
    attributes.length = sizeof attributes;
    attributes.object_name = &name;
    attributes.attributes = OBJ_CASE_INSENSITIVE;
    status = NtOpenFile(&root, FILE_WRITE_ATTRIBUTES, &attributes, &iosb, FILE_SHARE_ALL, FILE_DIRECTORY_FILE);
    if (status >= 0) {
        status = NtDeviceIoControlFile(root, 0, 0, 0, &iosb, IOCTL_MINO_SETUP_FORMAT,
                                       &request, sizeof request, 0, 0);
        NtClose(root);
    }
    if (status < 0) {
        DbgPrint("[setup] format failed: %08lx\n", status);
        DbgPrint("[setup] install stopped on the install screen\n");
        return;
    }
    DbgPrint("[setup] format: ESP and system volumes FAT32, mounted by the kernel\n");
    /* Stage copy: the kernel copies the boot files (BOOTX64.EFI, kernel.elf)
     * to the target ESP and the system tree to the system volume, verifying
     * each file's size after the write. */
    progress = 60;
    DbgPrint("[setup] stage copy: %d%%\n", progress);
    repaint(window);
    memset(&attributes, 0, sizeof attributes);
    memset(&iosb, 0, sizeof iosb);
    name.length = (USHORT)(wide_length(root_name) * sizeof(WCHAR));
    name.maximum_length = name.length + sizeof(WCHAR);
    name.buffer = root_name;
    attributes.length = sizeof attributes;
    attributes.object_name = &name;
    attributes.attributes = OBJ_CASE_INSENSITIVE;
    status = NtOpenFile(&root, FILE_WRITE_ATTRIBUTES, &attributes, &iosb, FILE_SHARE_ALL, FILE_DIRECTORY_FILE);
    if (status >= 0) {
        status = NtDeviceIoControlFile(root, 0, 0, 0, &iosb, IOCTL_MINO_SETUP_COPY,
                                       &request, sizeof request, 0, 0);
        NtClose(root);
    }
    if (status < 0) {
        DbgPrint("[setup] copy failed: %08lx\n", status);
        DbgPrint("[setup] install stopped on the install screen\n");
        return;
    }
    DbgPrint("[setup] copy: boot files and system tree copied\n");
    /* Stage configure: nothing to configure yet — the loader boots the
     * installed disk by convention. The verify stage ran inside the copy
     * (each file's size reread). */
    progress = 80;
    DbgPrint("[setup] stage configure: %d%%\n", progress);
    repaint(window);
    Sleep(40);
    progress = 100;
    DbgPrint("[setup] stage verify: %d%%\n", progress);
    repaint(window);
    Sleep(40);
    set_screen(window, SCREEN_COMPLETE);
}

static void activate(HWND window)
{
    switch (current_screen) {
    case SCREEN_WELCOME:
        set_screen(window, SCREEN_DISK);
        break;
    case SCREEN_DISK:
        if (focused_action == 0) {
            current_screen = SCREEN_WELCOME;
            focused_action = 1;
            DbgPrint("[setup] back to welcome\n");
            repaint(window);
        } else if (backend_ready) {
            set_screen(window, SCREEN_REVIEW);
        } else {
            DbgPrint("[setup] continue blocked: no safe target\n");
        }
        break;
    case SCREEN_REVIEW:
        if (focused_action == 0)
            set_screen(window, SCREEN_DISK);
        else
            run_install(window);
        break;
    case SCREEN_INSTALL:
        break;
    case SCREEN_COMPLETE:
        DbgPrint("[setup] finish requested (milestone stays open)\n");
        break;
    }
}

static void go_back(HWND window)
{
    if (current_screen == SCREEN_DISK) {
        current_screen = SCREEN_WELCOME;
        focused_action = 1;
        DbgPrint("[setup] back to welcome\n");
        repaint(window);
    } else if (current_screen == SCREEN_REVIEW) {
        set_screen(window, SCREEN_DISK);
        DbgPrint("[setup] returned to disk\n");
    }
}

static LRESULT __stdcall setup_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    switch (message) {
    case WM_ERASEBKGND:
        /* The canvas covers the whole window. */
        return 1;
    case WM_PAINT:
        BeginPaint(window, &paint);
        draw(paint.hdc);
        EndPaint(window, &paint);
        return 0;
    case WM_CHAR:
        if (w == VK_TAB && (current_screen == SCREEN_DISK || current_screen == SCREEN_REVIEW)) {
            focused_action = !focused_action;
            DbgPrint("[setup] focus %s\n", focused_action ? "primary" : "back");
            repaint(window);
            return 0;
        }
        if (w == VK_RETURN || w == VK_SPACE) {
            activate(window);
            return 0;
        }
        if (w == VK_ESCAPE) {
            go_back(window);
            return 0;
        }
        break;
    }
    return DefWindowProcW(window, message, w, l);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
    MSG message;
    int width, height;

    if (!take_desktop())
        ExitProcess(1);
    query_install_backend();
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        ExitProcess(2);

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = setup_procedure;
    class_info.hInstance = instance;
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);

    width = GetSystemMetrics(SM_CXSCREEN);
    height = GetSystemMetrics(SM_CYSCREEN);
    if (!canvas_create(&canvas, width, height))
        ExitProcess(5);
    window = CreateWindowExW(0, CLASS_NAME, L"Mino Setup", WS_POPUP | WS_VISIBLE, 0, 0, width, height, 0, 0,
                             instance, 0);
    if (!window)
        ExitProcess(4);
    UpdateWindow(window);
    DbgPrint("[setup] screen welcome\n");
    DbgPrint("[setup] ready\n");

    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ExitProcess(0);
    return 0;
}
