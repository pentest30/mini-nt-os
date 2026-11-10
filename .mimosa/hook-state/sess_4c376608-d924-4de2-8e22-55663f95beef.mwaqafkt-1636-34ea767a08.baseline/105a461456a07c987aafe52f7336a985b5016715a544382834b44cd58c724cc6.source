/*
 * Mino desktop design probe. It owns WinSta0\Default like winlogon, paints
 * the desktop shell in Mino's blue theme (theme.c) — blue sky wallpaper,
 * desktop icons, a Files window, the two-column Start menu and the blue
 * taskbar — and keeps the Start menu keyboard-accessible; with the mouse, the
 * Start button opens and closes it and a press selects an entry. Every shape
 * is drawn by the program; built freestanding by xtask.
 */

#include "theme.h"

static const WCHAR CLASS_NAME[] = L"MinoDesktop";
static BOOL menu_open = TRUE;
/* 0 to 5: the programs of the menu's left column; 6 Restart, 7 Shut down. */
static int selected_item;
static CANVAS canvas;

static void say(const WCHAR *value, RECT area, PIXEL color, int pixels, BOOL bold, UINT flags)
{
    text(&canvas, value, area, color, font(pixels, bold), flags);
}

static void line_text(const WCHAR *value, RECT area, PIXEL color, int pixels, BOOL bold)
{
    say(value, area, color, pixels, bold, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

/* The small pictures, drawn from shapes. */
static void page_icon(int x, int y, int size)
{
#define S(v) ((v) * size / 32)
    int line_y;

    round_fill(&canvas, rect(x + S(5), y + S(2), x + S(27), y + S(30)), S(2), CORNERS_ALL, C_WHITE,
               PX(226, 234, 248));
    round_frame(&canvas, rect(x + S(5), y + S(2), x + S(27), y + S(30)), S(2), CORNERS_ALL, PX(110, 130, 170));
    for (line_y = S(8); line_y < S(26); line_y += S(4))
        fill(&canvas, rect(x + S(9), y + line_y, x + S(23), y + line_y + 1), PX(120, 150, 210));
#undef S
}

static void terminal_icon(int x, int y, int size)
{
#define S(v) ((v) * size / 32)
    round_fill(&canvas, rect(x + S(2), y + S(5), x + S(30), y + S(27)), S(3), CORNERS_ALL, PX(70, 80, 100),
               PX(20, 24, 34));
    line(&canvas, x + S(7), y + S(11), x + S(11), y + S(15), 2, PX(120, 230, 120));
    line(&canvas, x + S(11), y + S(15), x + S(7), y + S(19), 2, PX(120, 230, 120));
    fill(&canvas, rect(x + S(13), y + S(19), x + S(20), y + S(21)), PX(120, 230, 120));
#undef S
}

static void settings_icon(int x, int y, int size)
{
    int cx = x + size / 2, cy = y + size / 2;

    disc(&canvas, cx, cy, size * 13 / 32, PX(210, 218, 232), PX(130, 144, 170));
    ring(&canvas, cx, cy, size * 13 / 32, 1, PX(80, 92, 120));
    disc(&canvas, cx, cy, size * 5 / 32, PX(70, 120, 210), PX(30, 80, 180));
}

static void software_icon(int x, int y, int size)
{
#define S(v) ((v) * size / 32)
    round_fill(&canvas, rect(x + S(4), y + S(8), x + S(28), y + S(28)), S(2), CORNERS_ALL, PX(255, 196, 110),
               PX(220, 140, 40));
    round_fill(&canvas, rect(x + S(2), y + S(4), x + S(30), y + S(11)), S(2), CORNERS_ALL, PX(255, 214, 140),
               PX(238, 168, 70));
    round_frame(&canvas, rect(x + S(4), y + S(8), x + S(28), y + S(28)), S(2), CORNERS_ALL, PX(170, 100, 20));
    fill(&canvas, rect(x + S(14), y + S(4), x + S(18), y + S(28)), PX(196, 60, 40));
#undef S
}

static void help_icon(int x, int y, int size)
{
    disc(&canvas, x + size / 2, y + size / 2, size * 13 / 32, PX(120, 180, 255), PX(20, 84, 210));
    say(L"?", rect(x, y, x + size, y + size), C_WHITE, size / 2, TRUE, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

static void computer_icon(int x, int y, int size)
{
#define S(v) ((v) * size / 32)
    round_fill(&canvas, rect(x + S(2), y + S(3), x + S(30), y + S(23)), S(2), CORNERS_ALL, PX(236, 238, 244),
               PX(180, 186, 200));
    round_frame(&canvas, rect(x + S(2), y + S(3), x + S(30), y + S(23)), S(2), CORNERS_ALL, PX(100, 108, 128));
    gradient(&canvas, rect(x + S(5), y + S(6), x + S(27), y + S(20)), PX(110, 170, 255), PX(30, 90, 210));
    fill(&canvas, rect(x + S(13), y + S(23), x + S(19), y + S(27)), PX(150, 156, 172));
    round_fill(&canvas, rect(x + S(8), y + S(26), x + S(24), y + S(30)), S(1), CORNERS_ALL, PX(210, 214, 224),
               PX(150, 156, 172));
#undef S
}

static void trash_icon(int x, int y, int size)
{
#define S(v) ((v) * size / 32)
    int stripe;

    round_fill(&canvas, rect(x + S(7), y + S(8), x + S(25), y + S(30)), S(2), CORNERS_ALL, PX(226, 236, 248),
               PX(160, 180, 210));
    round_frame(&canvas, rect(x + S(7), y + S(8), x + S(25), y + S(30)), S(2), CORNERS_ALL, PX(90, 110, 150));
    round_fill(&canvas, rect(x + S(5), y + S(4), x + S(27), y + S(9)), S(2), CORNERS_ALL, PX(200, 214, 236),
               PX(140, 160, 196));
    for (stripe = S(11); stripe < S(24); stripe += S(4))
        fill(&canvas, rect(x + stripe, y + S(12), x + stripe + 1, y + S(27)), PX(120, 140, 180));
#undef S
}

static void arrow_disc(int cx, int cy, int radius, BOOL left, BOOL enabled)
{
    PIXEL glyph = C_WHITE;
    int d = radius / 2;

    if (enabled)
        disc(&canvas, cx, cy, radius, PX(124, 206, 110), PX(36, 136, 40));
    else
        disc(&canvas, cx, cy, radius, PX(214, 222, 232), PX(176, 188, 204));
    if (left) {
        line(&canvas, cx + d, cy, cx - d, cy, 2, glyph);
        line(&canvas, cx - d, cy, cx - 1, cy - d + 1, 2, glyph);
        line(&canvas, cx - d, cy, cx - 1, cy + d - 1, 2, glyph);
    } else {
        line(&canvas, cx - d, cy, cx + d, cy, 2, glyph);
        line(&canvas, cx + d, cy, cx + 1, cy - d + 1, 2, glyph);
        line(&canvas, cx + d, cy, cx + 1, cy + d - 1, 2, glyph);
    }
}

static void desktop_icon(int x, int y, const WCHAR *label, int kind)
{
    if (kind == 0)
        computer_icon(x + 20, y, 40);
    else if (kind == 1)
        folder_icon(&canvas, x + 20, y, 40);
    else
        trash_icon(x + 20, y, 40);
    text_shadow(&canvas, label, rect(x, y + 42, x + 80, y + 60), C_WHITE, font(11, FALSE),
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

static void draw_wallpaper(int width, int height)
{
    /* The welcome screen: two dark blue bands frame a lighter blue field. */
    static const STOP field[] = {{0, PX(74, 104, 204)}, {160, PX(96, 130, 222)}, {256, PX(122, 156, 238)}};
    const int band = 52, bottom = height - 30;

    gradient_stops(&canvas, rect(0, band, width, bottom - band), field, 3);
    glow(&canvas, 200, 100, 480, PX(198, 218, 252), 100);
    fill(&canvas, rect(0, 0, width, band), PX(10, 40, 140));
    /* rect() takes the right and bottom edges, not a width and a height. */
    fill(&canvas, rect(0, band, width, band + 2), PX(150, 176, 240));
    fill(&canvas, rect(0, bottom - band, width, bottom), PX(10, 40, 140));
    desktop_icon(14, band + 24, L"Computer", 0);
    desktop_icon(14, band + 110, L"Documents", 1);
    desktop_icon(14, band + 196, L"Trash", 2);
}

/* A panel of the Files task pane: a header and lines of links. */
static void task_panel(int left, int top, int right, const WCHAR *title, const WCHAR *const *links, int count)
{
    int bottom = top + 26 + 8 + count * 20, index;

    round_fill(&canvas, rect(left, top, right, top + 26), 4, CORNERS_TOP, C_WHITE, PX(198, 211, 247));
    fill(&canvas, rect(left, top + 26, right, bottom), PX(214, 223, 247));
    frame(&canvas, rect(left, top + 25, right, bottom), C_WHITE);
    line_text(title, rect(left + 12, top, right - 30, top + 26), PX(33, 93, 198), 11, TRUE);
    disc(&canvas, right - 14, top + 13, 9, C_WHITE, PX(214, 226, 250));
    ring(&canvas, right - 14, top + 13, 9, 1, PX(150, 176, 226));
    line(&canvas, right - 18, top + 15, right - 14, top + 11, 2, PX(60, 110, 200));
    line(&canvas, right - 14, top + 11, right - 10, top + 15, 2, PX(60, 110, 200));
    for (index = 0; index < count; ++index)
        line_text(links[index], rect(left + 14, top + 30 + index * 20, right - 8, top + 50 + index * 20),
                  PX(33, 93, 198), 11, FALSE);
}

static void draw_files(void)
{
    static const WCHAR *folder_tasks[] = {L"Make a new folder", L"Share this folder"};
    static const WCHAR *places[] = {L"Documents", L"Pictures", L"Computer"};
    static const WCHAR *details[] = {L"Home", L"5 folders"};
    static const WCHAR *folders[] = {L"Documents", L"Downloads", L"Music", L"Pictures", L"Videos"};
    RECT client = window_frame(&canvas, rect(420, 56, 1196, 596), L"Files — Home", TRUE);
    int left = client.left, right = client.right, top = client.top;
    int main_top = top + 90, main_bottom = client.bottom - 22, pane = left + 210, index;

    folder_icon(&canvas, 428, 62, 18);
    /* The menu bar, the toolbar, the address bar. */
    fill(&canvas, rect(left, top, right, top + 22), C_FACE);
    line_text(L"File      Edit      View      Go      Help", rect(left + 10, top, right, top + 22), C_INK, 11,
              FALSE);
    fill(&canvas, rect(left, top + 22, right, top + 23), C_FACE_LINE);
    gradient(&canvas, rect(left, top + 23, right, top + 60), C_WHITE, PX(222, 233, 251));
    arrow_disc(left + 22, top + 41, 13, TRUE, TRUE);
    line_text(L"Back", rect(left + 40, top + 23, left + 90, top + 60), C_INK, 11, FALSE);
    arrow_disc(left + 106, top + 41, 11, FALSE, FALSE);
    fill(&canvas, rect(left + 128, top + 28, left + 129, top + 55), C_FACE_LINE);
    folder_icon(&canvas, left + 138, top + 30, 22);
    line(&canvas, left + 149, top + 47, left + 149, top + 37, 2, PX(36, 136, 40));
    line(&canvas, left + 145, top + 41, left + 149, top + 37, 2, PX(36, 136, 40));
    line(&canvas, left + 153, top + 41, left + 149, top + 37, 2, PX(36, 136, 40));
    fill(&canvas, rect(left + 170, top + 28, left + 171, top + 55), C_FACE_LINE);
    ring(&canvas, left + 190, top + 39, 7, 2, PX(60, 90, 150));
    line(&canvas, left + 195, top + 44, left + 200, top + 49, 3, PX(60, 90, 150));
    line_text(L"Search", rect(left + 206, top + 23, left + 260, top + 60), C_INK, 11, FALSE);
    folder_icon(&canvas, left + 266, top + 31, 20);
    line_text(L"Folders", rect(left + 292, top + 23, left + 350, top + 60), C_INK, 11, FALSE);
    fill(&canvas, rect(left, top + 60, right, top + 61), C_FACE_LINE);
    fill(&canvas, rect(left, top + 61, right, top + 90), C_FACE);
    line_text(L"Address", rect(left + 8, top + 61, left + 60, top + 90), C_INK_SOFT, 11, FALSE);
    fill(&canvas, rect(left + 62, top + 65, right - 56, top + 86), C_WHITE);
    frame(&canvas, rect(left + 62, top + 65, right - 56, top + 86), PX(127, 157, 196));
    folder_icon(&canvas, left + 66, top + 68, 16);
    line_text(L"Home", rect(left + 88, top + 65, right - 60, top + 86), C_INK, 11, FALSE);
    arrow_disc(right - 42, top + 75, 8, FALSE, TRUE);
    line_text(L"Go", rect(right - 30, top + 61, right - 4, top + 90), C_INK, 11, FALSE);

    /* The task pane, then the folders. */
    gradient(&canvas, rect(left, main_top, pane, main_bottom), PX(122, 162, 231), PX(99, 117, 214));
    task_panel(left + 12, main_top + 12, pane - 12, L"Folder tasks", folder_tasks, 2);
    task_panel(left + 12, main_top + 106, pane - 12, L"Other places", places, 3);
    task_panel(left + 12, main_top + 220, pane - 12, L"Details", details, 2);
    fill(&canvas, rect(pane, main_top, right, main_bottom), C_WHITE);
    for (index = 0; index < 5; ++index) {
        int x = pane + 24 + (index % 4) * 128, y = main_top + 20 + (index / 4) * 104;
        if (index == 0) {
            round_fill(&canvas, rect(x + 8, y - 4, x + 104, y + 82), 3, CORNERS_ALL, PX(220, 233, 252),
                       PX(206, 222, 250));
            round_frame(&canvas, rect(x + 8, y - 4, x + 104, y + 82), 3, CORNERS_ALL, PX(132, 172, 236));
        }
        folder_icon(&canvas, x + 32, y + 4, 48);
        say(folders[index], rect(x, y + 58, x + 112, y + 78), C_INK, 11, FALSE,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
    fill(&canvas, rect(left, main_bottom, right, main_bottom + 1), C_FACE_LINE);
    fill(&canvas, rect(left, main_bottom + 1, right, client.bottom), C_FACE);
    line_text(L"5 objects", rect(left + 8, main_bottom, right, client.bottom), C_INK_SOFT, 11, FALSE);
    say(L"Home", rect(left, main_bottom, right - 12, client.bottom), C_INK_SOFT, 11, FALSE,
        DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

static void menu_item(int index, int left, int top, int right, const WCHAR *label, const WCHAR *detail)
{
    BOOL selected = index == selected_item;

    if (selected)
        fill(&canvas, rect(left, top, right, top + 44), C_SELECT);
    switch (index) {
    case 0:
        folder_icon(&canvas, left + 8, top + 6, 32);
        break;
    case 1:
        page_icon(left + 8, top + 6, 32);
        break;
    case 2:
        terminal_icon(left + 8, top + 6, 32);
        break;
    case 3:
        settings_icon(left + 8, top + 6, 32);
        break;
    case 4:
        software_icon(left + 8, top + 6, 32);
        break;
    default:
        help_icon(left + 8, top + 6, 32);
        break;
    }
    line_text(label, rect(left + 48, top + 4, right - 4, top + 24), selected ? C_WHITE : C_INK, 11, TRUE);
    line_text(detail, rect(left + 48, top + 22, right - 4, top + 40), selected ? PX(214, 228, 255) : C_INK_SOFT,
              11, FALSE);
}

/* A button of the menu's bottom bar: Restart or Shut down. */
static void power_button(int index, int x, int y, const WCHAR *label)
{
    if (index == selected_item) {
        round_fill(&canvas, rect(x - 4, y - 3, x + 104, y + 27), 3, CORNERS_ALL, PX(60, 130, 240), PX(40, 104, 222));
        round_frame(&canvas, rect(x - 4, y - 3, x + 104, y + 27), 3, CORNERS_ALL, PX(150, 200, 255));
    }
    if (index == 6)
        round_fill(&canvas, rect(x, y, x + 24, y + 24), 3, CORNERS_ALL, PX(255, 206, 90), PX(230, 140, 20));
    else
        round_fill(&canvas, rect(x, y, x + 24, y + 24), 3, CORNERS_ALL, PX(244, 120, 90), PX(200, 50, 24));
    round_frame(&canvas, rect(x, y, x + 24, y + 24), 3, CORNERS_ALL, C_WHITE);
    ring(&canvas, x + 12, y + 13, 7, 2, C_WHITE);
    if (index == 7)
        line(&canvas, x + 12, y + 4, x + 12, y + 11, 2, C_WHITE);
    else
        fill(&canvas, rect(x + 13, y + 4, x + 18, y + 9), index == 6 ? PX(240, 160, 40) : C_WHITE);
    line_text(label, rect(x + 30, y, x + 104, y + 24), C_WHITE, 11, FALSE);
}

static void draw_start_menu(int height)
{
    static const STOP band[] = {{0, PX(40, 124, 244)}, {120, PX(22, 92, 222)}, {256, PX(14, 72, 198)}};
    static const WCHAR *programs[] = {L"Files", L"Text Editor", L"Terminal", L"Settings", L"Software", L"Help"};
    static const WCHAR *details[] = {L"Browse your folders", L"Write plain text", L"Command prompt",
                                     L"Change how MINO OS looks", L"Add programs", L"Questions and answers"};
    static const WCHAR *places[] = {L"Documents", L"Pictures", L"Music", L"Computer"};
    static const WCHAR *system[] = {L"Network", L"Printers", L"Search", L"Run..."};
    int bottom = height - 30, top = bottom - 496, left = 0, right = 392, middle = 200;
    int body_top = top + 66, body_bottom = bottom - 46, index;

    round_fill(&canvas, rect(left, top, right, bottom), 8, CORNERS_TOP, PX(30, 98, 216), PX(20, 76, 196));
    round_fill_stops(&canvas, rect(left, top, right, top + 64), 8, CORNERS_TOP, band, 3);
    hgradient(&canvas, rect(left + 2, top + 64, right - 2, top + 66), PX(150, 206, 255), PX(30, 98, 216));
    round_fill(&canvas, rect(12, top + 9, 58, top + 55), 5, CORNERS_ALL, C_WHITE, PX(210, 226, 250));
    round_fill(&canvas, rect(15, top + 12, 55, top + 52), 3, CORNERS_ALL, PX(255, 212, 110), PX(236, 150, 46));
    emblem(&canvas, 35, top + 32, 15);
    text_shadow(&canvas, L"MINO OS User", rect(70, top, right - 12, top + 64), C_WHITE, font(15, TRUE),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    fill(&canvas, rect(left + 2, body_top, middle, body_bottom), C_WHITE);
    fill(&canvas, rect(middle, body_top, right - 2, body_bottom), PX(211, 229, 250));
    fill(&canvas, rect(middle, body_top, middle + 1, body_bottom), PX(149, 189, 238));
    for (index = 0; index < 6; ++index)
        menu_item(index, left + 2, body_top + 6 + index * 46, middle, programs[index], details[index]);
    fill(&canvas, rect(left + 12, body_bottom - 44, middle - 10, body_bottom - 43), PX(214, 222, 236));
    line_text(L"All programs", rect(left + 52, body_bottom - 40, middle - 40, body_bottom - 8), C_INK, 11, TRUE);
    arrow_disc(middle - 28, body_bottom - 24, 9, FALSE, TRUE);
    for (index = 0; index < 4; ++index) {
        int y = body_top + 10 + index * 36;
        if (index == 3)
            computer_icon(middle + 12, y + 2, 26);
        else
            folder_icon(&canvas, middle + 12, y + 2, 26);
        line_text(places[index], rect(middle + 46, y, right - 8, y + 30), PX(0, 38, 110), 11, TRUE);
    }
    fill(&canvas, rect(middle + 12, body_top + 160, right - 12, body_top + 161), PX(170, 200, 238));
    for (index = 0; index < 4; ++index) {
        int y = body_top + 170 + index * 34;
        disc(&canvas, middle + 25, y + 15, 10, PX(150, 196, 255), PX(50, 112, 220));
        line_text(system[index], rect(middle + 46, y, right - 8, y + 30), PX(0, 38, 110), 11, FALSE);
    }

    round_fill_stops(&canvas, rect(left, body_bottom, right, bottom), 0, 0, band, 3);
    power_button(6, right - 250, body_bottom + 11, L"Restart");
    power_button(7, right - 126, body_bottom + 11, L"Shut down");
}

static void draw_taskbar(int width, int height)
{
    static const STOP bar[] = {{0, PX(70, 150, 255)}, {14, PX(42, 116, 242)}, {48, PX(34, 100, 226)},
                               {200, PX(28, 86, 214)}, {256, PX(20, 64, 178)}};
    static const STOP start[] = {{0, PX(128, 206, 112)}, {36, PX(72, 164, 66)}, {200, PX(46, 128, 44)},
                                 {256, PX(34, 102, 34)}};
    static const STOP pressed[] = {{0, PX(52, 120, 46)}, {60, PX(60, 140, 54)}, {256, PX(76, 162, 66)}};
    static const STOP tray[] = {{0, PX(52, 176, 252)}, {30, PX(24, 148, 240)}, {256, PX(14, 116, 222)}};
    int top = height - 30;

    gradient_stops(&canvas, rect(0, top, width, height), bar, 5);
    round_fill_stops(&canvas, rect(0, top, 108, height), 12, CORNER_TR | CORNER_BR, menu_open ? pressed : start,
                     menu_open ? 3 : 4);
    emblem(&canvas, 20, top + 15, 10);
    text_shadow(&canvas, L"Start", rect(36, top, 104, height), C_WHITE, font(15, TRUE),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    round_fill(&canvas, rect(118, top + 3, 290, height - 3), 3, CORNERS_ALL, PX(24, 70, 186), PX(30, 84, 204));
    round_frame(&canvas, rect(118, top + 3, 290, height - 3), 3, CORNERS_ALL, PX(14, 46, 140));
    folder_icon(&canvas, 126, top + 7, 16);
    line_text(L"Files — Home", rect(148, top, 286, height), C_WHITE, 11, FALSE);

    gradient_stops(&canvas, rect(width - 124, top, width, height), tray, 3);
    fill(&canvas, rect(width - 124, top, width - 123, height), PX(16, 66, 170));
    fill(&canvas, rect(width - 123, top, width - 122, height), PX(110, 196, 255));
    /* Network and volume, as small marks. */
    round_fill(&canvas, rect(width - 112, top + 9, width - 100, top + 19), 1, CORNERS_ALL, PX(230, 240, 255),
               PX(170, 196, 236));
    fill(&canvas, rect(width - 107, top + 19, width - 105, top + 22), PX(230, 240, 255));
    fill(&canvas, rect(width - 92, top + 11, width - 88, top + 18), PX(230, 240, 255));
    line(&canvas, width - 88, top + 11, width - 84, top + 7, 2, PX(230, 240, 255));
    line(&canvas, width - 88, top + 18, width - 84, top + 22, 2, PX(230, 240, 255));
    fill(&canvas, rect(width - 84, top + 7, width - 82, top + 23), PX(230, 240, 255));
    say(L"14:32", rect(width - 70, top, width - 10, height), C_WHITE, 11, FALSE, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

static void draw(HDC dc)
{
    draw_wallpaper(canvas.width, canvas.height);
    draw_files();
    if (menu_open)
        draw_start_menu(canvas.height);
    draw_taskbar(canvas.width, canvas.height);
    canvas_present(&canvas, dc);
}

static void repaint(HWND window)
{
    InvalidateRect(window, 0, FALSE);
    UpdateWindow(window);
}

/* The entries of the Start menu, by their index in draw_start_menu. */
static const char *const entry_names[] = {"Files",    "Text Editor", "Terminal", "Settings",
                                          "Software", "Help",        "Restart",  "Shut down"};

/* What the mouse at (x, y) is over: an entry of the open menu (0 to 7), or
 * one of these. The rectangles are those draw_taskbar and draw_start_menu
 * paint. */
enum { HIT_OUTSIDE = -3, HIT_START = -2, HIT_MENU = -1 };

static int desktop_hit(int x, int y)
{
    int height = canvas.height, bottom = height - 30, top = bottom - 496;
    int body_top = top + 66, body_bottom = bottom - 46, index;

    if (y >= bottom && y < height && x >= 0 && x < 108)
        return HIT_START;
    if (!menu_open || x < 0 || x >= 392 || y < top || y >= bottom)
        return HIT_OUTSIDE;
    for (index = 0; index < 6; ++index) {
        int item_top = body_top + 6 + index * 46;
        if (x >= 2 && x < 200 && y >= item_top && y < item_top + 44)
            return index;
    }
    for (index = 6; index < 8; ++index) {
        int left = 392 - (index == 6 ? 250 : 126), button_top = body_bottom + 11;
        if (x >= left - 4 && x < left + 104 && y >= button_top - 3 && y < button_top + 27)
            return index;
    }
    return HIT_MENU;
}

/* A press of the left button: the Start button opens or closes the menu, a
 * press outside the open menu closes it, an entry is selected. The paint goes
 * before the marker: a scenario's screendump never catches the screen before
 * the change it names. */
static void click(HWND window, int x, int y)
{
    int hit = desktop_hit(x, y);

    if (hit == HIT_START || (hit == HIT_OUTSIDE && menu_open)) {
        menu_open = !menu_open;
        repaint(window);
        DbgPrint("[desktop] %s: start menu %s\n", hit == HIT_START ? "start button" : "press outside the menu",
                 menu_open ? "open" : "closed");
    } else if (hit >= 0) {
        selected_item = hit;
        repaint(window);
        DbgPrint("[desktop] selected %s\n", entry_names[hit]);
    }
}

static LRESULT __stdcall desktop_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    if (message == WM_ERASEBKGND)
        return 1;
    if (message == WM_PAINT) {
        BeginPaint(window, &paint);
        draw(paint.hdc);
        EndPaint(window, &paint);
        return 0;
    }
    if (message == WM_LBUTTONDOWN) {
        click(window, MOUSE_X(l), MOUSE_Y(l));
        return 0;
    }
    if (message == WM_KEYDOWN && menu_open) {
        if (w == VK_UP) {
            selected_item = selected_item ? selected_item - 1 : 7;
            repaint(window);
            return 0;
        }
        if (w == VK_DOWN) {
            selected_item = selected_item == 7 ? 0 : selected_item + 1;
            repaint(window);
            return 0;
        }
    }
    if (message == WM_CHAR) {
        if (w == VK_ESCAPE) {
            menu_open = FALSE;
            DbgPrint("[desktop] start menu closed\n");
            repaint(window);
            return 0;
        }
        if (w == VK_RETURN || w == VK_SPACE) {
            menu_open = !menu_open;
            DbgPrint("[desktop] start menu %s\n", menu_open ? "open" : "closed");
            repaint(window);
            return 0;
        }
    }
    return DefWindowProcW(window, message, w, l);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
    MSG message;
    int width;
    int height;

    if (!take_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = desktop_procedure;
    class_info.hInstance = instance;
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    width = GetSystemMetrics(SM_CXSCREEN);
    height = GetSystemMetrics(SM_CYSCREEN);
    if (!canvas_create(&canvas, width, height))
        ExitProcess(4);
    window = CreateWindowExW(0, CLASS_NAME, L"MINO OS Desktop", WS_POPUP | WS_VISIBLE,
                             0, 0, width, height, 0, 0, instance, 0);
    if (!window)
        ExitProcess(3);
    UpdateWindow(window);
    DbgPrint("[desktop] start menu open\n");
    DbgPrint("[desktop] ready\n");
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ExitProcess(0);
    return 0;
}
