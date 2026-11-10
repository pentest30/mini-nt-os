/*
 * Mino's blue theme for the native GUI probes: see theme.h.
 *
 * The shapes are anti-aliased by supersampling: 4 x 4 samples a pixel, in
 * eighths of a pixel, with integer arithmetic (lines use float, compared
 * only: no conversion helper from a C runtime is needed).
 */

#include "theme.h"

typedef struct {
    DWORD biSize;
    LONG biWidth;
    LONG biHeight;
    WORD biPlanes;
    WORD biBitCount;
    DWORD biCompression;
    DWORD biSizeImage;
    LONG biXPelsPerMeter;
    LONG biYPelsPerMeter;
    DWORD biClrUsed;
    DWORD biClrImportant;
} BITMAPINFOHEADER;

typedef struct {
    BITMAPINFOHEADER bmiHeader;
    DWORD bmiColors[1];
} BITMAPINFO;

#define BI_RGB 0
#define DIB_RGB_COLORS 0
#define SRCCOPY 0x00CC0020
#define TRANSPARENT 1
#define FW_NORMAL 400
#define FW_BOLD 700
#define DEFAULT_CHARSET 1

__declspec(dllimport) BOOL __stdcall BitBlt(HDC dest, int x, int y, int width, int height, HDC source, int x_source,
                                            int y_source, DWORD rop);
__declspec(dllimport) HDC __stdcall CreateCompatibleDC(HDC dc);
__declspec(dllimport) HBITMAP __stdcall CreateDIBSection(HDC dc, const BITMAPINFO *info, UINT usage, void **bits,
                                                         HANDLE section, DWORD offset);
__declspec(dllimport) HFONT __stdcall CreateFontW(int height, int width, int escapement, int orientation, int weight,
                                                  DWORD italic, DWORD underline, DWORD strike_out, DWORD char_set,
                                                  DWORD out_precision, DWORD clip_precision, DWORD quality,
                                                  DWORD pitch_and_family, const WCHAR *face);
__declspec(dllimport) BOOL __stdcall GdiFlush(void);
__declspec(dllimport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ object);
__declspec(dllimport) int __stdcall SetBkMode(HDC dc, int mode);
__declspec(dllimport) COLORREF __stdcall SetTextColor(HDC dc, COLORREF color);

void *memset(void *destination, int value, unsigned int count)
{
    BYTE *bytes = destination;
    while (count--)
        *bytes++ = (BYTE)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned int count)
{
    BYTE *to = destination;
    const BYTE *from = source;
    while (count--)
        *to++ = *from++;
    return destination;
}

RECT rect(LONG left, LONG top, LONG right, LONG bottom)
{
    RECT value = {left, top, right, bottom};
    return value;
}

static int clamp(int value, int low, int high)
{
    return value < low ? low : value > high ? high : value;
}

PIXEL mix(PIXEL from, PIXEL to, int amount)
{
    int r0 = (int)(from >> 16) & 0xFF, g0 = (int)(from >> 8) & 0xFF, b0 = (int)from & 0xFF;
    int r1 = (int)(to >> 16) & 0xFF, g1 = (int)(to >> 8) & 0xFF, b1 = (int)to & 0xFF;

    amount = clamp(amount, 0, 256);
    return PX(r0 + (((r1 - r0) * amount) >> 8), g0 + (((g1 - g0) * amount) >> 8), b0 + (((b1 - b0) * amount) >> 8));
}

static COLORREF colorref(PIXEL color)
{
    return ((color >> 16) & 0xFF) | (color & 0xFF00) | ((color & 0xFF) << 16);
}

/* The text win32k has queued in the TEB's batch is drawn before the program
 * touches the pixels again: the painter's order holds. */
static void sync(CANVAS *canvas)
{
    if (canvas->text_pending) {
        GdiFlush();
        canvas->text_pending = FALSE;
    }
}

BOOL canvas_create(CANVAS *canvas, int width, int height)
{
    BITMAPINFO info;

    memset(canvas, 0, sizeof *canvas);
    memset(&info, 0, sizeof info);
    info.bmiHeader.biSize = sizeof info.bmiHeader;
    info.bmiHeader.biWidth = width;
    info.bmiHeader.biHeight = -height; /* rows from the top down */
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    canvas->dc = CreateCompatibleDC(0);
    canvas->bitmap = CreateDIBSection(0, &info, DIB_RGB_COLORS, (void **)&canvas->bits, 0, 0);
    if (!canvas->dc || !canvas->bitmap || !canvas->bits)
        return FALSE;
    SelectObject(canvas->dc, canvas->bitmap);
    SetBkMode(canvas->dc, TRANSPARENT);
    canvas->width = width;
    canvas->height = height;
    return TRUE;
}

void canvas_present(CANVAS *canvas, HDC target)
{
    /* BitBlt is a service of win32k: the batch of text goes first. */
    BitBlt(target, 0, 0, canvas->width, canvas->height, canvas->dc, 0, 0, SRCCOPY);
    canvas->text_pending = FALSE;
}

/* The area, cut to the canvas. */
static BOOL clip(const CANVAS *canvas, RECT *area)
{
    area->left = clamp(area->left, 0, canvas->width);
    area->right = clamp(area->right, 0, canvas->width);
    area->top = clamp(area->top, 0, canvas->height);
    area->bottom = clamp(area->bottom, 0, canvas->height);
    return area->left < area->right && area->top < area->bottom;
}

static void put(CANVAS *canvas, int x, int y, PIXEL color, int amount)
{
    PIXEL *pixel;

    if (x < 0 || y < 0 || x >= canvas->width || y >= canvas->height || amount <= 0)
        return;
    pixel = &canvas->bits[y * canvas->width + x];
    *pixel = amount >= 256 ? color : mix(*pixel, color, amount);
}

static void row(CANVAS *canvas, int y, int left, int right, PIXEL color)
{
    PIXEL *pixel = &canvas->bits[y * canvas->width + left];
    int x;

    for (x = left; x < right; ++x)
        *pixel++ = color;
}

void fill(CANVAS *canvas, RECT area, PIXEL color)
{
    int y;

    sync(canvas);
    if (!clip(canvas, &area))
        return;
    for (y = area.top; y < area.bottom; ++y)
        row(canvas, y, area.left, area.right, color);
}

void frame(CANVAS *canvas, RECT area, PIXEL color)
{
    fill(canvas, rect(area.left, area.top, area.right, area.top + 1), color);
    fill(canvas, rect(area.left, area.bottom - 1, area.right, area.bottom), color);
    fill(canvas, rect(area.left, area.top, area.left + 1, area.bottom), color);
    fill(canvas, rect(area.right - 1, area.top, area.right, area.bottom), color);
}

/* The colour of a vertical gradient at `y` of a band [top, bottom). */
static PIXEL stop_color(const STOP *stops, int count, int y, int top, int bottom)
{
    int span = bottom - top - 1;
    int at = span > 0 ? (y - top) * 256 / span : 0;
    int index;

    if (at <= stops[0].at)
        return stops[0].color;
    for (index = 0; index + 1 < count; ++index) {
        if (at <= stops[index + 1].at) {
            int width = stops[index + 1].at - stops[index].at;
            return mix(stops[index].color, stops[index + 1].color,
                       width > 0 ? (at - stops[index].at) * 256 / width : 256);
        }
    }
    return stops[count - 1].color;
}

void gradient_stops(CANVAS *canvas, RECT area, const STOP *stops, int count)
{
    RECT full = area;
    int y;

    sync(canvas);
    if (!clip(canvas, &area))
        return;
    for (y = area.top; y < area.bottom; ++y)
        row(canvas, y, area.left, area.right, stop_color(stops, count, y, full.top, full.bottom));
}

void gradient(CANVAS *canvas, RECT area, PIXEL top, PIXEL bottom)
{
    STOP stops[2] = {{0, top}, {256, bottom}};
    gradient_stops(canvas, area, stops, 2);
}

void hgradient(CANVAS *canvas, RECT area, PIXEL left, PIXEL right)
{
    RECT full = area;
    int x, y, span = area.right - area.left - 1;

    sync(canvas);
    if (!clip(canvas, &area))
        return;
    for (x = area.left; x < area.right; ++x) {
        PIXEL color = mix(left, right, span > 0 ? (x - full.left) * 256 / span : 0);
        for (y = area.top; y < area.bottom; ++y)
            canvas->bits[y * canvas->width + x] = color;
    }
}

void shade(CANVAS *canvas, RECT area, PIXEL color, int alpha)
{
    int x, y;

    sync(canvas);
    if (!clip(canvas, &area))
        return;
    for (y = area.top; y < area.bottom; ++y)
        for (x = area.left; x < area.right; ++x)
            put(canvas, x, y, color, alpha);
}

/* A soft light: `alpha` at the centre, nothing at `radius`. */
void glow(CANVAS *canvas, int cx, int cy, int radius, PIXEL color, int alpha)
{
    RECT area = rect(cx - radius, cy - radius, cx + radius, cy + radius);
    int x, y, r2 = radius * radius;

    sync(canvas);
    if (!clip(canvas, &area))
        return;
    for (y = area.top; y < area.bottom; ++y)
        for (x = area.left; x < area.right; ++x) {
            int d2 = (x - cx) * (x - cx) + (y - cy) * (y - cy);
            if (d2 < r2)
                put(canvas, x, y, color, alpha * (r2 - d2) / r2);
        }
}

/* How much of the pixel (x, y) a rounded rectangle covers: 0 to 16. */
static int coverage(int x, int y, RECT area, int radius, int corners)
{
    int cx, cy, samples = 0, i, j, r8;

    if (x < area.left || x >= area.right || y < area.top || y >= area.bottom)
        return 0;
    if (radius <= 0)
        return 16;
    if ((corners & CORNER_TL) && x < area.left + radius && y < area.top + radius) {
        cx = area.left + radius;
        cy = area.top + radius;
    } else if ((corners & CORNER_TR) && x >= area.right - radius && y < area.top + radius) {
        cx = area.right - radius;
        cy = area.top + radius;
    } else if ((corners & CORNER_BL) && x < area.left + radius && y >= area.bottom - radius) {
        cx = area.left + radius;
        cy = area.bottom - radius;
    } else if ((corners & CORNER_BR) && x >= area.right - radius && y >= area.bottom - radius) {
        cx = area.right - radius;
        cy = area.bottom - radius;
    } else {
        return 16;
    }
    r8 = radius * 8;
    for (j = 0; j < 4; ++j) {
        int dy = y * 8 + j * 2 + 1 - cy * 8;
        for (i = 0; i < 4; ++i) {
            int dx = x * 8 + i * 2 + 1 - cx * 8;
            if (dx * dx + dy * dy <= r8 * r8)
                ++samples;
        }
    }
    return samples;
}

void round_fill_stops(CANVAS *canvas, RECT area, int radius, int corners, const STOP *stops, int count)
{
    RECT cut = area;
    int x, y;

    sync(canvas);
    if (!clip(canvas, &cut))
        return;
    for (y = cut.top; y < cut.bottom; ++y) {
        PIXEL color = stop_color(stops, count, y, area.top, area.bottom);
        if (y >= area.top + radius && y < area.bottom - radius) {
            row(canvas, y, cut.left, cut.right, color);
            continue;
        }
        for (x = cut.left; x < cut.right; ++x)
            put(canvas, x, y, color, coverage(x, y, area, radius, corners) * 16);
    }
}

void round_fill(CANVAS *canvas, RECT area, int radius, int corners, PIXEL top, PIXEL bottom)
{
    STOP stops[2] = {{0, top}, {256, bottom}};
    round_fill_stops(canvas, area, radius, corners, stops, 2);
}

void round_frame(CANVAS *canvas, RECT area, int radius, int corners, PIXEL color)
{
    RECT inner = rect(area.left + 1, area.top + 1, area.right - 1, area.bottom - 1);
    int x, y, inner_radius = radius > 1 ? radius - 1 : 0;

    sync(canvas);
    for (y = area.top; y < area.bottom; ++y) {
        if (y > area.top + radius && y < area.bottom - radius - 1) {
            put(canvas, area.left, y, color, 256);
            put(canvas, area.right - 1, y, color, 256);
            continue;
        }
        for (x = area.left; x < area.right; ++x) {
            int amount = coverage(x, y, area, radius, corners) - coverage(x, y, inner, inner_radius, corners);
            put(canvas, x, y, color, amount * 16);
        }
    }
}

/* How much of the pixel (x, y) a disc of centre (cx, cy) covers. */
static int disc_coverage(int x, int y, int cx, int cy, int radius)
{
    int samples = 0, i, j, r8 = radius * 8;

    for (j = 0; j < 4; ++j) {
        int dy = y * 8 + j * 2 + 1 - cy * 8;
        for (i = 0; i < 4; ++i) {
            int dx = x * 8 + i * 2 + 1 - cx * 8;
            if (dx * dx + dy * dy <= r8 * r8)
                ++samples;
        }
    }
    return samples;
}

void disc(CANVAS *canvas, int cx, int cy, int radius, PIXEL top, PIXEL bottom)
{
    int x, y;

    sync(canvas);
    for (y = cy - radius; y < cy + radius; ++y) {
        PIXEL color = mix(top, bottom, (y - cy + radius) * 256 / (2 * radius));
        for (x = cx - radius; x < cx + radius; ++x)
            put(canvas, x, y, color, disc_coverage(x, y, cx, cy, radius) * 16);
    }
}

void ring(CANVAS *canvas, int cx, int cy, int radius, int width, PIXEL color)
{
    int x, y, inner = radius - width;

    sync(canvas);
    for (y = cy - radius; y < cy + radius; ++y)
        for (x = cx - radius; x < cx + radius; ++x) {
            int amount = disc_coverage(x, y, cx, cy, radius) - (inner > 0 ? disc_coverage(x, y, cx, cy, inner) : 0);
            put(canvas, x, y, color, amount * 16);
        }
}

/* A segment `width` pixels thick, with round ends. */
void line(CANVAS *canvas, int x0, int y0, int x1, int y1, int width, PIXEL color)
{
    float ax = (float)x0, ay = (float)y0, bx = (float)x1, by = (float)y1;
    float ux = bx - ax, uy = by - ay, length = ux * ux + uy * uy;
    float half = (float)width / 2.0f;
    int left = (x0 < x1 ? x0 : x1) - width, right = (x0 > x1 ? x0 : x1) + width;
    int top = (y0 < y1 ? y0 : y1) - width, bottom = (y0 > y1 ? y0 : y1) + width;
    int x, y, i, j;

    sync(canvas);
    for (y = top; y <= bottom; ++y)
        for (x = left; x <= right; ++x) {
            int samples = 0;
            for (j = 0; j < 4; ++j)
                for (i = 0; i < 4; ++i) {
                    float px = (float)x + (float)(i * 2 + 1) / 8.0f;
                    float py = (float)y + (float)(j * 2 + 1) / 8.0f;
                    float t = length > 0.0f ? ((px - ax) * ux + (py - ay) * uy) / length : 0.0f;
                    float dx, dy;
                    if (t < 0.0f)
                        t = 0.0f;
                    if (t > 1.0f)
                        t = 1.0f;
                    dx = px - (ax + t * ux);
                    dy = py - (ay + t * uy);
                    if (dx * dx + dy * dy <= half * half)
                        ++samples;
                }
            put(canvas, x, y, color, samples * 16);
        }
}

HFONT font(int pixels, BOOL bold)
{
    static struct {
        int pixels;
        BOOL bold;
        HFONT font;
    } cache[12];
    static int cached;
    int index;

    for (index = 0; index < cached; ++index)
        if (cache[index].pixels == pixels && cache[index].bold == bold)
            return cache[index].font;
    if (cached == (int)(sizeof cache / sizeof cache[0]))
        return cache[0].font;
    cache[cached].pixels = pixels;
    cache[cached].bold = bold;
    cache[cached].font =
        CreateFontW(-pixels, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Tahoma");
    return cache[cached++].font;
}

void text(CANVAS *canvas, const WCHAR *value, RECT area, PIXEL color, HFONT face, UINT flags)
{
    SelectObject(canvas->dc, face);
    SetTextColor(canvas->dc, colorref(color));
    DrawTextW(canvas->dc, value, -1, &area, flags | DT_NOPREFIX);
    canvas->text_pending = TRUE;
}

void text_shadow(CANVAS *canvas, const WCHAR *value, RECT area, PIXEL color, HFONT face, UINT flags)
{
    text(canvas, value, rect(area.left + 1, area.top + 1, area.right + 1, area.bottom + 1), PX(0, 28, 110), face,
         flags);
    text(canvas, value, area, color, face, flags);
}

void caption_button(CANVAS *canvas, int x, int y, enum Glyph glyph)
{
    RECT area = rect(x, y, x + 21, y + 21);

    if (glyph == GLYPH_CLOSE)
        round_fill(canvas, area, 3, CORNERS_ALL, PX(236, 128, 92), PX(204, 62, 28));
    else
        round_fill(canvas, area, 3, CORNERS_ALL, PX(92, 156, 255), PX(30, 92, 232));
    round_frame(canvas, area, 3, CORNERS_ALL, PX(255, 255, 255));
    switch (glyph) {
    case GLYPH_MINIMIZE:
        fill(canvas, rect(x + 5, y + 13, x + 12, y + 16), C_WHITE);
        break;
    case GLYPH_MAXIMIZE:
        frame(canvas, rect(x + 5, y + 5, x + 16, y + 16), C_WHITE);
        fill(canvas, rect(x + 5, y + 5, x + 16, y + 8), C_WHITE);
        break;
    case GLYPH_CLOSE:
        line(canvas, x + 6, y + 6, x + 14, y + 14, 2, C_WHITE);
        line(canvas, x + 14, y + 6, x + 6, y + 14, 2, C_WHITE);
        break;
    }
}

RECT window_frame(CANVAS *canvas, RECT area, const WCHAR *title, BOOL with_size_buttons)
{
    static const STOP caption[] = {{0, PX(96, 164, 255)},  {24, PX(44, 128, 255)}, {70, PX(10, 96, 242)},
                                   {150, PX(0, 84, 230)},  {220, PX(0, 76, 218)},  {256, PX(0, 62, 196)}};
    RECT bar = rect(area.left, area.top, area.right, area.top + 30);
    int close = area.right - 27;

    /* A soft shadow under the window. */
    shade(canvas, rect(area.left + 4, area.bottom, area.right + 4, area.bottom + 4), PX(0, 0, 0), 40);
    shade(canvas, rect(area.right, area.top + 8, area.right + 4, area.bottom), PX(0, 0, 0), 40);
    round_fill(canvas, area, 8, CORNERS_TOP, PX(0, 70, 214), PX(0, 54, 186));
    round_fill_stops(canvas, bar, 8, CORNERS_TOP, caption, 6);
    hgradient(canvas, rect(area.left + 1, bar.bottom, area.left + 4, area.bottom - 1), PX(0, 46, 172),
              PX(22, 104, 240));
    hgradient(canvas, rect(area.right - 4, bar.bottom, area.right - 1, area.bottom - 1), PX(22, 104, 240),
              PX(0, 46, 172));
    gradient(canvas, rect(area.left + 1, area.bottom - 4, area.right - 1, area.bottom - 1), PX(16, 96, 236),
             PX(0, 46, 172));
    round_frame(canvas, area, 8, CORNERS_TOP, PX(0, 28, 132));
    text_shadow(canvas, title, rect(area.left + 32, area.top + 1, close - 50, bar.bottom), C_WHITE, font(13, TRUE),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    caption_button(canvas, close, area.top + 5, GLYPH_CLOSE);
    if (with_size_buttons) {
        caption_button(canvas, close - 23, area.top + 5, GLYPH_MAXIMIZE);
        caption_button(canvas, close - 46, area.top + 5, GLYPH_MINIMIZE);
    }
    return rect(area.left + 4, bar.bottom, area.right - 4, area.bottom - 4);
}

void button(CANVAS *canvas, RECT area, const WCHAR *label, enum ButtonState state)
{
    RECT inner = rect(area.left + 1, area.top + 1, area.right - 1, area.bottom - 1);

    if (state == BUTTON_DISABLED) {
        round_fill(canvas, area, 3, CORNERS_ALL, PX(248, 250, 254), PX(238, 242, 250));
        round_frame(canvas, area, 3, CORNERS_ALL, PX(186, 198, 222));
        text(canvas, label, area, PX(158, 168, 188), font(11, FALSE), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return;
    }
    round_fill(canvas, area, 3, CORNERS_ALL, PX(255, 255, 255), PX(214, 228, 250));
    fill(canvas, rect(area.left + 2, area.bottom - 3, area.right - 2, area.bottom - 1), PX(196, 212, 240));
    if (state == BUTTON_FOCUSED) {
        round_frame(canvas, inner, 2, CORNERS_ALL, PX(118, 160, 246));
        round_frame(canvas, rect(inner.left + 1, inner.top + 1, inner.right - 1, inner.bottom - 1), 2, CORNERS_ALL,
                    PX(176, 206, 255));
    }
    round_frame(canvas, area, 3, CORNERS_ALL, PX(0, 52, 128));
    text(canvas, label, area, C_INK, font(11, state == BUTTON_FOCUSED), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void progress_bar(CANVAS *canvas, RECT area, int percent)
{
    static const STOP block[] = {{0, PX(178, 218, 255)}, {110, PX(70, 146, 250)}, {190, PX(34, 104, 232)},
                                 {256, PX(86, 156, 252)}};
    int left = area.left + 3, right = area.right - 3, filled, x;

    round_fill(canvas, area, 3, CORNERS_ALL, PX(255, 255, 255), PX(236, 242, 252));
    round_frame(canvas, area, 3, CORNERS_ALL, PX(112, 136, 184));
    filled = left + (right - left) * clamp(percent, 0, 100) / 100;
    for (x = left; x + 8 <= filled; x += 10)
        round_fill_stops(canvas, rect(x, area.top + 3, x + 8, area.bottom - 3), 1, CORNERS_ALL, block, 4);
}

void check_mark(CANVAS *canvas, int x, int y, int size, PIXEL color)
{
    line(canvas, x, y + size / 2, x + size / 3, y + size - 1, 2, color);
    line(canvas, x + size / 3, y + size - 1, x + size - 1, y + 1, 2, color);
}

/* A folder of `size` pixels, drawn from shapes. */
void folder_icon(CANVAS *canvas, int x, int y, int size)
{
#define S(v) ((v) * size / 32)
    round_fill(canvas, rect(x + S(2), y + S(4), x + S(14), y + S(10)), S(2), CORNERS_TOP, PX(250, 214, 112),
               PX(236, 186, 70));
    round_fill(canvas, rect(x, y + S(7), x + S(32), y + S(29)), S(2), CORNERS_ALL, PX(240, 198, 86),
               PX(214, 162, 44));
    round_fill(canvas, rect(x + S(1), y + S(11), x + S(31), y + S(29)), S(2), CORNERS_ALL, PX(255, 234, 156),
               PX(244, 194, 76));
    round_frame(canvas, rect(x, y + S(7), x + S(32), y + S(29)), S(2), CORNERS_ALL, PX(186, 136, 28));
#undef S
}

/* Mino's emblem: a blue disc, a white ring and an M of strokes. */
void emblem(CANVAS *canvas, int cx, int cy, int radius)
{
    int half = radius / 2, stroke = radius / 4 > 1 ? radius / 4 : 2;

    disc(canvas, cx, cy, radius, PX(126, 186, 255), PX(18, 78, 208));
    ring(canvas, cx, cy, radius, radius / 8 > 1 ? radius / 8 : 1, C_WHITE);
    line(canvas, cx - half, cy + half - 1, cx - half, cy - half + 1, stroke, C_WHITE);
    line(canvas, cx - half, cy - half + 1, cx, cy + half / 3, stroke, C_WHITE);
    line(canvas, cx, cy + half / 3, cx + half, cy - half + 1, stroke, C_WHITE);
    line(canvas, cx + half, cy - half + 1, cx + half, cy + half - 1, stroke, C_WHITE);
}

void card(CANVAS *canvas, RECT area, PIXEL background, PIXEL border, PIXEL accent)
{
    round_fill(canvas, area, 4, CORNERS_ALL, background, background);
    round_frame(canvas, area, 4, CORNERS_ALL, border);
    fill(canvas, rect(area.left + 1, area.top + 4, area.left + 4, area.bottom - 4), accent);
}

BOOL take_desktop(void)
{
    HWINSTA station;
    HDESK desktop;

    /* A child launched by BOOT1.EXE already belongs to WinSta0 and its
       STARTUPINFO names Default. Its first USER call attaches the thread to
       that inherited desktop, so it must not try to become a second logon
       process. Direct test scenarios still take the original path below. */
    station = GetProcessWindowStation();
    if (station)
        return TRUE;
    if (!RegisterLogonProcess(GetCurrentProcessId(), TRUE))
        return FALSE;
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station))
        return FALSE;
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    return desktop && SetThreadDesktop(desktop) && SwitchDesktop(desktop);
}
