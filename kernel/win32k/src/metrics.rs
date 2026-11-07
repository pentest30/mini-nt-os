//! Les métriques du système (`SERVERINFO.aiSysMet`, GetSystemMetrics) et
//! les couleurs système (`argbSystem`, GetSysColor), que `user32` lit dans
//! la section partagée de USER.
//!
//! Comme InitMetrics de ReactOS (`metric.c`, comme spécification), d'après
//! la taille de l'écran (640 × 480 sans pilote d'affichage, comme ReactOS
//! sans MDEV) et les paramètres du système (`sysparams.c`) : la ruche de
//! l'utilisateur (`Control Panel\Desktop\WindowMetrics`) n'est pas chargée,
//! ce sont donc leurs valeurs par défaut ([`Parameters::DEFAULT`]). Écrites
//! à NtUserInitialize ([`write()`]), comme InitVideo et CreateSysColorObjects.
//!
//! Pas encore : les pinceaux système (`ahbrSystem`, GDI), les polices
//! (`tmSysFont`), le reste de `PERUSERSERVERINFO`.

use core::mem::{offset_of, size_of};

use abi::ntstatus::{NtStatus, STATUS_UNSUCCESSFUL};
use abi::user::{sm, ServerInfo32, NUM_SYSCOLORS, SM_CMETRICS};

/// Les paramètres du système dont les métriques découlent (SPIVALUES :
/// NONCLIENTMETRICS, MINIMIZEDMETRICS, ICONMETRICS, souris, polices).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub border_width: i32,
    pub scroll_width: i32,
    pub scroll_height: i32,
    pub caption_width: i32,
    pub caption_height: i32,
    pub sm_caption_width: i32,
    pub sm_caption_height: i32,
    pub menu_width: i32,
    pub menu_height: i32,
    pub minimized_width: i32,
    pub minimized_horizontal_gap: i32,
    pub minimized_vertical_gap: i32,
    pub minimized_arrange: i32,
    pub icon_horizontal_spacing: i32,
    pub icon_vertical_spacing: i32,
    pub double_click_width: i32,
    pub double_click_height: i32,
    pub caption_font_average_width: i32,
    pub menu_font_height: i32,
    pub menu_font_external_leading: i32,
}

impl Parameters {
    /// Les valeurs par défaut de ReactOS (SpiUpdatePerUserSystemParameters,
    /// SpiFixupValues).
    pub const DEFAULT: Parameters = Parameters {
        border_width: 1,
        scroll_width: 16,
        scroll_height: 16,
        caption_width: 19,
        caption_height: 19,
        sm_caption_width: 12,
        sm_caption_height: 15,
        menu_width: 18,
        menu_height: 18,
        minimized_width: 160,
        minimized_horizontal_gap: 160,
        minimized_vertical_gap: 24,
        // ARW_HIDE.
        minimized_arrange: 8,
        icon_horizontal_spacing: 64,
        icon_vertical_spacing: 64,
        double_click_width: 4,
        double_click_height: 4,
        caption_font_average_width: 6,
        menu_font_height: 11,
        menu_font_external_leading: 2,
    };
}

/// InitMetrics : les métriques d'un écran de `width` × `height` pixels.
pub fn system_metrics(width: i32, height: i32, p: &Parameters) -> [i32; SM_CMETRICS] {
    let mut m = [0i32; SM_CMETRICS];
    m[sm::CXSCREEN] = width;
    m[sm::CYSCREEN] = height;
    m[sm::CXVIRTUALSCREEN] = width;
    m[sm::CYVIRTUALSCREEN] = height;
    // The non-client area.
    m[sm::CYCAPTION] = p.caption_height + 1;
    m[sm::CYSMCAPTION] = p.sm_caption_height + 1;
    m[sm::CXSIZE] = p.caption_height;
    m[sm::CYSIZE] = p.caption_height;
    m[sm::CXSMSIZE] = p.sm_caption_width;
    m[sm::CYSMSIZE] = p.sm_caption_height;
    m[sm::CXBORDER] = 1;
    m[sm::CYBORDER] = 1;
    m[sm::CXFOCUSBORDER] = 1;
    m[sm::CYFOCUSBORDER] = 1;
    m[sm::CXDLGFRAME] = 3;
    m[sm::CYDLGFRAME] = 3;
    m[sm::CXEDGE] = 2;
    m[sm::CYEDGE] = 2;
    m[sm::CXFRAME] = m[sm::CXDLGFRAME] + p.border_width;
    m[sm::CYFRAME] = m[sm::CYDLGFRAME] + p.border_width;
    // Windows.
    m[sm::CXMIN] =
        3 * p.caption_width.max(8) + m[sm::CYSIZE] + 4 + 4 * p.caption_font_average_width + 2 * m[sm::CXFRAME];
    m[sm::CYMIN] = m[sm::CYCAPTION] + 2 * m[sm::CYFRAME];
    m[sm::CXMAXIMIZED] = m[sm::CXSCREEN] + 2 * m[sm::CXFRAME];
    m[sm::CYMAXIMIZED] = m[sm::CYSCREEN] - 20;
    m[sm::CXFULLSCREEN] = m[sm::CXSCREEN];
    m[sm::CYFULLSCREEN] = m[sm::CYMAXIMIZED] - m[sm::CYMIN];
    m[sm::CXMINIMIZED] = p.minimized_width + 6;
    m[sm::CYMINIMIZED] = m[sm::CYCAPTION] + 5;
    m[sm::CXMINSPACING] = m[sm::CXMINIMIZED] + p.minimized_horizontal_gap;
    m[sm::CYMINSPACING] = m[sm::CYMINIMIZED] + p.minimized_vertical_gap;
    m[sm::CXMAXTRACK] = m[sm::CXVIRTUALSCREEN] + 4 + 2 * m[sm::CXFRAME];
    m[sm::CYMAXTRACK] = m[sm::CYVIRTUALSCREEN] + 4 + 2 * m[sm::CYFRAME];
    // Scroll bars, icons, cursors.
    m[sm::CXVSCROLL] = p.scroll_width;
    m[sm::CYVTHUMB] = p.scroll_height;
    m[sm::CYHSCROLL] = p.scroll_width;
    m[sm::CXHTHUMB] = p.scroll_height;
    m[sm::CYVSCROLL] = p.scroll_height;
    m[sm::CXHSCROLL] = p.scroll_height;
    m[sm::CXICON] = 32;
    m[sm::CYICON] = 32;
    m[sm::CXSMICON] = 16;
    m[sm::CYSMICON] = 16;
    m[sm::CXICONSPACING] = p.icon_horizontal_spacing;
    m[sm::CYICONSPACING] = p.icon_vertical_spacing;
    m[sm::CXCURSOR] = 32;
    m[sm::CYCURSOR] = 32;
    m[sm::CXMINTRACK] = m[sm::CXMIN];
    m[sm::CYMINTRACK] = m[sm::CYMIN];
    m[sm::CXDRAG] = 4;
    m[sm::CYDRAG] = 4;
    m[sm::ARRANGE] = p.minimized_arrange;
    // Menus.
    m[sm::CYMENU] = p.menu_height + 1;
    m[sm::CXMENUCHECK] = ((1 + p.menu_font_height + p.menu_font_external_leading) & !1) - 1;
    m[sm::CYMENUCHECK] = m[sm::CXMENUCHECK];
    m[sm::CXMENUSIZE] = p.menu_width;
    m[sm::CYMENUSIZE] = p.menu_height;
    // The mouse.
    m[sm::MOUSEPRESENT] = 1;
    m[sm::MOUSEWHEELPRESENT] = 1;
    m[sm::CMOUSEBUTTONS] = 2;
    m[sm::CXDOUBLECLK] = p.double_click_width;
    m[sm::CYDOUBLECLK] = p.double_click_height;
    // The rest: a network, one monitor (no DBCS code page, no IME).
    m[sm::NETWORK] = 3;
    m[sm::CMONITORS] = 1;
    m[sm::SAMEDISPLAYFORMAT] = 1;
    m
}

/// Les couleurs système par défaut de ReactOS (`SysColors`,
/// `win32ss/gdi/ntgdi/stockobj.c`), `COLOR_SCROLLBAR` à `COLOR_MENUBAR`, en
/// COLORREF (0x00BBGGRR).
pub const SYSTEM_COLORS: [u32; NUM_SYSCOLORS] = [
    rgb(212, 208, 200), // COLOR_SCROLLBAR
    rgb(219, 213, 197), // COLOR_BACKGROUND
    rgb(10, 36, 106),   // COLOR_ACTIVECAPTION
    rgb(128, 128, 128), // COLOR_INACTIVECAPTION
    rgb(212, 208, 200), // COLOR_MENU
    rgb(255, 255, 255), // COLOR_WINDOW
    rgb(0, 0, 0),       // COLOR_WINDOWFRAME
    rgb(0, 0, 0),       // COLOR_MENUTEXT
    rgb(0, 0, 0),       // COLOR_WINDOWTEXT
    rgb(255, 255, 255), // COLOR_CAPTIONTEXT
    rgb(212, 208, 200), // COLOR_ACTIVEBORDER
    rgb(212, 208, 200), // COLOR_INACTIVEBORDER
    rgb(128, 128, 128), // COLOR_APPWORKSPACE
    rgb(10, 36, 106),   // COLOR_HIGHLIGHT
    rgb(255, 255, 255), // COLOR_HIGHLIGHTTEXT
    rgb(212, 208, 200), // COLOR_BTNFACE
    rgb(128, 128, 128), // COLOR_BTNSHADOW
    rgb(128, 128, 128), // COLOR_GRAYTEXT
    rgb(0, 0, 0),       // COLOR_BTNTEXT
    rgb(212, 208, 200), // COLOR_INACTIVECAPTIONTEXT
    rgb(255, 255, 255), // COLOR_BTNHIGHLIGHT
    rgb(64, 64, 64),    // COLOR_3DDKSHADOW
    rgb(212, 208, 200), // COLOR_3DLIGHT
    rgb(0, 0, 0),       // COLOR_INFOTEXT
    rgb(255, 255, 225), // COLOR_INFOBK
    rgb(181, 181, 181), // COLOR_UNKNOWN
    rgb(0, 0, 128),     // COLOR_HOTLIGHT
    rgb(166, 202, 240), // COLOR_GRADIENTACTIVECAPTION
    rgb(192, 192, 192), // COLOR_GRADIENTINACTIVECAPTION
    rgb(49, 106, 197),  // COLOR_MENUHILIGHT
    rgb(236, 233, 216), // COLOR_MENUBAR
];

/// RGB(r, g, b) : un COLORREF.
const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}

/// Les métriques en vigueur, une fois écrites (pour les calculs de
/// win32k : bordures, zone cliente).
static METRICS: hal::sync::KSpinLock<Option<[i32; SM_CMETRICS]>> = hal::sync::KSpinLock::new(None);

/// UserGetSystemMetrics : la métrique `index` ; 0 avant [`write()`] ou hors
/// de la table.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get(index: usize) -> i32 {
    METRICS.lock().as_ref().and_then(|metrics| metrics.get(index).copied()).unwrap_or(0)
}

/// InitMetrics et les couleurs système : les écrit dans le `SERVERINFO`,
/// d'après le mode de l'écran ; avec un affichage, attache son moniteur
/// ([`crate::monitor::attach`]).
///
/// # Errors
/// `STATUS_UNSUCCESSFUL` avant la section partagée ; celles de son écriture
/// et de la table des handles.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn write() -> Result<(), NtStatus> {
    let mode = crate::display::mode();
    let (width, height) = mode.map_or((640, 480), |mode| (mode.width as i32, mode.height as i32));
    let metrics = system_metrics(width, height, &Parameters::DEFAULT);
    let section = crate::shared::section().ok_or(STATUS_UNSUCCESSFUL)?;
    let at = |field: usize| u64::from(crate::shared::SERVER_INFO) + field as u64;
    let bytes: alloc::vec::Vec<u8> = metrics.iter().flat_map(|value| value.to_le_bytes()).collect();
    section.write_kernel(at(offset_of!(ServerInfo32, sys_met)), &bytes)?;
    let colors: alloc::vec::Vec<u8> = SYSTEM_COLORS.iter().flat_map(|color| color.to_le_bytes()).collect();
    section.write_kernel(at(offset_of!(ServerInfo32, argb_system)), &colors)?;
    const _: () = assert!(size_of::<ServerInfo32>() <= 4096, "SERVERINFO fits in its page");
    *METRICS.lock() = Some(metrics);
    // co_IntInitializeDesktopGraphics attaches the monitor of the display.
    if mode.is_some() {
        crate::monitor::attach(width, height)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_metrics_of_a_1280_by_800_screen() {
        let m = system_metrics(1280, 800, &Parameters::DEFAULT);
        assert_eq!((m[sm::CXSCREEN], m[sm::CYSCREEN]), (1280, 800));
        assert_eq!((m[sm::CXVIRTUALSCREEN], m[sm::CYVIRTUALSCREEN]), (1280, 800));
        assert_eq!((m[sm::CYCAPTION], m[sm::CXSIZE], m[sm::CYSMCAPTION]), (20, 19, 16));
        assert_eq!((m[sm::CXBORDER], m[sm::CXDLGFRAME], m[sm::CXEDGE], m[sm::CXFRAME]), (1, 3, 2, 4));
        assert_eq!((m[sm::CXMIN], m[sm::CYMIN]), (112, 28), "3 * 19 + 19 + 4 + 4 * 6 + 2 * 4; 20 + 2 * 4");
        assert_eq!((m[sm::CXMINTRACK], m[sm::CYMINTRACK]), (112, 28));
        assert_eq!((m[sm::CXMAXIMIZED], m[sm::CYMAXIMIZED]), (1288, 780));
        assert_eq!((m[sm::CXFULLSCREEN], m[sm::CYFULLSCREEN]), (1280, 752));
        assert_eq!((m[sm::CXMAXTRACK], m[sm::CYMAXTRACK]), (1292, 812));
        assert_eq!((m[sm::CXMINIMIZED], m[sm::CYMINIMIZED]), (166, 25));
        assert_eq!((m[sm::CXMINSPACING], m[sm::CYMINSPACING]), (326, 49));
        assert_eq!((m[sm::CXVSCROLL], m[sm::CYHSCROLL], m[sm::CXICON], m[sm::CXSMICON]), (16, 16, 32, 16));
        assert_eq!((m[sm::CYMENU], m[sm::CXMENUCHECK], m[sm::CXMENUSIZE]), (19, 13, 18));
        assert_eq!((m[sm::MOUSEPRESENT], m[sm::CMOUSEBUTTONS], m[sm::CXDOUBLECLK]), (1, 2, 4));
        assert_eq!((m[sm::NETWORK], m[sm::CMONITORS], m[sm::ARRANGE]), (3, 1, 8));
        assert_eq!(m[sm::CXPADDEDBORDER], 0);
    }

    #[test]
    fn the_desktop_background_is_its_system_colour() {
        let background = SYSTEM_COLORS[1];
        assert_eq!(background, 0x00C5_D5DB, "RGB(219, 213, 197)");
        let gdi = crate::gdi::syscolor::BACKGROUND;
        assert_eq!(background, gdi.0, "GDI's desktop background");
    }
}
