//! Les réglages de l'affichage (`win32ss/user/ntuser/display.c` et
//! `win32ss/gdi/eng/pdevobj.c` de ReactOS, comme spécification) : le
//! périphérique d'affichage, ses modes vus comme des `DEVMODEW`, et le
//! changement de mode (UserChangeDisplaySettings) avec ce qui en dépend.
//!
//! Il n'y a qu'un périphérique, `\\.\DISPLAY1` (le pilote installé,
//! `crate::display`), attaché au bureau et principal, avec un moniteur,
//! `\\.\DISPLAY1\Monitor0` ([`adapter`], [`monitor`]). Ses modes sont ceux du
//! pilote, à 32 bits par pixel et [`FREQUENCY`] Hz ([`devmode`]) ; un mode
//! demandé se cherche parmi eux (LDEVOBJ_bProbeAndCaptureDevmode,
//! [`find_mode`]).
//!
//! Après un changement de mode ([`switch`], après PDEVOBJ_bSwitchMode) : les
//! métriques du système (InitMetrics), le moniteur (UserUpdateMonitorSize),
//! les capacités de l'écran que lit `gdi32`, la fenêtre de chaque bureau de
//! la station interactive (DesktopWindowProc de WM_DISPLAYCHANGE), les DC de
//! l'écran, la place du pointeur ; puis WM_DISPLAYCHANGE va aux fenêtres de
//! premier niveau du bureau de l'appelant (SendMessageTimeout de
//! HWND_BROADCAST, 100 ms chacune), et tout se repeint (UserRedrawDesktop).
//!
//! Le registre (`CDS_UPDATEREGISTRY`, `ENUM_REGISTRY_SETTINGS`) et le
//! périphérique nommé par l'appelant restent au service
//! (`ntoskrnl::sys::display`), qui a Cm.
//!
//! Pas encore : plusieurs écrans, d'autres profondeurs (le moteur DIB écrit
//! l'écran en 32 bits), le panoramique (`dmPanningWidth`), `CDS_FULLSCREEN`
//! et le retour au mode du registre à la fin du processus
//! (UserDisplayNotifyShutdown), ClipCursor (rien à rendre).

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::display::{
    cds, disp_change, display_device, dm, set_text, DevModeW, DisplayDeviceW, DM_SPECVERSION, WM_DISPLAYCHANGE,
};
use abi::user::{RDW_ALLCHILDREN, RDW_ERASE, RDW_INVALIDATE};

use crate::display::Mode;
use crate::gdi::dib::Rect;

/// Le nom du périphérique d'affichage (`szWinDeviceName` du premier
/// GRAPHICS_DEVICE de ReactOS).
pub const DEVICE_NAME: &str = "\\\\.\\DISPLAY1";
/// Le nom de son moniteur.
pub const MONITOR_NAME: &str = "\\\\.\\DISPLAY1\\Monitor0";
/// Ce qu'est son moniteur, sans données EDID.
pub const MONITOR_DESCRIPTION: &str = "Default Monitor";
/// La profondeur de tous les modes : le moteur DIB écrit l'écran en 32 bits.
pub const BITS_PER_PEL: u32 = 32;
/// La fréquence annoncée de tous les modes ; le framebuffer ne la dit pas.
pub const FREQUENCY: u32 = 60;
/// Ce que WM_DISPLAYCHANGE attend de chaque fenêtre, en millisecondes
/// (SMTO_NORMAL, comme ReactOS).
pub const DISPLAY_CHANGE_TIMEOUT_MS: u32 = 100;

/// `name` (des unités UTF-16, sans NUL) désigne-t-il le périphérique
/// d'affichage ? Sans casse.
pub fn is_device(name: &[u16]) -> bool {
    let expected = DEVICE_NAME.encode_utf16();
    name.len() == DEVICE_NAME.len() && name.iter().zip(expected).all(|(&a, b)| fold(a) == fold(b))
}

/// Une unité UTF-16 en majuscule, pour l'ASCII.
fn fold(unit: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
        unit - 0x20
    } else {
        unit
    }
}

/// UserEnumDisplayDevices de l'adaptateur numéro `index` : seul le premier
/// existe, avec la description et l'identifiant du pilote ; `key` est sa
/// clé du registre (`DeviceKey`). `None` sans pilote ou au-delà.
pub fn adapter(index: u32, key: &str) -> Option<DisplayDeviceW> {
    let (description, hardware_id) = crate::display::adapter().filter(|_| index == 0)?;
    let mut device = DisplayDeviceW {
        state_flags: display_device::ATTACHED_TO_DESKTOP
            | display_device::PRIMARY_DEVICE
            | display_device::VGA_COMPATIBLE,
        ..DisplayDeviceW::default()
    };
    set_text(&mut device.device_name, DEVICE_NAME);
    set_text(&mut device.device_string, description);
    set_text(&mut device.device_id, hardware_id);
    set_text(&mut device.device_key, key);
    Some(device)
}

/// UserEnumDisplayDevices du moniteur numéro `index` de l'adaptateur : un
/// seul, actif et attaché. `None` sans pilote ou au-delà.
pub fn monitor(index: u32, key: &str) -> Option<DisplayDeviceW> {
    crate::display::adapter().filter(|_| index == 0)?;
    let mut device =
        DisplayDeviceW { state_flags: display_device::ACTIVE | display_device::ATTACHED, ..DisplayDeviceW::default() };
    set_text(&mut device.device_name, MONITOR_NAME);
    set_text(&mut device.device_string, MONITOR_DESCRIPTION);
    set_text(&mut device.device_key, key);
    Some(device)
}

/// Le `DEVMODEW` du mode `mode` (ce que DrvGetModes donne d'un mode).
pub fn devmode(mode: &Mode) -> DevModeW {
    let mut record = DevModeW {
        spec_version: DM_SPECVERSION,
        driver_version: DM_SPECVERSION,
        size: core::mem::size_of::<DevModeW>() as u16,
        fields: dm::BITSPERPEL | dm::PELSWIDTH | dm::PELSHEIGHT | dm::DISPLAYFLAGS | dm::DISPLAYFREQUENCY,
        log_pixels: crate::gdi::devcaps::LOG_PIXELS as u16,
        bits_per_pel: BITS_PER_PEL,
        pels_width: mode.width,
        pels_height: mode.height,
        display_frequency: FREQUENCY,
        ..DevModeW::default()
    };
    if let Some((description, _)) = crate::display::adapter() {
        set_text(&mut record.device_name, description);
    }
    record
}

/// UserEnumDisplaySettings : le mode numéro `index` du pilote ; `None`
/// au-delà.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn mode_at(index: u32) -> Option<DevModeW> {
    crate::display::modes().get(index as usize).map(devmode)
}

/// UserEnumCurrentDisplaySettings : le mode en vigueur ; `None` sans pilote.
///
/// # IRQL
/// Tout niveau.
pub fn current() -> Option<DevModeW> {
    crate::display::mode().map(|mode| devmode(&mode))
}

/// LDEVOBJ_bProbeAndCaptureDevmode : le mode du pilote que `requested`
/// demande, parmi `modes`. La largeur et la hauteur sont exigées
/// (`DM_PELSWIDTH | DM_PELSHEIGHT`) ; une profondeur ou une fréquence
/// absente ou nulle prend celle des modes. `DISP_CHANGE_BADMODE` pour un
/// mode que le pilote n'a pas.
pub fn find_mode(requested: &DevModeW, modes: &[Mode]) -> Result<Mode, i32> {
    if requested.fields & (dm::PELSWIDTH | dm::PELSHEIGHT) != dm::PELSWIDTH | dm::PELSHEIGHT {
        return Err(disp_change::BADMODE);
    }
    let given = |flag: u32, value: u32| (requested.fields & flag != 0 && value != 0).then_some(value);
    if given(dm::BITSPERPEL, requested.bits_per_pel).is_some_and(|bits| bits != BITS_PER_PEL)
        || given(dm::DISPLAYFREQUENCY, requested.display_frequency).is_some_and(|hz| hz != FREQUENCY)
    {
        return Err(disp_change::BADMODE);
    }
    modes
        .iter()
        .copied()
        .find(|mode| mode.width == requested.pels_width && mode.height == requested.pels_height)
        .ok_or(disp_change::BADMODE)
}

/// La suite de UserChangeDisplaySettings une fois le mode trouvé et le
/// registre écrit : passe l'écran au mode `mode` (sauf `CDS_NORESET`) et
/// met à jour ce qui en dépend ([`apply`]), même quand le pilote échoue
/// après avoir changé quelque chose ; puis WM_DISPLAYCHANGE aux fenêtres de
/// premier niveau du bureau du thread courant, et tout se repeint. Rend
/// `DISP_CHANGE_SUCCESSFUL`, ou, en échec, `DISP_CHANGE_RESTART` si le
/// registre a été écrit (`registry_written`), `DISP_CHANGE_FAILED` sinon.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn switch(mode: Mode, flags: u32, registry_written: bool) -> i32 {
    if flags & cds::NORESET != 0 {
        return disp_change::SUCCESSFUL;
    }
    let before = crate::display::mode();
    let switched = crate::display::change_mode(mode.width, mode.height);
    let after = crate::display::mode();
    if let Some(after) = after.filter(|after| switched || before != Some(*after)) {
        apply(&after);
        broadcast(&after);
    }
    if switched {
        disp_change::SUCCESSFUL
    } else if registry_written {
        disp_change::RESTART
    } else {
        disp_change::FAILED
    }
}

/// Ce qui dépend du mode, passé à `mode` : les métriques du système, le
/// moniteur, les capacités de l'écran, la fenêtre de chaque bureau de la
/// station interactive et ses DC, la place du pointeur.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn apply(mode: &Mode) {
    let (width, height) = (mode.width as i32, mode.height as i32);
    if let Err(status) = crate::metrics::write_screen(width, height) {
        log::warn!("win32k: the system metrics of {width}x{height} not written: {status:?}");
    }
    if let Err(status) = crate::monitor::attach(width, height) {
        log::warn!("win32k: the monitor not resized: {status:?}");
    }
    if let Err(status) = crate::gdi::devcaps::publish(mode) {
        log::warn!("win32k: the display's capabilities not published: {status:?}");
    }
    crate::mouse::clamp_to_screen(mode.width, mode.height);
    for desktop in desktops() {
        crate::window::resize_desktop_window(&desktop, width, height);
    }
    crate::dce::reset_screen_dcs();
    crate::gdi::dc::resize_display_dcs(Rect::new(0, 0, width, height));
}

/// Les bureaux de la station interactive (tous, pas seulement celui de
/// l'appelant : ils partagent l'écran).
fn desktops() -> Vec<Arc<ob::Object<crate::desktop::Desktop>>> {
    crate::winsta::input_window_station().map(|station| station.desktops()).unwrap_or_default()
}

/// WM_DISPLAYCHANGE (`wParam` : les bits par pixel ; `lParam` :
/// MAKELONG(largeur, hauteur)) aux fenêtres de premier niveau du bureau du
/// thread courant, [`DISPLAY_CHANGE_TIMEOUT_MS`] au plus chacune, livré plus
/// tard à celles qui n'ont pas répondu à temps ([`crate::sent::broadcast`]).
/// Puis UserRedrawDesktop : la fenêtre du bureau et toutes ses filles sont
/// invalidées, fond et cadres compris, et le fond du bureau se repeint
/// aussitôt (les autres fenêtres, par leur WM_PAINT).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
fn broadcast(mode: &Mode) {
    let lparam = (mode.width & 0xFFFF) | (mode.height & 0xFFFF) << 16;
    let Ok(thread) = crate::convert_current_thread() else { return };
    crate::sent::broadcast(&thread, WM_DISPLAYCHANGE, BITS_PER_PEL, lparam, DISPLAY_CHANGE_TIMEOUT_MS);
    for desktop in desktops() {
        let window = &desktop.window;
        // Its children get RDW_FRAME too; the desktop window has no frame.
        crate::paint::redraw_window(window, None, None, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN);
        crate::paint::update_window(window, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdi::dib::PixelLayout;

    fn mode(width: u32, height: u32) -> Mode {
        Mode { width, height, layout: PixelLayout::Bgrx }
    }

    fn request(fields: u32, width: u32, height: u32, bits: u32, hz: u32) -> DevModeW {
        DevModeW {
            size: 220,
            fields,
            pels_width: width,
            pels_height: height,
            bits_per_pel: bits,
            display_frequency: hz,
            ..DevModeW::default()
        }
    }

    #[test]
    fn the_device_name_is_matched_without_case() {
        let units = |text: &str| text.encode_utf16().collect::<Vec<_>>();
        assert!(is_device(&units("\\\\.\\DISPLAY1")));
        assert!(is_device(&units("\\\\.\\display1")));
        assert!(!is_device(&units("\\\\.\\DISPLAY2")));
        assert!(!is_device(&units("DISPLAY")));
    }

    #[test]
    fn a_requested_mode_is_found_among_the_drivers() {
        let modes = [mode(640, 480), mode(800, 600), mode(1280, 800)];
        let both = dm::PELSWIDTH | dm::PELSHEIGHT;
        assert_eq!(find_mode(&request(both, 800, 600, 0, 0), &modes), Ok(mode(800, 600)));
        let full = both | dm::BITSPERPEL | dm::DISPLAYFREQUENCY;
        assert_eq!(find_mode(&request(full, 640, 480, 32, 60), &modes), Ok(mode(640, 480)));
        assert_eq!(find_mode(&request(full, 640, 480, 0, 0), &modes), Ok(mode(640, 480)), "0: any");
        assert_eq!(find_mode(&request(both, 1000, 700, 0, 0), &modes), Err(disp_change::BADMODE), "not a mode");
        assert_eq!(find_mode(&request(full, 800, 600, 16, 60), &modes), Err(disp_change::BADMODE), "16 bits");
        assert_eq!(find_mode(&request(full, 800, 600, 32, 75), &modes), Err(disp_change::BADMODE), "75 Hz");
        // A depth that is not in the fields is not looked at.
        assert_eq!(find_mode(&request(both, 800, 600, 16, 75), &modes), Ok(mode(800, 600)));
        assert_eq!(find_mode(&request(dm::PELSWIDTH, 800, 600, 0, 0), &modes), Err(disp_change::BADMODE), "no height");
    }

    #[test]
    fn a_mode_as_a_devmode() {
        let record = devmode(&mode(1024, 768));
        assert_eq!((record.pels_width, record.pels_height, record.bits_per_pel), (1024, 768, 32));
        assert_eq!((record.size, record.spec_version, record.display_frequency), (220, 0x0401, 60));
        assert_eq!(record.fields & (dm::PELSWIDTH | dm::PELSHEIGHT | dm::BITSPERPEL), 0x001C_0000);
    }
}
