//! Les services des réglages de l'affichage (`win32ss/user/ntuser/display.c`
//! de ReactOS, comme spécification) : NtUserEnumDisplayDevices,
//! NtUserEnumDisplaySettings, NtUserChangeDisplaySettings. Ce qui touche
//! l'écran est dans `win32k::display_settings` ; ici, la copie des arguments
//! et le registre.
//!
//! Le registre garde le mode de l'utilisateur (RegWriteDisplaySettings) dans
//! la clé du périphérique ([`DEVICE_KEY`], son `DeviceKey`), que
//! `HARDWARE\DEVICEMAP\VIDEO` désigne (`\Device\Video0`, comme le pose
//! VIDEOPRT) : `CDS_UPDATEREGISTRY` l'y écrit et réécrit la ruche dans son
//! fichier (NtFlushKey), `ENUM_REGISTRY_SETTINGS` et ChangeDisplaySettings
//! sans `DEVMODE` le relisent, et le démarrage le reprend
//! ([`apply_registry_mode`], comme la création du PDEV d'après le registre).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::display::{
    cds, disp_change, DevModeW, DisplayDeviceW, CCHDEVICENAME, ENUM_CURRENT_SETTINGS, ENUM_REGISTRY_SETTINGS,
};
use abi::ntstatus::{
    NtStatus, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER_1, STATUS_INVALID_PARAMETER_2, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};
use abi::registry::REG_DWORD;
use abi::winerror::ERROR_INVALID_PARAMETER;
use ke::usermem::{copy_from_user, copy_to_user, probe_for_write};

/// La clé du registre du périphérique d'affichage : son `DeviceKey`, où
/// ses réglages sont gardés. Le GUID est celui de Mino (« MINO » en tête).
pub const DEVICE_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Video\\{4D494E4F-0000-0000-0000-000000000001}\\0000";
/// La même, depuis `\Registry\Machine\System\CurrentControlSet\Control`.
const DEVICE_SUBKEYS: [&str; 3] = ["Video", "{4D494E4F-0000-0000-0000-000000000001}", "0000"];
/// La clé `Control` du jeu de contrôle courant.
const CONTROL_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control";

/// Les valeurs de RegWriteDisplaySettings, chacune avec son champ.
const SETTINGS: [(&str, u32); 4] = [
    ("DefaultSettings.BitsPerPel", abi::display::dm::BITSPERPEL),
    ("DefaultSettings.XResolution", abi::display::dm::PELSWIDTH),
    ("DefaultSettings.YResolution", abi::display::dm::PELSHEIGHT),
    ("DefaultSettings.VRefresh", abi::display::dm::DISPLAYFREQUENCY),
];

/// Les valeurs que RegWriteDisplaySettings écrit aussi, à zéro ici (pas de
/// panoramique, d'orientation ni de position).
const ZERO_SETTINGS: [&str; 7] = [
    "DefaultSettings.Flags",
    "DefaultSettings.XPanning",
    "DefaultSettings.YPanning",
    "DefaultSettings.Orientation",
    "DefaultSettings.FixedOutput",
    "Attach.RelativeX",
    "Attach.RelativeY",
];

/// Le champ de `record` que désigne `field` (l'un de [`SETTINGS`]).
fn setting(record: &mut DevModeW, field: u32) -> &mut u32 {
    match field {
        abi::display::dm::BITSPERPEL => &mut record.bits_per_pel,
        abi::display::dm::PELSWIDTH => &mut record.pels_width,
        abi::display::dm::PELSHEIGHT => &mut record.pels_height,
        _ => &mut record.display_frequency,
    }
}

/// RegReadDisplaySettings : le `DEVMODEW` que donnent les valeurs `value`
/// (nom → DWORD) ; seuls les champs présents sont dans `dmFields`.
pub fn read_settings(value: impl Fn(&str) -> Option<u32>) -> DevModeW {
    let mut record = DevModeW { size: core::mem::size_of::<DevModeW>() as u16, ..DevModeW::default() };
    for (name, field) in SETTINGS {
        if let Some(data) = value(name) {
            *setting(&mut record, field) = data;
            record.fields |= field;
        }
    }
    record
}

/// RegWriteDisplaySettings : les valeurs (nom, DWORD) qui gardent `record`.
pub fn settings_values(record: &DevModeW) -> Vec<(&'static str, u32)> {
    let mut copy = *record;
    SETTINGS
        .iter()
        .map(|&(name, field)| (name, *setting(&mut copy, field)))
        .chain(ZERO_SETTINGS.iter().map(|&name| (name, 0)))
        .collect()
}

/// La clé `name` du registre, ouverte par le noyau.
fn open_key(name: &str) -> Option<Arc<ob::Object<cm::Key>>> {
    let object = ob::namespace().open(name, None, Some(&cm::KEY_TYPE), 0).ok()?;
    ob::downcast::<cm::Key>(&object)
}

/// Le mode que garde le registre ; `None` sans la clé du périphérique.
fn registry_settings() -> Option<DevModeW> {
    let key = open_key(DEVICE_KEY)?;
    Some(read_settings(|name| {
        let units: Vec<u16> = name.encode_utf16().collect();
        let value = key.value(&units).ok()??;
        let bytes: [u8; 4] = value.data.get(..4)?.try_into().ok()?;
        (value.data_type == REG_DWORD).then_some(u32::from_le_bytes(bytes))
    }))
}

/// Écrit `record` dans la clé du périphérique, créée s'il le faut, et
/// réécrit la ruche dans son fichier.
fn write_registry_settings(record: &DevModeW) -> Result<(), NtStatus> {
    let control = open_key(CONTROL_KEY).ok_or(STATUS_UNSUCCESSFUL)?;
    let (video, _) = control.create_subkey(DEVICE_SUBKEYS[0], &[], false)?;
    let (guid, _) = video.create_subkey(DEVICE_SUBKEYS[1], &[], false)?;
    let (key, _) = guid.create_subkey(DEVICE_SUBKEYS[2], &[], false)?;
    for (name, data) in settings_values(record) {
        let units: Vec<u16> = name.encode_utf16().collect();
        key.set_value(&units, REG_DWORD, data.to_le_bytes().to_vec())?;
    }
    key.flush()
}

/// Le chemin de la clé du périphérique, pour `DeviceKey`.
fn device_key_name() -> String {
    String::from(DEVICE_KEY)
}

/// Le nom de périphérique d'un appelant, en `address` (un UNICODE_STRING,
/// ou rien) : `Ok(None)` pour aucun ou un nom vide, `Ok(Some)` pour un nom
/// (au plus [`CCHDEVICENAME`] caractères gardés, comme RtlCopyUnicodeString
/// vers le tampon de ReactOS).
fn capture_device(address: u32) -> Result<Option<Vec<u16>>, NtStatus> {
    if address == 0 {
        return Ok(None);
    }
    let mut units = super::object::capture_unicode_string(address)?;
    units.truncate(CCHDEVICENAME);
    Ok((!units.is_empty()).then_some(units))
}

/// NtUserEnumDisplayDevices(pustrDevice, iDevNum, pDisplayDevice, dwFlags) :
/// BOOL. Sans nom (ou un nom vide), l'adaptateur `iDevNum` ; avec le nom de
/// l'adaptateur, son moniteur `iDevNum` (`win32k::display_settings`). Le
/// `DISPLAY_DEVICEW` de l'appelant reçoit au plus son `cb` d'octets (`cb`
/// borné à 840). FALSE au-delà, pour un autre nom, ou un tampon qu'on ne
/// peut écrire.
pub(super) fn nt_user_enum_display_devices(arguments: &[u32]) -> NtStatus {
    let [device, index, out, _flags] = arguments[..4] else { unreachable!("4 arguments") };
    let enumerate = || -> Result<(), NtStatus> {
        let key = device_key_name();
        let found = match capture_device(device)? {
            None => win32k::display_settings::adapter(index, &key),
            Some(name) if win32k::display_settings::is_device(&name) => win32k::display_settings::monitor(index, &key),
            Some(_) => None,
        };
        let mut found = found.ok_or(STATUS_UNSUCCESSFUL)?;
        probe_for_write(u64::from(out), 4, 1)?;
        let mut cb = [0u8; 4];
        copy_from_user(&mut cb, u64::from(out))?;
        let cb = u32::from_le_bytes(cb).min(core::mem::size_of::<DisplayDeviceW>() as u32);
        if cb == 0 {
            return Ok(());
        }
        found.cb = cb;
        copy_to_user(u64::from(out), &found.as_bytes()[..cb as usize])
    };
    NtStatus(u32::from(enumerate().is_ok()))
}

/// NtUserEnumDisplaySettings(pustrDevice, iModeNum, lpDevMode, dwFlags) :
/// NTSTATUS. Le `DEVMODEW` de l'appelant, dont `dmSize` doit être 220
/// (`STATUS_BUFFER_TOO_SMALL` sinon), reçoit le mode `iModeNum` du pilote,
/// le mode en vigueur (`ENUM_CURRENT_SETTINGS`) ou celui du registre
/// (`ENUM_REGISTRY_SETTINGS`) ; ses octets de pilote, aucun.
/// `STATUS_INVALID_PARAMETER_1` pour un autre périphérique,
/// `STATUS_INVALID_PARAMETER_2` au-delà des modes.
pub(super) fn nt_user_enum_display_settings(arguments: &[u32]) -> NtStatus {
    let [device, mode, out, _flags] = arguments[..4] else { unreachable!("4 arguments") };
    let enumerate = || -> Result<(), NtStatus> {
        let mut head = [0u8; 72];
        copy_from_user(&mut head, u64::from(out))?;
        let size = u16::from_le_bytes([head[68], head[69]]);
        if usize::from(size) != core::mem::size_of::<DevModeW>() {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        match capture_device(device) {
            Ok(Some(name)) if !win32k::display_settings::is_device(&name) => return Err(STATUS_INVALID_PARAMETER_1),
            Ok(_) => {}
            Err(_) => return Err(STATUS_INVALID_PARAMETER_1),
        }
        let record = match mode {
            ENUM_CURRENT_SETTINGS => win32k::display_settings::current().ok_or(STATUS_INVALID_PARAMETER_1)?,
            ENUM_REGISTRY_SETTINGS => registry_settings().ok_or(STATUS_UNSUCCESSFUL)?,
            index => win32k::display_settings::mode_at(index).ok_or(STATUS_INVALID_PARAMETER_2)?,
        };
        let record = DevModeW { driver_extra: 0, ..record };
        copy_to_user(u64::from(out), record.as_bytes())
    };
    enumerate().map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtUserChangeDisplaySettings(pustrDevice, lpDevMode, dwflags, lParam) :
/// LONG, un `DISP_CHANGE_*`. Les drapeaux d'abord (`lParam` seulement avec
/// `CDS_VIDEOPARAMETERS` : `DISP_CHANGE_BADPARAM` ; `CDS_GLOBAL` ou
/// `CDS_NORESET` sans `CDS_UPDATEREGISTRY`, `CDS_RESET` avec
/// `CDS_NORESET` : `DISP_CHANGE_BADFLAGS`), puis UserChangeDisplaySettings :
/// sans `DEVMODE`, celui du registre ; un `DEVMODE` plus court que
/// `dmFields` : `DISP_CHANGE_BADMODE` ; le mode cherché parmi ceux du
/// pilote ; `CDS_TEST` s'arrête là ; `CDS_UPDATEREGISTRY` l'écrit
/// (`DISP_CHANGE_NOTUPDATED` s'il ne s'écrit pas) ; le mode en vigueur
/// n'est pas repris sans `CDS_RESET` ; enfin le changement
/// (`win32k::display_settings::switch`).
pub(super) fn nt_user_change_display_settings(arguments: &[u32]) -> NtStatus {
    let [device, devmode, flags, lparam] = arguments[..4] else { unreachable!("4 arguments") };
    NtStatus(change_display_settings(device, devmode, flags, lparam) as u32)
}

fn change_display_settings(device: u32, devmode: u32, flags: u32, lparam: u32) -> i32 {
    if flags != cds::VIDEOPARAMETERS && lparam != 0 {
        let _ = win32k::set_last_error(ERROR_INVALID_PARAMETER);
        return disp_change::BADPARAM;
    }
    if flags & (cds::GLOBAL | cds::NORESET) != 0 && flags & cds::UPDATEREGISTRY == 0 {
        return disp_change::BADFLAGS;
    }
    if flags & cds::RESET != 0 && flags & cds::NORESET != 0 {
        return disp_change::BADFLAGS;
    }
    match capture_device(device) {
        Ok(Some(name)) if !win32k::display_settings::is_device(&name) => return disp_change::BADPARAM,
        Ok(_) => {}
        Err(_) => return disp_change::BADPARAM,
    }
    let requested = if devmode == 0 {
        match registry_settings() {
            Some(record) => record,
            None => return disp_change::BADPARAM,
        }
    } else {
        let mut size = [0u8; 2];
        if copy_from_user(&mut size, u64::from(devmode) + 68).is_err() {
            return disp_change::BADPARAM;
        }
        let size = usize::from(u16::from_le_bytes(size)).min(core::mem::size_of::<DevModeW>());
        if size < core::mem::offset_of!(DevModeW, fields) {
            return disp_change::BADMODE;
        }
        let mut bytes = alloc::vec![0u8; size];
        if copy_from_user(&mut bytes, u64::from(devmode)).is_err() {
            return disp_change::BADPARAM;
        }
        DevModeW::from_bytes(&bytes)
    };
    let mode = match win32k::display_settings::find_mode(&requested, &win32k::display::modes()) {
        Ok(mode) => mode,
        Err(result) => return result,
    };
    if flags & cds::TEST != 0 {
        return disp_change::SUCCESSFUL;
    }
    let mut result = disp_change::SUCCESSFUL;
    let mut written = false;
    if flags & cds::UPDATEREGISTRY != 0 {
        match write_registry_settings(&win32k::display_settings::devmode(&mode)) {
            Ok(()) => written = true,
            Err(status) => {
                log::warn!("sys: the display settings not written to the registry: {status}");
                result = disp_change::NOTUPDATED;
            }
        }
    }
    let current = win32k::display::mode();
    if current == Some(mode) && flags & cds::RESET == 0 {
        return result;
    }
    if flags & cds::NORESET != 0 {
        return result;
    }
    win32k::display_settings::switch(mode, flags, written)
}

/// Au démarrage, une fois la ruche SYSTEM montée et le pilote d'affichage
/// installé, avant que win32k ne dessine : l'écran passe au mode que garde
/// le registre, s'il en garde un que le pilote a (EngpCreatePDEV d'après
/// RegReadDisplaySettings).
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub(crate) fn apply_registry_mode() {
    let Some(record) = registry_settings() else { return };
    let modes = win32k::display::modes();
    match win32k::display_settings::find_mode(&record, &modes) {
        Ok(mode) if win32k::display::mode() != Some(mode) => {
            if win32k::display::change_mode(mode.width, mode.height) {
                log::info!("[boot] display: {}x{}, the mode the registry keeps", mode.width, mode.height);
            }
        }
        Ok(_) => {}
        Err(_) => log::info!(
            "[boot] display: the registry's {}x{} is not a mode of the driver",
            record.pels_width,
            record.pels_height
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::display::dm;

    #[test]
    fn the_registry_settings_go_and_come_back() {
        let record = DevModeW {
            bits_per_pel: 32,
            pels_width: 800,
            pels_height: 600,
            display_frequency: 60,
            ..DevModeW::default()
        };
        let values = settings_values(&record);
        assert_eq!(values.len(), 11, "RegWriteDisplaySettings's eleven values");
        assert!(values.contains(&("DefaultSettings.XResolution", 800)));
        assert!(values.contains(&("Attach.RelativeY", 0)));
        let read = read_settings(|name| values.iter().find(|(n, _)| *n == name).map(|&(_, data)| data));
        assert_eq!((read.pels_width, read.pels_height, read.bits_per_pel, read.display_frequency), (800, 600, 32, 60));
        assert_eq!(read.fields, dm::BITSPERPEL | dm::PELSWIDTH | dm::PELSHEIGHT | dm::DISPLAYFREQUENCY);
    }

    #[test]
    fn missing_values_leave_their_fields_out() {
        let read = read_settings(|name| (name == "DefaultSettings.XResolution").then_some(1024));
        assert_eq!((read.fields, read.pels_width, read.pels_height), (dm::PELSWIDTH, 1024, 0));
    }
}
