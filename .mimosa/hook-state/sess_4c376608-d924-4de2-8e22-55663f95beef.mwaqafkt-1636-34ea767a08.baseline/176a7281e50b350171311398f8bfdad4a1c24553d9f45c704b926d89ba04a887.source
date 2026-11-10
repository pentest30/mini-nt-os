//! Les dispositions de clavier (02 §7.2) : une disposition (KL) a son HKL et
//! son fichier (KBDFILE), une DLL de disposition (`kbdus.dll`) dont
//! `KbdLayerDescriptor` rend les tables (KBDTABLES).
//!
//! win32k ne l'exécute pas (ReactOS le fait, et le note comme dangereux) :
//! il lit le fichier. `KbdLayerDescriptor` y est `mov eax, offset tables ;
//! ret` ; l'adresse, à la base préférée de l'image, donne la RVA des tables
//! ([`layer_descriptor_tables`]). Le noyau lit le fichier, d'après la clé
//! `Keyboard Layouts\<KLID>` du registre (`Layout File`) ; win32k n'y touche
//! pas (`sys::user`).
//!
//! Les dispositions chargées forment une liste (gspklBaseLayout), dans
//! l'ordre de leur chargement. Une disposition activée devient celle du
//! thread (son `CLIENTINFO` : `hKL`, `CodePage`), ou de chaque thread GUI du
//! processus (`KLF_SETFORPROCESS`).
//!
//! Le jeu de caractères, la page de code et la signature de police d'une
//! disposition viennent de sa langue (le KLID), par le rappel GetCharsetInfo
//! de `user32` (co_IntGetCharsetInfo, [`crate::callback`]).
//!
//! Les tables de la disposition sont lues au chargement
//! ([`crate::kbdtables`]) : elles traduisent les touches.
//!
//! Pas encore : l'IME, le déchargement (NtUserUnloadKeyboardLayout), le
//! réordonnancement (`KLF_REORDER`), la notification du shell.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use abi::ntstatus::{NtStatus, STATUS_INVALID_IMAGE_FORMAT, STATUS_OBJECT_NAME_INVALID};
use abi::teb32::Teb32;
use abi::user::{CharsetInfo32, ClientInfo32, ANSI_CHARSET, CP_ACP, FS_LATIN1, KLF_ACTIVATE, KLF_SETFORPROCESS};
use hal::sync::KSpinLock;

use crate::kbdtables::Tables;

/// Un fichier de disposition (KBDFILE) : son nom (le KLID), son image, la
/// RVA de ses tables, et ces tables lues (`crate::kbdtables`).
pub struct KeyboardFile {
    pub name: String,
    pub image: Vec<u8>,
    pub tables: u32,
    pub kbd: Tables,
}

/// Les tables (KBDTABLES) en `tables` de l'image `image` ;
/// `STATUS_INVALID_IMAGE_FORMAT` pour des tables mal formées.
pub fn read_tables(image: &[u8], tables: u32) -> Result<Tables, NtStatus> {
    let pe = pe::Pe32::parse(image).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    let base = pe.optional_header().image_base;
    Tables::parse(&|rva, count| pe.read_rva(rva, count), base, tables).ok_or(STATUS_INVALID_IMAGE_FORMAT)
}

/// Une disposition chargée (KL).
pub struct KeyboardLayout {
    pub hkl: u32,
    pub file: Arc<KeyboardFile>,
    /// Le jeu de caractères de sa langue (iBaseCharset).
    pub charset: u32,
    /// Les pages de code de sa langue, en bits (dwFontSigs : `fsCsb[0]`).
    pub font_signature: u32,
    /// La page de code ANSI de sa langue (CodePage) ; `CP_ACP` sans
    /// GetCharsetInfo.
    pub code_page: u16,
}

/// La langue (LCID) d'un KLID, en hexadécimal comme
/// RtlUnicodeStringToInteger en base 16 ; `STATUS_OBJECT_NAME_INVALID`
/// sinon.
pub fn klid_locale(klid: &str) -> Result<u32, NtStatus> {
    u32::from_str_radix(klid, 16).map_err(|_| STATUS_OBJECT_NAME_INVALID)
}

/// Ce qu'une disposition retient de la réponse de GetCharsetInfo, ou, s'il
/// échoue, ANSI_CHARSET, FS_LATIN1 et CP_ACP (UserLoadKbdLayout) : son jeu
/// de caractères, sa signature de police, sa page de code.
pub fn layout_charset(answer: Result<CharsetInfo32, NtStatus>) -> (u32, u32, u16) {
    match answer {
        Ok(info) => (info.charset, info.code_page_bits[0], info.ansi_code_page as u16),
        Err(_) => (ANSI_CHARSET, FS_LATIN1, CP_ACP as u16),
    }
}

/// La RVA des tables d'une DLL de disposition : `KbdLayerDescriptor` est
/// `B8 imm32 C3` (`mov eax, imm32 ; ret`), `imm32` une adresse dans l'image
/// à sa base préférée. `STATUS_INVALID_IMAGE_FORMAT` pour un fichier qui
/// n'est pas une image, sans cet export, d'un autre code, ou dont l'adresse
/// sort de l'image.
pub fn layer_descriptor_tables(image: &[u8]) -> Result<u32, NtStatus> {
    let pe = pe::Pe32::parse(image).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    let Some(pe::ExportTarget::Rva(function)) = pe.export("KbdLayerDescriptor") else {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    };
    let code = pe.read_rva(function, 6).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let [0xB8, a, b, c, d, 0xC3] = *code else {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    };
    let header = pe.optional_header();
    let (base, size) = (header.image_base, header.size_of_image);
    let tables = u32::from_le_bytes([a, b, c, d]).wrapping_sub(base);
    if tables >= size || pe.read_rva(tables, 4).is_none() {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    Ok(tables)
}

/// Le nom du fichier d'une disposition, d'après sa valeur `Layout File`
/// (de type `data_type`, aux octets `data`) : une chaîne `REG_SZ` (jusqu'à
/// son NUL), un nom de fichier seul ; `STATUS_OBJECT_NAME_INVALID` sinon
/// (vide, ou avec un séparateur ou un lecteur : il sortirait de
/// `System32`).
pub fn layout_file_name(data_type: u32, data: &[u8]) -> Result<String, NtStatus> {
    let units: Vec<u16> =
        data.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).take_while(|&unit| unit != 0).collect();
    let name = String::from_utf16(&units).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
    if data_type != abi::registry::REG_SZ || name.is_empty() || name.contains(['\\', '/', ':']) {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(name)
}

/// Les dispositions chargées, dans l'ordre de leur chargement.
static LAYOUTS: KSpinLock<Vec<Arc<KeyboardLayout>>> = KSpinLock::new(Vec::new());

/// La disposition de HKL `hkl`, si elle est chargée (UserHklToKbl).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn layout(hkl: u32) -> Option<Arc<KeyboardLayout>> {
    LAYOUTS.lock().iter().find(|layout| layout.hkl == hkl).cloned()
}

/// Les HKL des dispositions chargées, dans leur ordre (IntGetKeyboardLayoutList).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn layouts() -> Vec<u32> {
    LAYOUTS.lock().iter().map(|layout| layout.hkl).collect()
}

/// co_IntLoadKeyboardLayoutEx : la disposition `hkl` (du KLID `klid`),
/// chargée si elle ne l'est pas — `read` rend alors le fichier de
/// disposition, et `charset` (GetCharsetInfo) ce que dit la langue du KLID
/// —, puis activée (`KLF_ACTIVATE`) pour le thread courant, ou chaque thread
/// GUI de son processus (`KLF_SETFORPROCESS`). Rend le HKL ; `None` pour un
/// HKL nul ou une station sans entrée ni sortie (`no_io`).
///
/// # Errors
/// Celles de `read`, de la lecture des tables
/// ([`layer_descriptor_tables`], [`read_tables`]) et de l'activation ;
/// `STATUS_OBJECT_NAME_INVALID` pour un KLID qui n'est pas hexadécimal.
/// Un échec de `charset` est journalisé, et la disposition prend les
/// valeurs par défaut ([`layout_charset`]).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un thread GUI. `charset` peut rappeler le mode
/// utilisateur : rien n'est tenu pendant son appel.
pub fn load(
    no_io: bool,
    klid: &str,
    hkl: u32,
    flags: u32,
    charset: impl FnOnce(u32) -> Result<CharsetInfo32, NtStatus>,
    read: impl FnOnce(&str) -> Result<Vec<u8>, NtStatus>,
) -> Result<Option<u32>, NtStatus> {
    if hkl == 0 || no_io {
        return Ok(None);
    }
    let layout = match layout(hkl) {
        Some(layout) => layout,
        None => {
            let image = read(klid)?;
            let tables = layer_descriptor_tables(&image)?;
            let kbd = read_tables(&image, tables)?;
            let answer = charset(klid_locale(klid)?);
            match &answer {
                Ok(info) => log::info!(
                    "win32k: keyboard layout {klid}: charset {}, code page {}, font signature {:#x} (GetCharsetInfo)",
                    info.charset,
                    info.ansi_code_page,
                    info.code_page_bits[0]
                ),
                Err(status) => {
                    log::warn!("win32k: GetCharsetInfo for keyboard layout {klid} failed ({status:?}): the defaults")
                }
            }
            let (charset, font_signature, code_page) = layout_charset(answer);
            let file = Arc::new(KeyboardFile { name: String::from(klid), image, tables, kbd });
            let created = Arc::new(KeyboardLayout { hkl, file, charset, font_signature, code_page });
            let mut layouts = LAYOUTS.lock();
            // Another thread may have loaded it meanwhile.
            match layouts.iter().find(|other| other.hkl == hkl) {
                Some(other) => other.clone(),
                None => {
                    layouts.push(created.clone());
                    created
                }
            }
        }
    };
    if flags & KLF_ACTIVATE != 0 {
        activate(&layout, flags & KLF_SETFORPROCESS != 0)?;
    }
    Ok(Some(hkl))
}

/// co_UserActivateKeyboardLayout : `layout` devient celle du thread courant
/// (un thread de `csrss` : lui seul), ou de chaque thread GUI de son
/// processus (`for_process`) ; leur `CLIENTINFO` prend son HKL et sa page de
/// code.
fn activate(layout: &Arc<KeyboardLayout>, for_process: bool) -> Result<(), NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(abi::ntstatus::STATUS_INVALID_PARAMETER)?;
    let info = crate::convert_current_thread()?;
    let process = thread.process().clone();
    if !for_process || info.ti_flags & abi::user::TIF_CSRSSTHREAD != 0 {
        info.set_keyboard_layout(layout.clone());
        return write_client(&thread, &process, layout);
    }
    for other in process.threads() {
        let Some(other_info) = other.win32_thread() else { continue };
        let other_info = crate::gui::thread_info(other_info);
        other_info.set_keyboard_layout(layout.clone());
        write_client(&other, &process, layout)?;
    }
    Ok(())
}

/// Écrit dans le `CLIENTINFO` du TEB de `thread` le HKL et la page de code
/// de `layout`.
fn write_client(thread: &ps::EThread, process: &ps::EProcess, layout: &KeyboardLayout) -> Result<(), NtStatus> {
    let info = u64::from(thread.teb()) + offset_of!(Teb32, win32_client_info) as u64;
    process.write_memory(info + offset_of!(ClientInfo32, hkl) as u64, &layout.hkl.to_le_bytes())?;
    process.write_memory(info + offset_of!(ClientInfo32, code_page) as u64, &layout.code_page.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pe::builder::Pe32Builder;

    /// A layout DLL at 0x5FFF0000, its `KbdLayerDescriptor` at 0x1080 being
    /// `code`; at 0x1000, the smallest tables: no modifiers, no characters,
    /// no scan codes.
    fn layout_dll(code: [u8; 6]) -> Vec<u8> {
        let mut data = [0u8; 0x100];
        // KBDTABLES: MODIFIERS at 0x1040 (VK_TO_BIT at 0x1050, ending at
        // once), VK_TO_WCHAR_TABLE at 0x1060 (ending at once).
        data[0..4].copy_from_slice(&0x5FFF_1040u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x5FFF_1060u32.to_le_bytes());
        data[0x40..0x44].copy_from_slice(&0x5FFF_1050u32.to_le_bytes());
        data[0x80..0x86].copy_from_slice(&code);
        Pe32Builder::new(0x5FFF_0000)
            .section(".data", 0x1000, 0x100, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
            .exports("kbdus.dll", &[("KbdLayerDescriptor", 0x1080)])
            .build()
    }

    #[test]
    fn the_tables_are_read_not_run() {
        // mov eax, 0x5FFF1000 ; ret: the tables at the start of .data.
        assert_eq!(layer_descriptor_tables(&layout_dll([0xB8, 0x00, 0x10, 0xFF, 0x5F, 0xC3])), Ok(0x1000));
        let other_code = layout_dll([0x8B, 0x00, 0x10, 0xFF, 0x5F, 0xC3]);
        assert_eq!(layer_descriptor_tables(&other_code), Err(STATUS_INVALID_IMAGE_FORMAT), "not mov eax");
        let no_ret = layout_dll([0xB8, 0x00, 0x10, 0xFF, 0x5F, 0x90]);
        assert_eq!(layer_descriptor_tables(&no_ret), Err(STATUS_INVALID_IMAGE_FORMAT), "no ret");
        let outside = layout_dll([0xB8, 0x00, 0x00, 0x00, 0x70, 0xC3]);
        assert_eq!(layer_descriptor_tables(&outside), Err(STATUS_INVALID_IMAGE_FORMAT), "past the image");
        assert_eq!(layer_descriptor_tables(b"MZ"), Err(STATUS_INVALID_IMAGE_FORMAT), "no image");
        let no_export =
            Pe32Builder::new(0x5FFF_0000).section(".data", 0x1000, 0x10, &[0; 0x10], pe::SCN_MEM_READ).build();
        assert_eq!(layer_descriptor_tables(&no_export), Err(STATUS_INVALID_IMAGE_FORMAT), "no KbdLayerDescriptor");
    }

    // Its own HKL: the list of layouts is shared by the tests, which run at
    // once.
    #[test]
    fn a_layout_whose_tables_cannot_be_read_is_refused() {
        let image = layout_dll([0xB8, 0x00, 0x10, 0xFF, 0x5F, 0xC3]);
        assert!(read_tables(&image, 0x1000).is_ok());
        // KBDTABLES at 0x1080: its MODIFIERS pointer is the code, outside the image.
        assert_eq!(read_tables(&image, 0x1080).err(), Some(STATUS_INVALID_IMAGE_FORMAT));
        let charset = |_| Ok(CharsetInfo32::default());
        let pointing_at_code = |_: &str| Ok(layout_dll([0xB8, 0x80, 0x10, 0xFF, 0x5F, 0xC3]));
        assert_eq!(
            load(false, "00000415", 0x0415_0415, 0, charset, pointing_at_code),
            Err(STATUS_INVALID_IMAGE_FORMAT)
        );
        assert!(layout(0x0415_0415).is_none(), "not listed");
    }

    #[test]
    fn a_layout_file_is_a_file_name() {
        let sz = |text: &str| -> Vec<u8> { text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect() };
        assert_eq!(layout_file_name(abi::registry::REG_SZ, &sz("kbdus.dll")).as_deref(), Ok("kbdus.dll"));
        for bad in ["", "..\\kbdus.dll", "C:kbdus.dll", "a/b.dll"] {
            assert_eq!(layout_file_name(abi::registry::REG_SZ, &sz(bad)), Err(STATUS_OBJECT_NAME_INVALID), "{bad}");
        }
        assert_eq!(layout_file_name(7, &sz("kbdus.dll")), Err(STATUS_OBJECT_NAME_INVALID), "REG_MULTI_SZ");
    }

    #[test]
    fn a_layout_loads_once_and_lists() {
        let hkl = 0x040C_040C;
        let read = |klid: &str| {
            assert_eq!(klid, "0000040C");
            Ok(layout_dll([0xB8, 0x00, 0x10, 0xFF, 0x5F, 0xC3]))
        };
        let charset = |locale: u32| {
            assert_eq!(locale, 0x40C, "the language of the KLID");
            Ok(CharsetInfo32 { charset: 0, ansi_code_page: 1252, code_page_bits: [FS_LATIN1, 0], ..Default::default() })
        };
        assert_eq!(load(false, "0000040C", hkl, 0, charset, read), Ok(Some(hkl)));
        let loaded = layout(hkl).expect("loaded");
        assert_eq!((loaded.file.name.as_str(), loaded.file.tables, loaded.code_page), ("0000040C", 0x1000, 1252));
        assert_eq!((loaded.charset, loaded.font_signature), (ANSI_CHARSET, FS_LATIN1));
        assert!(layouts().contains(&hkl));
        let again = |_: &str| -> Result<Vec<u8>, NtStatus> { panic!("loaded already") };
        let asked = |_: u32| -> Result<CharsetInfo32, NtStatus> { panic!("loaded already") };
        assert_eq!(load(false, "0000040C", hkl, 0, asked, again), Ok(Some(hkl)), "not read again");
        assert_eq!(layouts().iter().filter(|&&other| other == hkl).count(), 1, "listed once");
    }

    #[test]
    fn a_layout_that_cannot_be_read_is_not_listed() {
        let hkl = 0x0407_0407;
        let asked = |_: u32| -> Result<CharsetInfo32, NtStatus> { panic!("not asked for a layout not read") };
        let missing = |_: &str| Err(abi::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        assert_eq!(load(false, "00000407", hkl, 0, asked, missing), Err(abi::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
        let bad = |_: &str| Ok(alloc::vec![0u8; 16]);
        assert_eq!(load(false, "00000407", hkl, 0, asked, bad), Err(STATUS_INVALID_IMAGE_FORMAT));
        let read = |_: &str| Ok(layout_dll([0xB8, 0x00, 0x10, 0xFF, 0x5F, 0xC3]));
        assert_eq!(load(false, "0000040G", hkl, 0, asked, read), Err(STATUS_OBJECT_NAME_INVALID), "not hexadecimal");
        assert!(layout(hkl).is_none() && !layouts().contains(&hkl));
    }

    #[test]
    fn a_layout_without_its_charset_takes_the_defaults() {
        let hkl = 0x0411_0411;
        let read = |_: &str| Ok(layout_dll([0xB8, 0x00, 0x10, 0xFF, 0x5F, 0xC3]));
        let failed = |_: u32| Err(abi::ntstatus::STATUS_UNSUCCESSFUL);
        assert_eq!(load(false, "00000411", hkl, 0, failed, read), Ok(Some(hkl)), "loaded all the same");
        let loaded = layout(hkl).expect("loaded");
        assert_eq!((loaded.charset, loaded.font_signature, loaded.code_page), (ANSI_CHARSET, FS_LATIN1, 0));
    }

    #[test]
    fn a_klid_is_its_language_in_hexadecimal() {
        assert_eq!(klid_locale("00000409"), Ok(0x409));
        assert_eq!(klid_locale("00010409"), Ok(0x1_0409));
        assert_eq!(klid_locale(""), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(klid_locale("0409 "), Err(STATUS_OBJECT_NAME_INVALID));
    }

    #[test]
    fn nothing_loads_without_a_hkl_or_off_the_interactive_station() {
        let read = |_: &str| -> Result<Vec<u8>, NtStatus> { panic!("nothing to read") };
        let asked = |_: u32| -> Result<CharsetInfo32, NtStatus> { panic!("nothing to ask") };
        assert_eq!(load(false, "00000409", 0, 0, asked, read), Ok(None), "no HKL");
        assert_eq!(load(true, "00000409", 0x0409_0409, 0, asked, read), Ok(None), "no input or output");
    }
}
