//! Les paramètres d'un processus (RTL_USER_PROCESS_PARAMETERS, `abi`) : ce
//! que `ntdll` lit à son démarrage (`Peb->ProcessParameters`). Sous XP, le
//! créateur les écrit dans le processus fils (RtlCreateProcessParameters,
//! puis l'écriture dans le fils) ; ici, pour un processus que crée le noyau,
//! Ps le fait ([`write`]).
//!
//! Le bloc est d'un seul tenant : la structure, puis ses chaînes en UTF-16,
//! chacune terminée et alignée sur 4 octets ; il est écrit *normalisé*
//! (adresses, et non décalages). Le répertoire courant réserve `MAX_PATH`
//! caractères, que `RtlSetCurrentDirectory_U` récrit sur place.
//! L'environnement a son allocation à lui : `RtlSetEnvironmentVariable` en
//! alloue un nouveau et libère l'ancien.

use alloc::vec::Vec;
use core::mem::{offset_of, size_of};

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_NAME_TOO_LONG};
use abi::peb32::{Peb32, UnicodeString32};
use abi::process_parameters::{RtlUserProcessParameters32, RTL_USER_PROCESS_PARAMETERS_NORMALIZED};
use mm::vad::PageProtect;
use mm::virtual_alloc::{AllocType, FreeType};

use crate::eprocess::EProcess;

/// MAX_PATH, en caractères, terminateur compris.
pub const MAX_PATH: usize = 260;

/// Les paramètres d'un processus, en chaînes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessParameters<'a> {
    /// Le chemin de son image.
    pub image_path_name: &'a str,
    pub command_line: &'a str,
    /// Un chemin DOS qui finit par `\`, de moins de `MAX_PATH` caractères.
    pub current_directory: &'a str,
    /// Les répertoires où chercher les DLL, séparés par `;`.
    pub dll_path: &'a str,
    pub window_title: &'a str,
    pub desktop_info: &'a str,
    /// Ses variables, `NOM=valeur`.
    pub environment: &'a [&'a str],
}

/// La racine du système (`KUSER_SHARED_DATA.NtSystemRoot`) et son
/// `system32`.
const SYSTEM32: &str = "C:\\WINDOWS\\system32";

/// L'environnement d'un programme du système : ses variables, triées sans
/// casse comme le fait l'environnement d'XP.
pub const SYSTEM_ENVIRONMENT: &[&str] =
    &["Path=C:\\WINDOWS\\system32;C:\\WINDOWS", "SystemDrive=C:", "SystemRoot=C:\\WINDOWS", "windir=C:\\WINDOWS"];

impl<'a> ProcessParameters<'a> {
    /// Ceux d'un programme du système, `image_path_name` lancé par
    /// `command_line` : répertoire courant et chemin des DLL dans
    /// `C:\WINDOWS\system32`, [`SYSTEM_ENVIRONMENT`].
    pub fn system(image_path_name: &'a str, command_line: &'a str) -> Self {
        Self {
            image_path_name,
            command_line,
            current_directory: "C:\\WINDOWS\\system32\\",
            dll_path: SYSTEM32,
            window_title: image_path_name,
            desktop_info: "",
            environment: SYSTEM_ENVIRONMENT,
        }
    }
}

/// `text` en UTF-16, et sa longueur en octets pour un UNICODE_STRING ;
/// `STATUS_NAME_TOO_LONG` si elle ne tient pas.
fn utf16(text: &str) -> Result<(Vec<u16>, u16), NtStatus> {
    let units: Vec<u16> = text.encode_utf16().collect();
    // Room for the terminator in MaximumLength.
    let length = u16::try_from(units.len() * 2).ok().filter(|l| *l <= u16::MAX - 2).ok_or(STATUS_NAME_TOO_LONG)?;
    Ok((units, length))
}

/// Le bloc des paramètres, normalisé, pour l'adresse `base`, avec
/// l'environnement en `environment`. `STATUS_INVALID_PARAMETER` pour un
/// répertoire courant trop long ou qui ne finit pas par `\` ;
/// `STATUS_NAME_TOO_LONG` pour une chaîne de plus de 32 766 octets.
pub fn block(params: &ProcessParameters<'_>, base: u32, environment: u32) -> Result<Vec<u8>, NtStatus> {
    let directory = params.current_directory;
    if !directory.ends_with('\\') || directory.encode_utf16().count() >= MAX_PATH {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut header = RtlUserProcessParameters32::zeroed();
    let mut strings: Vec<u8> = Vec::new();
    let start = size_of::<RtlUserProcessParameters32>();
    // Each string after the header, terminated, 4-byte aligned; `room` bytes
    // at least.
    let mut place = |text: &str, room: usize| -> Result<UnicodeString32, NtStatus> {
        let (units, length) = utf16(text)?;
        let maximum = (usize::from(length) + 2).max(room);
        let at = start + strings.len();
        for unit in units {
            strings.extend_from_slice(&unit.to_le_bytes());
        }
        strings.resize((at - start + maximum).next_multiple_of(4), 0);
        Ok(UnicodeString32 {
            length,
            maximum_length: u16::try_from(maximum).map_err(|_| STATUS_NAME_TOO_LONG)?,
            buffer: base + at as u32,
        })
    };
    header.current_directory.dos_path = place(directory, MAX_PATH * 2)?;
    header.dll_path = place(params.dll_path, 0)?;
    header.image_path_name = place(params.image_path_name, 0)?;
    header.command_line = place(params.command_line, 0)?;
    header.window_title = place(params.window_title, 0)?;
    header.desktop_info = place(params.desktop_info, 0)?;
    header.shell_info = place("", 0)?;
    header.runtime_data = place("", 0)?;
    let size = (start + strings.len()) as u32;
    header.maximum_length = size;
    header.length = size;
    header.flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
    header.environment = environment;
    let mut bytes = Vec::with_capacity(size as usize);
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(&strings);
    Ok(bytes)
}

/// Le bloc d'environnement : chaque variable en UTF-16, terminée, puis une
/// chaîne vide. `STATUS_INVALID_PARAMETER` pour une variable sans `=` après
/// son nom ; un nom peut commencer par `=` (`=C:`, le répertoire courant
/// d'un lecteur).
pub fn environment_block(variables: &[&str]) -> Result<Vec<u8>, NtStatus> {
    let mut bytes = Vec::new();
    for variable in variables {
        if !variable.chars().skip(1).any(|c| c == '=') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for unit in variable.encode_utf16().chain([0]) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&[0, 0]);
    // An empty environment is two empty strings.
    if variables.is_empty() {
        bytes.extend_from_slice(&[0, 0]);
    }
    Ok(bytes)
}

/// Écrit `params` dans `process` : l'environnement, puis le bloc, chacun dans
/// une allocation à lui, et l'adresse du bloc dans son PEB. Rend cette
/// adresse. Sur une erreur, rien ne reste alloué.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn write(process: &EProcess, params: &ProcessParameters<'_>) -> Result<u32, NtStatus> {
    if process.peb() == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let environment = environment_block(params.environment)?;
    // The block's size does not depend on its address.
    let size = block(params, 0, 0)?.len() as u64;
    let commit = AllocType::MEM_RESERVE | AllocType::MEM_COMMIT;
    let peb_field = u64::from(process.peb()) + offset_of!(Peb32, process_parameters) as u64;
    process.with_space(|space| {
        let env_at = space.allocate(0, environment.len() as u64, commit, PageProtect::READWRITE)?;
        let written = space.write_bytes(env_at, &environment).and_then(|()| {
            let at = space.allocate(0, size, commit, PageProtect::READWRITE)?;
            let filled = block(params, at as u32, env_at as u32)
                .and_then(|bytes| space.write_bytes(at, &bytes))
                .and_then(|()| space.write_bytes(peb_field, &(at as u32).to_le_bytes()));
            if filled.is_err() {
                space.free(at, 0, FreeType::MEM_RELEASE).expect("the block just allocated");
            }
            filled.map(|()| at as u32)
        });
        if written.is_err() {
            space.free(env_at, 0, FreeType::MEM_RELEASE).expect("the environment just allocated");
        }
        written
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_at(bytes: &[u8], base: u32, s: UnicodeString32) -> alloc::string::String {
        let at = (s.buffer - base) as usize;
        let units: Vec<u16> =
            bytes[at..at + usize::from(s.length)].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let end = at + usize::from(s.length);
        assert_eq!(&bytes[end..end + 2], &[0, 0], "terminated");
        assert!(s.maximum_length >= s.length + 2);
        assert_eq!(s.buffer % 4, 0, "aligned");
        assert!(end + 2 <= at + usize::from(s.maximum_length) && at + usize::from(s.maximum_length) <= bytes.len());
        alloc::string::String::from_utf16(&units).unwrap()
    }

    fn header(bytes: &[u8]) -> RtlUserProcessParameters32 {
        assert!(bytes.len() >= size_of::<RtlUserProcessParameters32>());
        // SAFETY: at least as many bytes as the header, which is plain
        // integers; read unaligned.
        unsafe { bytes.as_ptr().cast::<RtlUserProcessParameters32>().read_unaligned() }
    }

    #[test]
    fn the_block_is_normalized_with_its_strings_after_it() {
        let params = ProcessParameters::system("C:\\WINDOWS\\system32\\s1native.exe", "s1native.exe -x");
        let base = 0x0002_0000;
        let bytes = block(&params, base, 0x0001_0000).unwrap();
        let h = header(&bytes);
        assert_eq!((h.flags, h.environment), (RTL_USER_PROCESS_PARAMETERS_NORMALIZED, 0x0001_0000));
        assert_eq!((h.length, h.maximum_length), (bytes.len() as u32, bytes.len() as u32));
        assert_eq!(string_at(&bytes, base, h.image_path_name), "C:\\WINDOWS\\system32\\s1native.exe");
        assert_eq!(string_at(&bytes, base, h.command_line), "s1native.exe -x");
        assert_eq!(string_at(&bytes, base, h.current_directory.dos_path), "C:\\WINDOWS\\system32\\");
        assert_eq!(h.current_directory.dos_path.maximum_length, 520, "MAX_PATH characters, rewritten in place");
        assert_eq!(string_at(&bytes, base, h.dll_path), "C:\\WINDOWS\\system32");
        assert_eq!(string_at(&bytes, base, h.window_title), "C:\\WINDOWS\\system32\\s1native.exe");
        for empty in [h.desktop_info, h.shell_info, h.runtime_data] {
            assert_eq!(string_at(&bytes, base, empty), "");
        }
        assert_eq!(h.image_path_name.buffer, base + 0x290 + 520 + 40, "after the header, the directory, DllPath");
        assert_eq!(block(&params, 0, 0).unwrap().len(), bytes.len(), "the size does not depend on the address");
    }

    #[test]
    fn a_bad_directory_or_a_long_string_is_refused() {
        let params = ProcessParameters::system("a.exe", "a.exe");
        let no_slash = ProcessParameters { current_directory: "C:\\WINDOWS", ..params };
        assert_eq!(block(&no_slash, 0, 0), Err(STATUS_INVALID_PARAMETER));
        let long = alloc::format!("C:\\{}\\", "d".repeat(MAX_PATH - 4));
        assert_eq!(
            block(&ProcessParameters { current_directory: &long, ..params }, 0, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        let longest = alloc::format!("C:\\{}\\", "d".repeat(MAX_PATH - 5));
        assert!(block(&ProcessParameters { current_directory: &longest, ..params }, 0, 0).is_ok(), "259 characters");
        let huge = "x".repeat(32_768);
        assert_eq!(block(&ProcessParameters { command_line: &huge, ..params }, 0, 0), Err(STATUS_NAME_TOO_LONG));
    }

    #[test]
    fn the_environment_is_terminated_strings_then_an_empty_one() {
        let bytes = environment_block(&["A=1", "Path=C:\\"]).unwrap();
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let expected: Vec<u16> = "A=1\0Path=C:\\\0\0".encode_utf16().collect();
        assert_eq!(units, expected);
        assert_eq!(environment_block(&[]).unwrap(), [0, 0, 0, 0]);
        assert_eq!(environment_block(&["NOEQUALS"]), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(environment_block(&["=NAME"]), Err(STATUS_INVALID_PARAMETER), "no name before the =");
        assert!(environment_block(&["=C:=C:\\"]).is_ok(), "a drive's current directory");
    }
}
