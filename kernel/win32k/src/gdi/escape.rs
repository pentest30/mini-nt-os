//! ExtEscape (NtGdiExtEscape) : les échappements que le pilote d'affichage
//! répond (DrvEscape). Mino n'en répond que deux, ceux par lesquels
//! l'`opengl32` épinglé trouve l'ICD OpenGL du pilote (ADR-025 ; `icdload.c`,
//! IntGetIcdData) : QUERYESCSUPPORT d'OPENGL_GETINFO, puis OPENGL_GETINFO
//! (OPENGL_GETINFO_DRVNAME), qui rend le nom de l'ICD et ses versions
//! (`Drv_Opengl_Info`). `opengl32` ouvre ensuite
//! `OpenGLDrivers\<nom>` (écrit par `tools/mkhive/mino.inf`) et charge sa
//! `Dll` ; sans la clé, sans le fichier ou sans ICD, il garde son rendu
//! logiciel.
//!
//! Comme un pilote d'XP, un échappement qu'il ne connaît pas rend 0 (« pas
//! fait »), comme une demande mal formée : entrée trop courte, sortie trop
//! petite.

use abi::gdi::escape::{
    DrvOpenglInfo32, DRV_OPENGL_INFO_SIZE, OPENGL_GETINFO, OPENGL_GETINFO_DRVNAME, QUERYESCSUPPORT,
};

use crate::display::OpenglIcd;

/// L'échappement `code` du pilote dont l'ICD est `icd`, avec l'entrée
/// `input` et la sortie `output` (de la taille que donne l'appelant) : le
/// résultat de DrvEscape (positif : fait ; 0 : pas fait) et les octets écrits
/// au début d'`output`.
///
/// # IRQL
/// Tout niveau.
pub fn escape(icd: Option<OpenglIcd>, code: u32, input: &[u8], output: &mut [u8]) -> (i32, usize) {
    let argument = input.get(..4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    match (code, argument) {
        (QUERYESCSUPPORT, Some(queried)) => {
            let supported = queried == QUERYESCSUPPORT || (queried == OPENGL_GETINFO && icd.is_some());
            (i32::from(supported), 0)
        }
        (OPENGL_GETINFO, Some(OPENGL_GETINFO_DRVNAME)) => match icd {
            Some(icd) if output.len() >= DRV_OPENGL_INFO_SIZE => {
                let info = DrvOpenglInfo32::new(icd.name, icd.version, icd.driver_version);
                output[..DRV_OPENGL_INFO_SIZE].copy_from_slice(&info.to_bytes());
                (1, DRV_OPENGL_INFO_SIZE)
            }
            _ => (0, 0),
        },
        _ => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESA: Option<OpenglIcd> = Some(OpenglIcd::MESA);

    fn query(icd: Option<OpenglIcd>, queried: u32) -> i32 {
        escape(icd, QUERYESCSUPPORT, &queried.to_le_bytes(), &mut []).0
    }

    #[test]
    fn the_driver_supports_the_opengl_query_only_with_an_icd() {
        assert_eq!(query(MESA, OPENGL_GETINFO), 1);
        assert_eq!(query(None, OPENGL_GETINFO), 0);
        assert_eq!(query(MESA, QUERYESCSUPPORT), 1);
        assert_eq!(query(MESA, 4352), 0, "OPENGL_CMD is not supported");
        assert_eq!(escape(MESA, QUERYESCSUPPORT, &[0x01, 0x11], &mut []).0, 0, "a short input");
    }

    #[test]
    fn opengl_getinfo_names_the_icd_with_its_versions() {
        let mut output = [0xAAu8; DRV_OPENGL_INFO_SIZE + 4];
        let (result, written) = escape(MESA, OPENGL_GETINFO, &OPENGL_GETINFO_DRVNAME.to_le_bytes(), &mut output);
        assert_eq!((result, written), (1, DRV_OPENGL_INFO_SIZE));
        assert_eq!(&output[..8], &[2, 0, 0, 0, 1, 0, 0, 0], "Version 2, DriverVersion 1");
        assert_eq!(&output[8..18], &[b'M', 0, b'e', 0, b's', 0, b'a', 0, 0, 0]);
        assert_eq!(&output[DRV_OPENGL_INFO_SIZE..], &[0xAA; 4], "nothing written past the info");
    }

    #[test]
    fn opengl_getinfo_refuses_what_it_cannot_answer() {
        let drvname = OPENGL_GETINFO_DRVNAME.to_le_bytes();
        let mut small = [0u8; DRV_OPENGL_INFO_SIZE - 1];
        assert_eq!(escape(MESA, OPENGL_GETINFO, &drvname, &mut small), (0, 0), "a short output");
        let mut output = [0u8; DRV_OPENGL_INFO_SIZE];
        assert_eq!(escape(None, OPENGL_GETINFO, &drvname, &mut output), (0, 0), "no ICD");
        assert_eq!(escape(MESA, OPENGL_GETINFO, &1u32.to_le_bytes(), &mut output), (0, 0), "another subcode");
        assert_eq!(escape(MESA, OPENGL_GETINFO, &[], &mut output), (0, 0), "no input");
        assert_eq!(escape(MESA, 0x1000, &drvname, &mut output), (0, 0), "an unknown escape");
    }
}
