//! Les capacités de l'écran (PDEVOBJ_vGetDeviceCaps de `pdevobj.c`, le
//! GDIINFO du pilote `framebuf` de ReactOS, comme spécification) : ce que
//! rend GetDeviceCaps. `gdi32` les lit dans la table des handles partagée
//! (`DevCaps`, après les entrées) pour un DC de l'écran principal
//! (`DC_PRIMARY_DISPLAY` dans ses attributs, ce qu'ont tous les DC ici),
//! sans appeler le noyau ; [`publish`] les y écrit quand le pilote
//! d'affichage est installé.
//!
//! L'écran est celui du pilote : 32 bits par pixel, sans palette, à 96
//! points par pouce (sa taille en millimètres en vient), 60 Hz.
//!
//! Pas encore : NtGdiGetDeviceCaps et NtGdiGetDeviceCapsAll (un DC d'un
//! autre périphérique), un changement de mode.

use abi::gdi::caps::{
    DT_RASDISPLAY, GDI_DRIVER_VERSION, RC_BIGFONT, RC_BITBLT, RC_BITMAP64, RC_DIBTODEV, RC_DI_BITMAP, RC_FLOODFILL,
    RC_GDI20_OUTPUT, RC_OP_DX_OUTPUT, RC_STRETCHBLT, RC_STRETCHDIB, TC_CP_STROKE, TC_OP_CHARACTER, TC_OP_STROKE,
    TC_RA_ABLE, TC_SO_ABLE, TC_UA_ABLE, TC_VA_ABLE,
};
use abi::gdi::DevCaps32;
use abi::ntstatus::NtStatus;

use crate::display::Mode;

/// Les points par pouce de l'écran (`ulLogPixelsX`, `ulLogPixelsY`).
pub const LOG_PIXELS: u32 = 96;
/// Ses bits par pixel.
pub const BITS_PIXEL: u32 = 32;
/// Sa fréquence de rafraîchissement, que le framebuffer UEFI ne dit pas.
const REFRESH: u32 = 60;

/// Les millimètres de `pixels` pixels à [`LOG_PIXELS`] points par pouce,
/// arrondis.
const fn millimetres(pixels: u32) -> u32 {
    (pixels * 254 + LOG_PIXELS * 5) / (LOG_PIXELS * 10)
}

/// PDEVOBJ_vGetDeviceCaps : les capacités d'un écran du mode `mode`.
pub fn of_display(mode: &Mode) -> DevCaps32 {
    let (width, height) = (mode.width, mode.height);
    let (horz_size, vert_size) = (millimetres(width), millimetres(height));
    DevCaps32 {
        version: GDI_DRIVER_VERSION,
        technology: DT_RASDISPLAY,
        horz_size_m: (horz_size + 500) / 1000,
        vert_size_m: (vert_size + 500) / 1000,
        horz_size,
        vert_size,
        horz_res: width,
        vert_res: height,
        bits_pixel: BITS_PIXEL,
        planes: 1,
        // More than 256 colours: -1, for the pens too.
        num_pens: u32::MAX,
        num_fonts: 0,
        num_colors: u32::MAX,
        // What the PDEV adds to a raster display's (EngpCreatePDEV).
        raster_caps: RC_OP_DX_OUTPUT
            | RC_GDI20_OUTPUT
            | RC_BIGFONT
            | RC_STRETCHDIB
            | RC_STRETCHBLT
            | RC_DIBTODEV
            | RC_DI_BITMAP
            | RC_BITMAP64
            | RC_BITBLT
            | RC_FLOODFILL,
        aspect_x: 36,
        aspect_y: 36,
        aspect_xy: 51,
        log_pixels_x: LOG_PIXELS,
        log_pixels_y: LOG_PIXELS,
        size_palette: 0,
        color_res: 3 * 8,
        physical_width: 0,
        physical_height: 0,
        physical_offset_x: 0,
        physical_offset_y: 0,
        text_caps: TC_RA_ABLE | TC_SO_ABLE | TC_UA_ABLE | TC_CP_STROKE | TC_OP_STROKE | TC_OP_CHARACTER | TC_VA_ABLE,
        v_refresh: REFRESH,
        desktop_horz_res: width,
        desktop_vert_res: height,
        blt_alignment: 1,
        panning_horz_res: width,
        panning_vert_res: height,
        x_panning_alignment: 0,
        y_panning_alignment: 0,
        shade_blend: 0,
        // CM_NONE: neither a palette nor a gamma ramp.
        color_mgmt_caps: 0,
    }
}

/// Écrit les capacités de l'écran du mode `mode` dans la table des handles
/// partagée.
///
/// # Errors
/// Celles de l'écriture de la section de la table.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, après la table des handles.
pub fn publish(mode: &Mode) -> Result<(), NtStatus> {
    super::handles::set_device_caps(&of_display(mode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdi::dib::PixelLayout;

    #[test]
    fn a_display_of_800_by_600() {
        let caps = of_display(&Mode { width: 800, height: 600, layout: PixelLayout::Bgrx });
        assert_eq!((caps.horz_res, caps.vert_res, caps.bits_pixel, caps.planes), (800, 600, 32, 1));
        assert_eq!((caps.desktop_horz_res, caps.panning_vert_res), (800, 600));
        assert_eq!((caps.horz_size, caps.vert_size), (212, 159), "millimetres at 96 dots per inch");
        assert_eq!((caps.log_pixels_x, caps.log_pixels_y, caps.aspect_xy), (96, 96, 51));
        assert_eq!((caps.num_colors, caps.num_pens, caps.size_palette), (u32::MAX, u32::MAX, 0), "no palette");
        assert_eq!(caps.technology, DT_RASDISPLAY);
        assert_eq!(caps.raster_caps, 0x7E99, "BitBlt, StretchBlt, DIBs, flood fill, no palette");
        assert_eq!(caps.text_caps, 0x7807);
    }
}
