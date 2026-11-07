//! Les couleurs système que GDI emploie : pour l'instant le seul fond du
//! bureau. La table entière, que GetSysColor lit (`SERVERINFO.argbSystem`),
//! est `crate::metrics::SYSTEM_COLORS`.
//!
//! Pas encore : les pinceaux système, les couleurs lues du registre de
//! l'utilisateur (`Control Panel\Colors`).

use super::dib::ColorRef;

/// COLOR_BACKGROUND : le fond du bureau, RGB(90, 126, 220) — le bleu clair
/// de l'écran d'accueil de MINO OS (le champ clair entre les deux bandes
/// sombres).
pub const BACKGROUND: ColorRef = ColorRef::rgb(90, 126, 220);
