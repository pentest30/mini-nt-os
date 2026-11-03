//! Les couleurs système que GDI emploie : pour l'instant le seul fond du
//! bureau. La table entière, que GetSysColor lit (`SERVERINFO.argbSystem`),
//! est `crate::metrics::SYSTEM_COLORS`.
//!
//! Pas encore : les pinceaux système, les couleurs lues du registre de
//! l'utilisateur (`Control Panel\Colors`).

use super::dib::ColorRef;

/// COLOR_BACKGROUND : le fond du bureau, RGB(58, 110, 165) (la table par
/// défaut de ReactOS, `win32ss/gdi/ntgdi/stockobj.c`).
pub const BACKGROUND: ColorRef = ColorRef::rgb(58, 110, 165);
