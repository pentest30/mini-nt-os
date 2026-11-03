//! Les couleurs système (GetSysColor) : celles que GDI connaît avant que
//! `winlogon` ou le panneau de configuration ne les change. Pour l'instant
//! le seul fond du bureau.
//!
//! Pas encore : la table entière (`SERVERINFO.argbSystem`, les pinceaux
//! système), lue du registre de l'utilisateur (`Control Panel\Colors`).

use super::dib::ColorRef;

/// COLOR_BACKGROUND : le fond du bureau, RGB(58, 110, 165) (la table par
/// défaut de ReactOS, `win32ss/gdi/ntgdi/stockobj.c`).
pub const BACKGROUND: ColorRef = ColorRef::rgb(58, 110, 165);
