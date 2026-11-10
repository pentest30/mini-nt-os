//! Les moniteurs : un seul, le principal, de la taille de l'écran, que
//! win32k attache quand il initialise l'affichage (InitVideo, avec les
//! métriques du système).
//!
//! Comme ReactOS (`monitor.c`, `window.c`, comme spécification) : le
//! moniteur a un handle USER (`TYPE_MONITOR`), son rectangle (`rcMonitor`)
//! et sa zone de travail (`rcWork`, la même tant que rien ne la réduit) ;
//! il compte les fenêtres recouvrantes placées par défaut (`cWndStack`), en
//! cascade ([`cascade`]). MonitorFromWindow, MonitorFromRect et
//! MonitorFromPoint le trouvent d'après un rectangle ([`from_rect`]),
//! GetMonitorInfo le décrit ([`get`]).
//!
//! Pas encore : plusieurs moniteurs (EnumDisplayMonitors), le changement de
//! mode (UserUpdateMonitorSize), la région du moniteur, une zone de travail
//! réduite (la barre des tâches, SPI_SETWORKAREA). L'objet du moniteur n'est
//! pas dans la section partagée : son entrée de la table des handles n'a
//! pas d'adresse (`user32` ne le lit pas, il passe par win32k).

use abi::ntstatus::NtStatus;
use abi::user::{sm, MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTOPRIMARY, TYPE_MONITOR};
use hal::sync::KSpinLock;

use crate::gdi::dib::Rect;

/// Un moniteur : son handle, son rectangle et sa zone de travail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Monitor {
    pub handle: u32,
    pub rect: Rect,
    pub work: Rect,
}

/// Le moniteur principal, et les fenêtres placées en cascade.
struct Primary {
    monitor: Monitor,
    window_stack: i32,
}

static PRIMARY: KSpinLock<Option<Primary>> = KSpinLock::new(None);

/// UserAttachMonitor puis UserUpdateMonitorSize : le moniteur principal,
/// d'un écran de `width` × `height`. Une seconde fois, il change de taille.
///
/// # Errors
/// Celles de la table des handles.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn attach(width: i32, height: i32) -> Result<(), NtStatus> {
    let rect = Rect::new(0, 0, width, height);
    let mut primary = PRIMARY.lock();
    if let Some(primary) = primary.as_mut() {
        (primary.monitor.rect, primary.monitor.work) = (rect, rect);
        return Ok(());
    }
    let handle = crate::handles::alloc(0, 0, TYPE_MONITOR)?;
    *primary = Some(Primary { monitor: Monitor { handle, rect, work: rect }, window_stack: 0 });
    Ok(())
}

/// UserGetPrimaryMonitor : le moniteur principal, s'il y en a un.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn primary() -> Option<Monitor> {
    PRIMARY.lock().as_ref().map(|primary| primary.monitor)
}

/// UserGetMonitorObject : le moniteur de handle `handle`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get(handle: u32) -> Option<Monitor> {
    primary().filter(|monitor| handle != 0 && monitor.handle == handle)
}

/// IntGetMonitorsFromRect, pour un moniteur de rectangle `monitor` : s'il
/// est rendu pour `rect` (il le coupe, ou, sinon, `flags` demande le plus
/// proche ou le principal ; seul, il est l'un et l'autre).
pub fn covers(monitor: Rect, rect: Rect, flags: u32) -> bool {
    !monitor.intersect(&rect).is_empty() || flags == MONITOR_DEFAULTTONEAREST || flags == MONITOR_DEFAULTTOPRIMARY
}

/// IntGetMonitorFromRect : le moniteur de `rect` (`MONITOR_DEFAULTTO*`).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn from_rect(rect: Rect, flags: u32) -> Option<Monitor> {
    primary().filter(|monitor| covers(monitor.rect, rect, flags))
}

/// La place en cascade de la fenêtre recouvrante numéro `stack` d'une zone
/// de travail `work` (IntFixWindowCoordinates), d'après les métriques `m`,
/// et le numéro de la suivante : la cascade recommence en haut à gauche
/// quand elle dépasse le quart de la zone.
pub fn cascade(stack: i32, work: Rect, m: &impl Fn(usize) -> i32) -> ((i32, i32), i32) {
    let x = stack * (m(sm::CXSIZE) + m(sm::CXFRAME));
    let y = stack * (m(sm::CYSIZE) + m(sm::CYFRAME));
    if x > (work.right - work.left) / 4 || y > (work.bottom - work.top) / 4 {
        return ((0, 0), 1);
    }
    ((x, y), stack + 1)
}

/// La place de la prochaine fenêtre recouvrante placée par défaut sur le
/// moniteur principal ([`cascade`]) ; `None` sans moniteur.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn next_cascade_place() -> Option<(i32, i32)> {
    let mut primary = PRIMARY.lock();
    let primary = primary.as_mut()?;
    let (place, next) = cascade(primary.window_stack, primary.monitor.work, &crate::metrics::get);
    primary.window_stack = next;
    Some(place)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::MONITOR_DEFAULTTONULL;

    fn metric(index: usize) -> i32 {
        crate::metrics::system_metrics(1280, 800, &crate::metrics::Parameters::DEFAULT)[index]
    }

    #[test]
    fn a_rectangle_finds_the_monitor_it_crosses() {
        let screen = Rect::new(0, 0, 1280, 800);
        assert!(covers(screen, Rect::new(1270, 790, 1300, 820), MONITOR_DEFAULTTONULL), "a corner on it");
        assert!(!covers(screen, Rect::new(1280, 0, 1300, 20), MONITOR_DEFAULTTONULL), "beside it");
        assert!(!covers(screen, Rect::new(5, 5, 5, 5), MONITOR_DEFAULTTONULL), "an empty rectangle crosses nothing");
        assert!(covers(screen, Rect::new(2000, 0, 2100, 20), MONITOR_DEFAULTTONEAREST), "the nearest");
        assert!(covers(screen, Rect::new(2000, 0, 2100, 20), MONITOR_DEFAULTTOPRIMARY), "the primary");
    }

    #[test]
    fn default_places_cascade_then_start_again() {
        let work = Rect::new(0, 0, 1280, 800);
        assert_eq!(cascade(0, work, &metric), ((0, 0), 1));
        assert_eq!(cascade(1, work, &metric), ((23, 23), 2), "a caption button and a frame further");
        assert_eq!(cascade(8, work, &metric), ((184, 184), 9));
        assert_eq!(cascade(9, work, &metric), ((0, 0), 1), "207 is beyond a quarter of 800");
    }
}
