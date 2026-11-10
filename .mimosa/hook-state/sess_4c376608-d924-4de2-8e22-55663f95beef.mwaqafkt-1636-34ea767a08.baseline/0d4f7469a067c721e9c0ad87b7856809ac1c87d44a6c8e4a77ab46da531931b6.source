//! Les périphériques (DEVICE_OBJECT, 02 §5.6) et le type `Device`.
//!
//! Un périphérique nommé dans `\Device` résout la suite d'un nom par sa
//! procédure *parse* (IopParseDevice, puis le pilote du système de
//! fichiers) : celui qui porte un volume monté ouvre le fichier ou le
//! répertoire de ce chemin (`\Device\Ramdisk0\WINDOWS\system32` ouvre
//! `\WINDOWS\system32` du volume, comme objet `File`) ; celui des tubes
//! nommés (`\Device\NamedPipe`, [`crate::npfs`]) donne un objet fichier de
//! NPFS pour sa racine ou pour un tube, que le service qui ouvre (ou qui
//! crée une instance) lie ensuite. Le nom du périphérique seul désigne le
//! périphérique lui-même.
//!
//! Pas encore : les objets pilote, les piles de périphériques et les IRP.

use alloc::sync::Arc;

use abi::ntstatus::{NtStatus, STATUS_OBJECT_TYPE_MISMATCH};
use ob::{create_object, downcast, Object, ObjectRef, ObjectType, Parsed};

use crate::file::{File, FILE_ALL_ACCESS_MASK, FILE_GENERIC_MAPPING};
use crate::npfs::Npfs;
use crate::volume::Volume;

/// Le type `Device`.
pub static DEVICE_TYPE: ObjectType =
    ObjectType::new("Device", FILE_ALL_ACCESS_MASK, FILE_GENERIC_MAPPING).with_parse(parse_device);

/// Le corps d'un objet `Device`.
pub struct Device {
    kind: DeviceKind,
}

/// Ce que porte un périphérique.
enum DeviceKind {
    Volume(Arc<Volume>),
    NamedPipe(Arc<Npfs>),
}

impl Device {
    /// Un périphérique qui porte `volume`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn with_volume(volume: Volume) -> Arc<Object<Device>> {
        create_object(&DEVICE_TYPE, Device { kind: DeviceKind::Volume(Arc::new(volume)) })
    }

    /// Le périphérique des tubes nommés de `npfs`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn with_named_pipes(npfs: Arc<Npfs>) -> Arc<Object<Device>> {
        create_object(&DEVICE_TYPE, Device { kind: DeviceKind::NamedPipe(npfs) })
    }

    /// Le volume qu'il porte, s'il en porte un.
    pub fn volume(&self) -> Option<&Arc<Volume>> {
        match &self.kind {
            DeviceKind::Volume(volume) => Some(volume),
            DeviceKind::NamedPipe(_) => None,
        }
    }

    /// Le système de fichiers des tubes nommés qu'il porte, s'il le porte.
    pub fn named_pipes(&self) -> Option<&Arc<Npfs>> {
        match &self.kind {
            DeviceKind::NamedPipe(npfs) => Some(npfs),
            DeviceKind::Volume(_) => None,
        }
    }
}

/// La procédure *parse* des périphériques : le fichier que désigne la suite
/// du nom sur le volume, l'objet fichier de NPFS, ou le périphérique sans
/// suite.
fn parse_device(object: &ObjectRef, remaining: &str) -> Result<Parsed, NtStatus> {
    let device = downcast::<Device>(object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    if remaining.is_empty() {
        return Ok(Parsed::Object(object.clone()));
    }
    match &device.kind {
        DeviceKind::Volume(volume) => Ok(Parsed::Object(File::open(volume, remaining)?)),
        DeviceKind::NamedPipe(npfs) => npfs.parse(remaining),
    }
}
