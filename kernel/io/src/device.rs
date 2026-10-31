//! Les périphériques (DEVICE_OBJECT, 02 §5.6) et le type `Device`.
//!
//! Un périphérique nommé dans `\Device` qui porte un volume monté résout la
//! suite d'un nom par sa procédure *parse* (IopParseDevice, puis le pilote
//! du système de fichiers) : `\Device\Ramdisk0\WINDOWS\system32` ouvre le
//! répertoire `\WINDOWS\system32` du volume, comme objet `File`. Le nom du
//! périphérique seul désigne le périphérique lui-même.
//!
//! Pas encore : les objets pilote, les piles de périphériques et les IRP ;
//! un périphérique sans volume.

use alloc::sync::Arc;

use abi::ntstatus::{NtStatus, STATUS_OBJECT_TYPE_MISMATCH};
use ob::{create_object, downcast, Object, ObjectRef, ObjectType, Parsed};

use crate::file::{File, FILE_ALL_ACCESS_MASK, FILE_GENERIC_MAPPING};
use crate::volume::Volume;

/// Le type `Device`.
pub static DEVICE_TYPE: ObjectType =
    ObjectType::new("Device", FILE_ALL_ACCESS_MASK, FILE_GENERIC_MAPPING).with_parse(parse_device);

/// Le corps d'un objet `Device`.
pub struct Device {
    volume: Arc<Volume>,
}

impl Device {
    /// Un périphérique qui porte `volume`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn with_volume(volume: Volume) -> Arc<Object<Device>> {
        create_object(&DEVICE_TYPE, Device { volume: Arc::new(volume) })
    }

    /// Le volume qu'il porte.
    pub fn volume(&self) -> &Arc<Volume> {
        &self.volume
    }
}

/// La procédure *parse* des périphériques : le fichier que désigne la suite
/// du nom sur le volume, ou le périphérique sans suite.
fn parse_device(object: &ObjectRef, remaining: &str) -> Result<Parsed, NtStatus> {
    let device = downcast::<Device>(object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    if remaining.is_empty() {
        return Ok(Parsed::Object(object.clone()));
    }
    Ok(Parsed::Object(File::open(&device.volume, remaining)?))
}
