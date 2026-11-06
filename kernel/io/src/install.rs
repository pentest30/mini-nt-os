//! Moteur privilégié de l'installateur : inventaire sûr et plan en lecture
//! seule. Aucune fonction de ce module n'écrit encore sur un disque.
//!
//! Le média IDE primaire qui a démarré les scénarios et le disque qui porte
//! le système courant sont protégés. Le premier jalon ne propose donc que le
//! maître secondaire présent, non monté et distinct du système. Le plan est
//! calculé entièrement avant d'être rendu à l'interface.

use core::sync::atomic::{AtomicU8, Ordering};

use abi::setup::{
    SetupPreview, SETUP_ABI_VERSION, SETUP_DISK_BOOT, SETUP_DISK_CANDIDATE, SETUP_DISK_SYSTEM, SETUP_NO_TARGET,
    SETUP_READY, SETUP_TOO_SMALL,
};

use crate::disk::AtaDisk;

/// Alignement GPT des partitions : 1 Mio sur des secteurs de 512 octets.
const ALIGNMENT: u64 = 2048;
/// La politique guidée réserve 40 Mio à l'ESP.
const ESP_SECTORS: u64 = 40 * 2048;
/// Numéro du maître primaire dans l'ABI.
const PRIMARY_MASTER: u32 = 1;
/// Numéro du maître secondaire dans l'ABI.
const SECONDARY_MASTER: u32 = 2;

/// 0 : système en RAM ; 1 : maître primaire ; 2 : maître secondaire.
static SYSTEM_DISK_NUMBER: AtomicU8 = AtomicU8::new(0);

/// Un disque vu par le planificateur, sans accès à son contenu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disk {
    number: u32,
    sectors: u64,
    flags: u32,
}

impl Disk {
    #[cfg(test)]
    fn candidate(number: u32, sectors: u64) -> Self {
        Self { number, sectors, flags: SETUP_DISK_CANDIDATE }
    }

    #[cfg(test)]
    fn protected(number: u32, sectors: u64, flags: u32) -> Self {
        Self { number, sectors, flags }
    }
}

/// Un plan dont les champs deviennent immuables après validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    disk: Disk,
    token: u64,
    esp_first: u64,
    esp_sectors: u64,
    system_first: u64,
    system_sectors: u64,
}

/// Pourquoi aucun plan guidé ne peut être produit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    Protected,
    TooSmall,
}

impl Plan {
    /// Calcule les deux partitions dans la plage utilisable d'une GPT
    /// canonique. Les deux tailles doivent être acceptées par le formateur
    /// FAT32 avant que le plan soit rendu.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL ; aucun accès au disque.
    pub fn guided(disk: Disk) -> Result<Self, PlanError> {
        if disk.flags != SETUP_DISK_CANDIDATE {
            return Err(PlanError::Protected);
        }
        let esp_first = ALIGNMENT;
        let system_first = align_up(esp_first.checked_add(ESP_SECTORS).ok_or(PlanError::TooSmall)?)?;
        let last_usable = disk.sectors.checked_sub(34).ok_or(PlanError::TooSmall)?;
        let system_sectors = last_usable
            .checked_sub(system_first)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(PlanError::TooSmall)?;
        let esp = u32::try_from(ESP_SECTORS).map_err(|_| PlanError::TooSmall)?;
        let system = u32::try_from(system_sectors).map_err(|_| PlanError::TooSmall)?;
        if fatfs::format::Geometry::for_sectors(esp).is_none() || fatfs::format::Geometry::for_sectors(system).is_none()
        {
            return Err(PlanError::TooSmall);
        }
        let mut plan = Self { disk, token: 0, esp_first, esp_sectors: ESP_SECTORS, system_first, system_sectors };
        plan.token = plan.fingerprint();
        Ok(plan)
    }

    fn fingerprint(&self) -> u64 {
        // FNV-1a sert d'identifiant anti-confusion, pas de secret
        // cryptographique. Le futur appel d'exécution reverra aussi la
        // capacité et l'identité matérielle avant la première écriture.
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for value in [
            u64::from(self.disk.number),
            self.disk.sectors,
            self.esp_first,
            self.esp_sectors,
            self.system_first,
            self.system_sectors,
        ] {
            for byte in value.to_le_bytes() {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        hash
    }

    fn preview(self) -> SetupPreview {
        SetupPreview {
            version: SETUP_ABI_VERSION,
            state: SETUP_READY,
            disk_number: self.disk.number,
            disk_flags: self.disk.flags,
            sector_size: 512,
            total_sectors: self.disk.sectors,
            plan_token: self.token,
            esp_first: self.esp_first,
            esp_sectors: self.esp_sectors,
            system_first: self.system_first,
            system_sectors: self.system_sectors,
        }
    }
}

fn align_up(value: u64) -> Result<u64, PlanError> {
    value.checked_add(ALIGNMENT - 1).map(|value| value / ALIGNMENT * ALIGNMENT).ok_or(PlanError::TooSmall)
}

/// Mémorise quel disque ATA porte le système courant. `None` signifie que
/// `C:` est le disque RAM. Appelé une fois pendant le montage initial.
///
/// # IRQL
/// PASSIVE_LEVEL, pendant l'initialisation.
pub fn record_system_disk(primary: Option<bool>) {
    SYSTEM_DISK_NUMBER.store(primary.map_or(0, |primary| if primary { 1 } else { 2 }), Ordering::Release);
}

/// Rend la cible guidée et son plan sans écrire sur le disque. Le maître
/// primaire reste réservé au média de démarrage dans ce jalon ; seul un
/// maître secondaire non système peut être proposé.
///
/// # IRQL
/// PASSIVE_LEVEL (IDENTIFY DEVICE attend le matériel).
pub fn preview() -> SetupPreview {
    let system = u32::from(SYSTEM_DISK_NUMBER.load(Ordering::Acquire));
    if let Some(disk) = AtaDisk::probe(hal::ata::AtaDrive::new(hal::ata::SECONDARY, false)) {
        let number = SECONDARY_MASTER;
        let flags = if system == number { SETUP_DISK_SYSTEM } else { SETUP_DISK_CANDIDATE };
        let candidate = Disk { number, sectors: disk.sectors(), flags };
        return match Plan::guided(candidate) {
            Ok(plan) => plan.preview(),
            Err(PlanError::TooSmall) => unavailable(candidate, SETUP_TOO_SMALL),
            Err(PlanError::Protected) => unavailable(candidate, SETUP_NO_TARGET),
        };
    }
    if let Some(disk) = AtaDisk::probe(hal::ata::AtaDrive::new(hal::ata::PRIMARY, false)) {
        let flags = SETUP_DISK_BOOT | if system == PRIMARY_MASTER { SETUP_DISK_SYSTEM } else { 0 };
        return unavailable(Disk { number: PRIMARY_MASTER, sectors: disk.sectors(), flags }, SETUP_NO_TARGET);
    }
    SetupPreview { version: SETUP_ABI_VERSION, state: SETUP_NO_TARGET, sector_size: 512, ..Default::default() }
}

fn unavailable(disk: Disk, state: u32) -> SetupPreview {
    SetupPreview {
        version: SETUP_ABI_VERSION,
        state,
        disk_number: disk.number,
        disk_flags: disk.flags,
        sector_size: 512,
        total_sectors: disk.sectors,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guided_plan_is_aligned_bounded_and_stable() {
        let disk = Disk::candidate(SECONDARY_MASTER, 192 * 2048);
        let first = Plan::guided(disk).unwrap();
        let second = Plan::guided(disk).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.esp_first % ALIGNMENT, 0);
        assert_eq!(first.system_first % ALIGNMENT, 0);
        assert!(first.system_first >= first.esp_first + first.esp_sectors);
        assert_eq!(first.system_first + first.system_sectors, disk.sectors - 33);
        assert_ne!(first.token, 0);
        assert_eq!(first.preview().state, SETUP_READY);
    }

    #[test]
    fn system_and_boot_disks_are_refused() {
        for flags in [SETUP_DISK_SYSTEM, SETUP_DISK_BOOT, SETUP_DISK_SYSTEM | SETUP_DISK_BOOT] {
            let disk = Disk::protected(SECONDARY_MASTER, 192 * 2048, flags);
            assert_eq!(Plan::guided(disk), Err(PlanError::Protected));
        }
    }

    #[test]
    fn both_fat32_volumes_must_fit() {
        let too_small = Disk::candidate(SECONDARY_MASTER, 72 * 2048);
        assert_eq!(Plan::guided(too_small), Err(PlanError::TooSmall));
        assert!(Plan::guided(Disk::candidate(SECONDARY_MASTER, 96 * 2048)).is_ok());
    }
}
