//! Moteur privilégié de l'installateur : inventaire sûr, plan en lecture
//! seule, puis préparation — les tables GPT du plan, écrites une fois le
//! jeton reverifié, et relues pour être vérifiées. Ce module ne formate pas
//! et ne copie rien : les volumes et les fichiers viennent après.
//!
//! Le média IDE primaire qui a démarré les scénarios et le disque qui porte
//! le système courant sont protégés. Le premier jalon ne propose donc que le
//! maître secondaire présent, non monté et distinct du système. Le plan est
//! calculé entièrement avant d'être rendu à l'interface, et revérifié
//! entièrement avant la première écriture.

use core::sync::atomic::{AtomicU8, Ordering};

use abi::setup::{
    SetupPreview, SETUP_ABI_VERSION, SETUP_DISK_BOOT, SETUP_DISK_CANDIDATE, SETUP_DISK_SYSTEM, SETUP_NO_TARGET,
    SETUP_READY, SETUP_TOO_SMALL,
};

use crate::disk::AtaDisk;
use crate::fat::{BlockDevice, FatError};

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

/// Pourquoi une préparation n'écrit rien.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareError {
    /// Le disque demandé n'est pas là.
    NoTarget,
    /// Le disque porte le système courant, ou est le média de démarrage.
    Protected,
    /// Le jeton ne décrit plus le plan du disque (capacité ou géométrie
    /// changées).
    TokenMismatch,
    /// Le disque porte déjà des tables de partitions : la revue de
    /// l'interface est la dernière étape réversible, un disque occupé ne se
    /// réécrit pas.
    NotBlank,
    /// La capacité ou la géométrie ne permettent plus le plan.
    CapacityMismatch,
    /// Une autre préparation est en cours : le verrou exclusif du moteur
    /// tient une seule écriture de tables à la fois.
    Busy,
    /// Une écriture ou la relecture de vérification a échoué.
    Io,
}

/// Le verrou exclusif du moteur : une seule préparation à la fois, quel
/// que soit l'appelant. La préparation bloque son thread le temps des E/S
/// PIO ; le verrou empêche un second appelant d'écrire en même temps.
#[derive(Default)]
pub struct Exclusive(AtomicU8);

impl Exclusive {
    /// Prend le verrou ; `false` s'il est déjà pris.
    pub fn try_acquire(&self) -> bool {
        self.0.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    /// Le rend.
    pub fn release(&self) {
        self.0.store(0, Ordering::Release);
    }
}

/// Le verrou du moteur, autour de chaque préparation réelle.
static PREPARE_LOCK: Exclusive = Exclusive(AtomicU8::new(0));

/// Un GUID tiré du jeton, d'un nonce propre à cette exécution et d'un rôle
/// (1 : le disque, 2 : l'ESP, 3 : le système). La bibliothèque GPT n'invente
/// rien ; le nonce empêche deux installations de même capacité de partager
/// leurs identifiants.
fn guid(token: u64, nonce: u64, role: u64) -> gpt::Guid {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in token.to_le_bytes().iter().chain(nonce.to_le_bytes().iter()).chain(role.to_le_bytes().iter()) {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    let low = hash;
    let high = (hash ^ 0xa5a5_a5a5_a5a5_a5a5).rotate_left(23).wrapping_mul(0x0000_0100_0000_01b3);
    let mut guid = [0u8; 16];
    guid[..8].copy_from_slice(&low.to_le_bytes());
    guid[8..].copy_from_slice(&high.to_le_bytes());
    // Version 4 et variante RFC 4122 : un GUID bien formé, qui ne peut pas
    // être le GUID nul que `Layout::new` refuse.
    guid[7] = (guid[7] & 0x0f) | 0x40;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    guid
}

/// [`gpt`] vu sur un [`BlockDevice`] : les mêmes secteurs de 512 octets, la
/// même erreur.
struct BlockSectors<'a, B: BlockDevice>(&'a B);

impl<B: BlockDevice> gpt::ReadSectors for BlockSectors<'_, B> {
    type Error = FatError;

    fn read_sector(&self, lba: u64, sector: &mut [u8; gpt::SECTOR_SIZE]) -> Result<(), FatError> {
        self.0.read_sector(lba, sector.as_mut_slice())
    }
}

impl<B: BlockDevice> gpt::WriteSectors for BlockSectors<'_, B> {
    fn write_sector(&mut self, lba: u64, sector: &[u8; gpt::SECTOR_SIZE]) -> Result<(), FatError> {
        self.0.write_sector(lba, sector.as_slice())
    }

    fn flush(&mut self) -> Result<(), FatError> {
        self.0.flush()
    }
}

/// Vérifie une dernière fois le plan sur ce que le disque est maintenant
/// (`flags`, capacité — qui entre dans l'empreinte du jeton), refuse un
/// disque qui porte déjà des tables, écrit le MBR protecteur et les deux
/// copies GPT (la secours d'abord, [`gpt::write`]), puis les relit : les
/// deux copies valides et les plages du plan. Ne formate pas et ne copie
/// rien.
///
/// # IRQL
/// <= DISPATCH_LEVEL ; le disque doit attendre la préemption (PIO).
pub fn prepare_disk<D: gpt::WriteSectors<Error = FatError>>(
    disk: &mut D,
    sectors: u64,
    number: u32,
    flags: u32,
    token: u64,
    nonce: u64,
) -> Result<gpt::Layout, PrepareError> {
    let plan = Plan::guided(Disk { number, sectors, flags }).map_err(|error| match error {
        PlanError::Protected => PrepareError::Protected,
        PlanError::TooSmall => PrepareError::CapacityMismatch,
    })?;
    if plan.token != token {
        return Err(PrepareError::TokenMismatch);
    }
    let mut mbr = [0u8; gpt::SECTOR_SIZE];
    disk.read_sector(0, &mut mbr).map_err(|_| PrepareError::Io)?;
    if gpt::has_protective_partition(&mbr) {
        return Err(PrepareError::NotBlank);
    }
    let partition = |index: u32, role: u64, kind: gpt::Guid, first: u64, last: u64, name: &str| gpt::Partition {
        index,
        kind,
        id: guid(token, nonce, role),
        first_lba: first,
        last_lba: last,
        attributes: 0,
        name: {
            let mut units = [0u16; 36];
            for (at, unit) in name.encode_utf16().enumerate() {
                units[at] = unit;
            }
            units
        },
    };
    let partitions = alloc::vec![
        partition(1, 2, gpt::EFI_SYSTEM, plan.esp_first, plan.esp_first + plan.esp_sectors - 1, "ESP"),
        partition(2, 3, gpt::BASIC_DATA, plan.system_first, plan.system_first + plan.system_sectors - 1, "MINO"),
    ];
    let layout =
        gpt::Layout::new(sectors, guid(token, nonce, 1), partitions).map_err(|_| PrepareError::CapacityMismatch)?;
    gpt::write(disk, &layout).map_err(|_| PrepareError::Io)?;
    // La vérification après écriture : les deux copies valides, leur CRC,
    // et les plages que le plan décrivait.
    let (read_back, source) = gpt::read(disk, sectors).map_err(|_| PrepareError::Io)?;
    if source != gpt::Source::Both || read_back != layout {
        return Err(PrepareError::Io);
    }
    Ok(layout)
}

/// Prépare le disque `number` d'après le jeton `token` de l'aperçu. Le
/// média de démarrage (le maître primaire) et le disque qui porte le
/// système courant sont refusés avant toute écriture ; le verrou exclusif
/// tient une seule préparation à la fois.
///
/// # IRQL
/// PASSIVE_LEVEL (IDENTIFY DEVICE et les E/S PIO attendent le matériel).
pub fn prepare(number: u32, token: u64) -> Result<gpt::Layout, PrepareError> {
    if number == PRIMARY_MASTER {
        return Err(PrepareError::Protected);
    }
    if u32::from(SYSTEM_DISK_NUMBER.load(Ordering::Acquire)) == number {
        return Err(PrepareError::Protected);
    }
    if number != SECONDARY_MASTER {
        return Err(PrepareError::NoTarget);
    }
    // Une seule écriture de tables à la fois : le verrou tient toute la
    // préparation, de la sonde du disque à sa relecture.
    if !PREPARE_LOCK.try_acquire() {
        return Err(PrepareError::Busy);
    }
    let prepared = prepare_locked(number, token);
    PREPARE_LOCK.release();
    prepared
}

fn prepare_locked(number: u32, token: u64) -> Result<gpt::Layout, PrepareError> {
    let disk = AtaDisk::probe(hal::ata::AtaDrive::new(hal::ata::SECONDARY, false)).ok_or(PrepareError::NoTarget)?;
    let sectors = disk.sectors();
    let mut view = BlockSectors(&disk);
    let nonce = hal::rtc::system_time() ^ hal::timer::performance_counter().0 ^ token;
    prepare_disk(&mut view, sectors, number, SETUP_DISK_CANDIDATE, token, nonce)
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

#[cfg(test)]
mod prepare_tests {
    use super::*;
    use crate::fat::FatError;
    use alloc::vec::Vec;

    const NONCE: u64 = 0x1234_5678_9abc_def0;

    /// Le disque de développement des scénarios : 96 Mio, en mémoire.
    struct RamSectors(Vec<u8>);

    impl RamSectors {
        const SECTORS: u64 = 96 * 2048;

        fn new() -> Self {
            Self(alloc::vec![0u8; Self::SECTORS as usize * 512])
        }

        fn sector(&self, lba: u64) -> &[u8] {
            let at = lba as usize * 512;
            &self.0[at..at + 512]
        }
    }

    impl gpt::ReadSectors for RamSectors {
        type Error = FatError;

        fn read_sector(&self, lba: u64, sector: &mut [u8; gpt::SECTOR_SIZE]) -> Result<(), FatError> {
            sector.copy_from_slice(self.sector(lba));
            Ok(())
        }
    }

    impl gpt::WriteSectors for RamSectors {
        fn write_sector(&mut self, lba: u64, sector: &[u8; gpt::SECTOR_SIZE]) -> Result<(), FatError> {
            self.0[lba as usize * 512..(lba as usize + 1) * 512].copy_from_slice(sector);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), FatError> {
            Ok(())
        }
    }

    fn candidate() -> Disk {
        Disk::candidate(SECONDARY_MASTER, RamSectors::SECTORS)
    }

    fn token_of(disk: Disk) -> u64 {
        Plan::guided(disk).expect("the plan").token
    }

    #[test]
    fn prepare_writes_the_plan_and_rereads_it() {
        let token = token_of(candidate());
        let mut disk = RamSectors::new();
        let layout = prepare_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token, NONCE)
            .expect("the disk prepares");
        // Les plages du plan, un MBR protecteur, et les deux copies que la
        // bibliothèque relit d'elle-même.
        let esp = &layout.partitions()[0];
        let system = &layout.partitions()[1];
        assert_eq!((esp.first_lba, esp.last_lba), (2048, 2048 + 40 * 2048 - 1));
        assert_eq!(system.first_lba, esp.last_lba + 1);
        assert_eq!(layout.usable_range().1, RamSectors::SECTORS - 34);
        assert_eq!(disk.sector(0)[450], 0xee);
        let (read_back, source) = gpt::read(&disk, RamSectors::SECTORS).expect("the tables reread");
        assert_eq!(source, gpt::Source::Both);
        assert_eq!(read_back, layout);
    }

    #[test]
    fn a_wrong_token_writes_nothing() {
        let token = token_of(candidate());
        let mut disk = RamSectors::new();
        let before = disk.0.clone();
        let error =
            prepare_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token ^ 1, NONCE)
                .unwrap_err();
        assert_eq!(error, PrepareError::TokenMismatch);
        assert_eq!(disk.0, before, "not one byte written before the token passes");
    }

    #[test]
    fn a_disk_with_tables_is_refused_untouched() {
        let token = token_of(candidate());
        let mut disk = RamSectors::new();
        prepare_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token, NONCE)
            .expect("the first pass");
        let after_first = disk.0.clone();
        let error = prepare_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token, NONCE);
        assert_eq!(error, Err(PrepareError::NotBlank));
        assert_eq!(disk.0, after_first, "the refusal writes nothing");
        // Un disque qui n'est pas vierge sans être à nous non plus : une
        // entrée protectrice dans son MBR suffit au refus.
        let mut foreign = RamSectors::new();
        foreign.0[450] = 0xee;
        assert_eq!(
            prepare_disk(&mut foreign, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token, NONCE,),
            Err(PrepareError::NotBlank)
        );
    }

    #[test]
    fn protected_flags_and_shrunk_disks_are_refused() {
        let token = token_of(candidate());
        let mut disk = RamSectors::new();
        for flags in [SETUP_DISK_SYSTEM, SETUP_DISK_BOOT, SETUP_DISK_SYSTEM | SETUP_DISK_BOOT] {
            assert_eq!(
                prepare_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, flags, token, NONCE),
                Err(PrepareError::Protected)
            );
        }
        // La capacité entre dans l'empreinte : un disque qui rétrécit rend
        // le jeton faux (le plan recalculé n'est plus le même), et un
        // disque trop petit pour le plan ne passe plus la revalidation.
        let shrunk = RamSectors::SECTORS - 2048;
        assert_eq!(
            prepare_disk(&mut disk, shrunk, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token, NONCE),
            Err(PrepareError::TokenMismatch)
        );
        let tiny = 72 * 2048;
        assert_eq!(
            prepare_disk(&mut disk, tiny, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token, NONCE),
            Err(PrepareError::CapacityMismatch)
        );
    }

    #[test]
    fn guids_are_unique_per_installation_distinct_and_well_formed() {
        let token = token_of(candidate());
        assert_eq!(guid(token, NONCE, 1), guid(token, NONCE, 1));
        assert_ne!(guid(token, NONCE, 1), guid(token, NONCE, 2));
        assert_ne!(guid(token, NONCE, 1), guid(token, NONCE ^ 1, 1));
        for role in 1..=3 {
            let guid = guid(token, NONCE, role);
            assert_ne!(guid, [0; 16]);
            assert_eq!(guid[7] >> 4, 0x4, "version 4");
            assert_eq!(guid[8] >> 6, 0b10, "RFC 4122 variant");
        }
    }

    #[test]
    fn the_engine_lock_is_exclusive_and_comes_back() {
        let lock = Exclusive::default();
        assert!(lock.try_acquire());
        assert!(!lock.try_acquire(), "a second caller waits, it does not write");
        lock.release();
        assert!(lock.try_acquire(), "the lock comes back once released");
        lock.release();
    }
}
