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
use crate::fat::{BlockDevice, FatError, FatVolume};
use crate::partition::PartitionDevice;
use crate::volume::{Node, Volume};

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
    /// Les tables GPT de la préparation ne sont pas là : le formatage vient
    /// après la préparation.
    NotPrepared,
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

/// [`fatfs`] vu sur une vue bornée de partition : les LBAs relatifs au
/// volume, la même erreur.
struct VolumeSectors<'a, D: BlockDevice>(&'a mut PartitionDevice<D>);

impl<D: BlockDevice> fatfs::format::WriteSectors for VolumeSectors<'_, D> {
    type Error = FatError;

    fn write_sector(&mut self, lba: u32, sector: &[u8; 512]) -> Result<(), FatError> {
        self.0.write_sector(u64::from(lba), sector.as_slice())
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
    let plan = validated_plan(sectors, number, flags, token)?;
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

/// La revalidation partagée de la préparation et du formatage : le plan
/// recalculé sur ce que le disque est maintenant, et le jeton reverifié.
fn validated_plan(sectors: u64, number: u32, flags: u32, token: u64) -> Result<Plan, PrepareError> {
    let plan = Plan::guided(Disk { number, sectors, flags }).map_err(|error| match error {
        PlanError::Protected => PrepareError::Protected,
        PlanError::TooSmall => PrepareError::CapacityMismatch,
    })?;
    if plan.token != token {
        return Err(PrepareError::TokenMismatch);
    }
    Ok(plan)
}

/// Formate les deux volumes du plan en FAT32, après la préparation. La même
/// revalidation que la préparation (plan recalculé, jeton reverifié), puis
/// les tables GPT relues pour trouver les deux partitions — qui doivent
/// être celles du plan —, et chaque partition formatée par
/// [`fatfs::format`] sur sa vue bornée, **vérifiée par le montage du
/// lecteur FAT du noyau**. Ne copie rien.
///
/// # IRQL
/// <= DISPATCH_LEVEL ; le disque doit attendre la préemption (PIO).
pub fn format_disk<D: BlockDevice>(
    disk: &mut D,
    sectors: u64,
    number: u32,
    flags: u32,
    token: u64,
) -> Result<(fatfs::format::Geometry, fatfs::format::Geometry), PrepareError> {
    let plan = validated_plan(sectors, number, flags, token)?;
    // Les tables GPT de la préparation doivent être là, les deux copies
    // valides, et porter les deux volumes du plan.
    let reader = BlockSectors(&*disk);
    let (layout, source) = gpt::read(&reader, sectors).map_err(|_| PrepareError::NotPrepared)?;
    if source != gpt::Source::Both {
        return Err(PrepareError::NotPrepared);
    }
    let [esp, system] = [layout.partitions().first(), layout.partitions().get(1)].map(|partition| {
        partition.filter(|partition| {
            (partition.kind == gpt::EFI_SYSTEM || partition.kind == gpt::BASIC_DATA)
                && partition.last_lba >= partition.first_lba
        })
    });
    let (Some(esp), Some(system)) = (esp, system) else {
        return Err(PrepareError::NotPrepared);
    };
    if esp.kind != gpt::EFI_SYSTEM
        || system.kind != gpt::BASIC_DATA
        || esp.first_lba != plan.esp_first
        || system.first_lba != plan.system_first
    {
        return Err(PrepareError::NotPrepared);
    }
    let esp_sectors = esp.last_lba - esp.first_lba + 1;
    let system_sectors = system.last_lba - system.first_lba + 1;
    // L'ESP, puis le système : chaque volume formaté sur sa vue bornée, et
    // vérifié par le montage du lecteur FAT du noyau sur la même vue.
    let mut format_volume = |first: u64, count: u64| -> Result<fatfs::format::Geometry, PrepareError> {
        let mut view = PartitionDevice::new(&mut *disk, sectors, first, count).map_err(|_| PrepareError::Io)?;
        let geometry =
            fatfs::format::format(&mut VolumeSectors(&mut view), count as u32).map_err(|error| match error {
                fatfs::format::FormatError::InvalidSize => PrepareError::CapacityMismatch,
                fatfs::format::FormatError::Io(_) => PrepareError::Io,
            })?;
        crate::fat::FatVolume::mount(view).map_err(|_| PrepareError::Io)?;
        Ok(geometry)
    };
    let esp_geometry = format_volume(esp.first_lba, esp_sectors)?;
    let system_geometry = format_volume(system.first_lba, system_sectors)?;
    Ok((esp_geometry, system_geometry))
}

/// Formate les deux volumes du disque `number` d'après le jeton `token` de
/// l'aperçu, après la préparation. Les mêmes refus que la préparation, le
/// même verrou exclusif.
///
/// # IRQL
/// PASSIVE_LEVEL (IDENTIFY DEVICE et les E/S PIO attendent le matériel).
pub fn format(number: u32, token: u64) -> Result<(fatfs::format::Geometry, fatfs::format::Geometry), PrepareError> {
    if number == PRIMARY_MASTER {
        return Err(PrepareError::Protected);
    }
    if u32::from(SYSTEM_DISK_NUMBER.load(Ordering::Acquire)) == number {
        return Err(PrepareError::Protected);
    }
    if number != SECONDARY_MASTER {
        return Err(PrepareError::NoTarget);
    }
    if !PREPARE_LOCK.try_acquire() {
        return Err(PrepareError::Busy);
    }
    let formatted = format_locked(number, token);
    PREPARE_LOCK.release();
    formatted
}

fn format_locked(number: u32, token: u64) -> Result<(fatfs::format::Geometry, fatfs::format::Geometry), PrepareError> {
    let mut disk = AtaDisk::probe(hal::ata::AtaDrive::new(hal::ata::SECONDARY, false)).ok_or(PrepareError::NoTarget)?;
    let sectors = disk.sectors();
    format_disk(&mut disk, sectors, number, SETUP_DISK_CANDIDATE, token)
}

/// Ce qu'une copie a transféré.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CopyReport {
    pub files: u32,
    pub directories: u32,
    pub bytes: u64,
}

/// Le volume de l'ESP de démarrage : la partition EFI du disque primaire
/// quand il porte un GPT (l'image installée, son ESP est FAT32), sinon
/// `None` — l'ESP virtuelle FAT16 de QEMU ne se monte pas (le lecteur FAT
/// du noyau ne lit que du FAT32) et la copie des fichiers de boot passe
/// par l'image installée.
fn boot_esp_volume() -> Result<Option<FatVolume<alloc::boxed::Box<dyn BlockDevice>>>, PrepareError> {
    let disk = AtaDisk::probe(hal::ata::AtaDrive::new(hal::ata::PRIMARY, false)).ok_or(PrepareError::NoTarget)?;
    let sectors = disk.sectors();
    let reader = BlockSectors(&disk);
    if let Ok((layout, source)) = gpt::read(&reader, sectors) {
        if source == gpt::Source::Both {
            let esp = layout
                .partitions()
                .iter()
                .find(|partition| partition.kind == gpt::EFI_SYSTEM)
                .ok_or(PrepareError::NotPrepared)?;
            let count = esp.last_lba - esp.first_lba + 1;
            let view = PartitionDevice::new(disk, sectors, esp.first_lba, count).map_err(|_| PrepareError::Io)?;
            let device: alloc::boxed::Box<dyn BlockDevice> = alloc::boxed::Box::new(view);
            return FatVolume::mount(device).map(Some).map_err(|_| PrepareError::Io);
        }
    }
    Ok(None)
}

/// Copie un fichier de l'ESP de démarrage vers le répertoire de l'ESP
/// cible : lu par le lecteur FAT, créé et écrit par le Volume cible.
fn copy_boot_file<D: BlockDevice>(
    esp: &FatVolume<D>,
    path: &str,
    dst: &Volume,
    dst_dir: &Node,
) -> Result<(), PrepareError> {
    let mut file = esp.open(path).map_err(|_| PrepareError::Io)?;
    let mut data = alloc::vec![0u8; file.file_size as usize];
    esp.read(&mut file, &mut data).map_err(|_| PrepareError::Io)?;
    let name = path.rsplit('/').next().unwrap_or(path);
    let node = dst.create(dst_dir, name, false, 0x20).map_err(|_| PrepareError::Io)?;
    dst.write(&node, 0, &data).map_err(|_| PrepareError::Io)?;
    Ok(())
}

/// Copie récursive de l'arbre `src_path` du volume de démarrage vers le
/// répertoire `dst_dir` du volume cible. Les entrées `.` et `..` ne se
/// copient pas ; chaque fichier est relu depuis la source, créé et écrit
/// sur la cible (le Volume grandit le fichier), sa taille vérifiée à la
/// relecture de son entrée.
fn copy_dir(src_path: &str, dst: &Volume, dst_dir: &Node, report: &mut CopyReport) -> Result<(), PrepareError> {
    for entry in crate::list_fat_dir(src_path).map_err(|_| PrepareError::Io)? {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let child = alloc::format!("{src_path}/{}", entry.name);
        if entry.attr & 0x10 != 0 {
            let node = dst.create(dst_dir, &entry.name, true, u32::from(entry.attr)).map_err(|_| PrepareError::Io)?;
            report.directories += 1;
            copy_dir(&child, dst, &node, report)?;
        } else {
            let mut file = crate::open_fat_file(&child).map_err(|_| PrepareError::Io)?;
            let mut data = alloc::vec![0u8; file.file_size as usize];
            crate::read_fat_file(&mut file, &mut data).map_err(|_| PrepareError::Io)?;
            let node = dst.create(dst_dir, &entry.name, false, u32::from(entry.attr)).map_err(|_| PrepareError::Io)?;
            let written = dst.write(&node, 0, &data).map_err(|_| PrepareError::Io)?;
            // La vérification après écriture : l'entrée de la cible rend la
            // taille écrite.
            if dst.current(&written).map_err(|_| PrepareError::Io)?.size as u64 != data.len() as u64 {
                return Err(PrepareError::Io);
            }
            report.files += 1;
            report.bytes += data.len() as u64;
        }
    }
    Ok(())
}

/// Copie le système sur le disque installé : les deux fichiers de boot de
/// l'ESP de démarrage vers l'ESP cible, et l'arbre WINDOWS du volume de
/// démarrage (le ramdisk, qui porte la même arborescence) vers le volume
/// système cible. La même revalidation ; les tables GPT du disque cible
/// doivent être là (la préparation et le formatage ont tourné).
///
/// # IRQL
/// PASSIVE_LEVEL (les E/S PIO attendent le matériel).
pub fn copy_files(number: u32, token: u64) -> Result<CopyReport, PrepareError> {
    if number == PRIMARY_MASTER {
        return Err(PrepareError::Protected);
    }
    if u32::from(SYSTEM_DISK_NUMBER.load(Ordering::Acquire)) == number {
        return Err(PrepareError::Protected);
    }
    if number != SECONDARY_MASTER {
        return Err(PrepareError::NoTarget);
    }
    if !PREPARE_LOCK.try_acquire() {
        return Err(PrepareError::Busy);
    }
    let copied = copy_locked(number, token);
    PREPARE_LOCK.release();
    copied
}

fn copy_locked(number: u32, token: u64) -> Result<CopyReport, PrepareError> {
    let target =
        AtaDisk::probe(hal::ata::AtaDrive::new(hal::ata::SECONDARY, false)).ok_or(PrepareError::NoTarget)?;
    let sectors = target.sectors();
    let _plan = validated_plan(sectors, number, SETUP_DISK_CANDIDATE, token)?;
    // Les tables GPT du disque cible (la préparation les a écrites).
    let reader = BlockSectors(&target);
    let (layout, source) = gpt::read(&reader, sectors).map_err(|_| PrepareError::NotPrepared)?;
    if source != gpt::Source::Both {
        return Err(PrepareError::NotPrepared);
    }
    let esp = layout
        .partitions()
        .iter()
        .find(|partition| partition.kind == gpt::EFI_SYSTEM)
        .ok_or(PrepareError::NotPrepared)?;
    let system = layout
        .partitions()
        .iter()
        .find(|partition| partition.kind == gpt::BASIC_DATA)
        .ok_or(PrepareError::NotPrepared)?;
    // Les deux fichiers de boot vers l'ESP cible — quand l'ESP de démarrage
    // est montageable en FAT32 (le GPT de l'image installée). L'ESP
    // virtuelle FAT16 de QEMU ne se monte pas : les fichiers de boot ne se
    // copient pas dans ce cas (les scénarios QEMU testent l'arbre système).
    let boot_esp = boot_esp_volume()?;
    let esp_device = PartitionDevice::new(target.clone(), sectors, esp.first_lba, esp.last_lba - esp.first_lba + 1)
        .map_err(|_| PrepareError::Io)?;
    let esp_volume = Volume::mount(alloc::boxed::Box::new(esp_device)).map_err(|_| PrepareError::Io)?;
    let esp_root = esp_volume.root();
    match &boot_esp {
        Some(boot_esp) => {
            copy_boot_file(boot_esp, "EFI/BOOT/BOOTX64.EFI", &esp_volume, &esp_root).inspect_err(|&error| {
                log::warn!("TEMP copy: h (bootx64 {error:?})");
            })?;
            copy_boot_file(boot_esp, "kernel.elf", &esp_volume, &esp_root).inspect_err(|&error| {
                log::warn!("TEMP copy: i (kernel.elf {error:?})");
            })?;
        }
        None => log::warn!("[m4] install: copy: the boot ESP is not FAT32-mountable, boot files skipped"),
    }
    // L'arbre système : le ramdisk (qui porte l'arborescence du démarrage)
    // vers le volume système cible.
    let system_device = PartitionDevice::new(target, sectors, system.first_lba, system.last_lba - system.first_lba + 1)
        .map_err(|_| PrepareError::Io)?;
    let system_volume = Volume::mount(alloc::boxed::Box::new(system_device)).map_err(|_| PrepareError::Io)?;
    let system_root = system_volume.root();
    let mut report = CopyReport::default();
    copy_dir("", &system_volume, &system_root, &mut report)?;
    // La vérification : les tailles écrites relues à chaque fichier dans
    // copy_dir, et le lecteur du noyau a monté les deux volumes.
    Ok(report)
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

    const NONCE: u64 = 0x1234_5678_9abc_def0;

    /// Le disque de développement des scénarios : 96 Mio, en mémoire. Le
    /// trait écrit à travers `&self` (comme les ports du vrai disque) : la
    /// mutabilité intérieure du test.
    #[derive(Clone)]
    struct RamSectors(core::cell::RefCell<alloc::vec::Vec<u8>>);

    impl RamSectors {
        const SECTORS: u64 = 96 * 2048;

        fn new() -> Self {
            Self(core::cell::RefCell::new(alloc::vec![0u8; Self::SECTORS as usize * 512]))
        }

        fn sector(&self, lba: u64) -> alloc::vec::Vec<u8> {
            let at = lba as usize * 512;
            self.0.borrow()[at..at + 512].to_vec()
        }
    }

    impl BlockDevice for RamSectors {
        fn sector_size(&self) -> u32 {
            512
        }

        fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
            out.copy_from_slice(&self.sector(lba));
            Ok(())
        }

        fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
            self.0.borrow_mut()[lba as usize * 512..(lba as usize + 1) * 512].copy_from_slice(data);
            Ok(())
        }

        fn flush(&self) -> Result<(), FatError> {
            Ok(())
        }
    }

    impl gpt::ReadSectors for RamSectors {
        type Error = FatError;

        fn read_sector(&self, lba: u64, sector: &mut [u8; gpt::SECTOR_SIZE]) -> Result<(), FatError> {
            sector.copy_from_slice(&self.sector(lba));
            Ok(())
        }
    }

    impl gpt::WriteSectors for RamSectors {
        fn write_sector(&mut self, lba: u64, sector: &[u8; gpt::SECTOR_SIZE]) -> Result<(), FatError> {
            self.0.borrow_mut()[lba as usize * 512..(lba as usize + 1) * 512].copy_from_slice(sector);
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
        let after_first = disk.0.borrow().clone();
        let error = prepare_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token, NONCE);
        assert_eq!(error, Err(PrepareError::NotBlank));
        assert_eq!(*disk.0.borrow(), after_first, "the refusal writes nothing");
        // Un disque qui n'est pas vierge sans être à nous non plus : une
        // entrée protectrice dans son MBR suffit au refus.
        let mut foreign = RamSectors::new();
        foreign.0.borrow_mut()[450] = 0xee;
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

    #[test]
    fn format_writes_both_volumes_the_kernel_mounts() {
        let token = token_of(candidate());
        let mut disk = RamSectors::new();
        prepare_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token, NONCE)
            .expect("prepare");
        let (esp, system) = format_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token)
            .expect("the volumes format");
        assert_eq!(esp.total_sectors as u64, 40 * 2048, "the ESP of the plan");
        assert!(system.total_sectors as u64 >= 54 * 2048, "the system volume of the plan");
        // Le secteur de boot de l'ESP : l'OEM de Mino et la signature, les
        // deux FAT présentes, et le montage du lecteur du noyau a validé le
        // reste (fait dans format_disk).
        let mut bpb = [0u8; 512];
        disk.read_sector(2048, &mut bpb).expect("the ESP boot sector");
        assert_eq!(&bpb[3..11], b"MINO    ");
        assert_eq!(&bpb[510..512], &[0x55, 0xAA]);
        // Reformatage : idempotent, les volumes restent montables.
        format_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token)
            .expect("the second pass reformats");
        let mounted = crate::fat::FatVolume::mount(
            PartitionDevice::new(disk.clone(), RamSectors::SECTORS, 2048, 40 * 2048).expect("the ESP view"),
        );
        assert!(mounted.is_ok(), "the formatted ESP mounts");
    }

    #[test]
    fn format_without_prepare_is_refused() {
        let token = token_of(candidate());
        let mut disk = RamSectors::new();
        assert_eq!(
            format_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token),
            Err(PrepareError::NotPrepared)
        );
    }

    #[test]
    fn format_with_wrong_token_is_refused_untouched() {
        let token = token_of(candidate());
        let mut disk = RamSectors::new();
        prepare_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token, NONCE)
            .expect("prepare");
        let before = disk.0.clone();
        assert_eq!(
            format_disk(&mut disk, RamSectors::SECTORS, SECONDARY_MASTER, SETUP_DISK_CANDIDATE, token ^ 1),
            Err(PrepareError::TokenMismatch)
        );
        assert_eq!(disk.0, before, "the refusal writes nothing");
    }
}
