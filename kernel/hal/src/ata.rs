//! ATA en PIO (02 §8, M4) : un disque IDE, lu et écrit en PIO, sans DMA ni
//! interruption (nIEN) : chaque commande attend son disque en lisant son
//! état.
//!
//! [`AtaDrive`] désigne un disque : le canal primaire (0x1F0) ou secondaire
//! (0x170), maître ou esclave. [`AtaDrive::identify`] dit s'il y a un disque
//! ATA (et non ATAPI) et sa taille ; [`AtaDrive::read_sectors`] et
//! [`AtaDrive::write_sectors`] transfèrent jusqu'à 256 secteurs de 512 octets
//! par commande, en LBA 28 bits (128 Gio) ; [`AtaDrive::flush`] vide le cache
//! du disque (FLUSH CACHE).
//!
//! L'appelant sérialise les commandes d'un canal. Sous QEMU, le canal
//! primaire tient l'ESP ; le disque système `C:` est le maître du canal
//! secondaire.
//!
//! [`probe`] et [`read_sector`] (le maître du canal secondaire) servent
//! l'ancien chargeur (`io_manager::open_game_file`) : ne pas les étendre.
//!
//! Pas encore : LBA 48 bits, DMA, interruptions, plus d'un disque à la fois
//! sur un canal.

use x86_64::instructions::port::Port;

/// Un canal IDE : ses registres de commande, puis son registre de contrôle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    base: u16,
    control: u16,
}

pub const PRIMARY: Channel = Channel { base: 0x1F0, control: 0x3F6 };
pub const SECONDARY: Channel = Channel { base: 0x170, control: 0x376 };

/// Un disque d'un canal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtaDrive {
    channel: Channel,
    slave: bool,
}

/// Pourquoi une commande échoue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtaError {
    /// Pas de disque ATA à cette place.
    NoDevice,
    /// Le disque ne répond pas ; son état.
    Timeout(u8),
    /// Le disque signale une erreur : son état et son registre d'erreur.
    Device(u8, u8),
    /// Au-delà de 28 bits de LBA, ou plus de 256 secteurs, ou un tampon qui
    /// n'est pas fait de secteurs.
    OutOfRange,
}

const SECTOR: usize = 512;
/// Le dernier secteur qu'atteint le LBA 28 bits, plus un.
const LBA28_LIMIT: u64 = 1 << 28;

const STATUS_ERR: u8 = 0x01;
const STATUS_DRQ: u8 = 0x08;
const STATUS_DF: u8 = 0x20;
const STATUS_BSY: u8 = 0x80;

const COMMAND_READ_SECTORS: u8 = 0x20;
const COMMAND_WRITE_SECTORS: u8 = 0x30;
const COMMAND_FLUSH_CACHE: u8 = 0xE7;
const COMMAND_IDENTIFY: u8 = 0xEC;

/// Le registre de contrôle : nIEN, pas d'interruption.
const CONTROL_NIEN: u8 = 0x02;

/// Les lectures de l'état qu'on attend au plus un disque.
const SPINS: u32 = 10_000_000;

impl AtaDrive {
    /// Le disque maître (ou esclave) du canal `channel`.
    pub const fn new(channel: Channel, slave: bool) -> Self {
        Self { channel, slave }
    }

    fn outb(&self, offset: u16, value: u8) {
        // SAFETY: a register of this IDE channel, which only this driver
        // programs; the caller serialises the commands of a channel.
        unsafe { Port::<u8>::new(self.channel.base + offset).write(value) }
    }

    fn inb(&self, offset: u16) -> u8 {
        // SAFETY: as in `outb`; reading a register has no other effect than
        // the ones ATA gives it (the status read acknowledges an interrupt,
        // and interrupts are off).
        unsafe { Port::<u8>::new(self.channel.base + offset).read() }
    }

    /// L'état, sans effet de bord (registre d'état alternatif).
    fn alternate_status(&self) -> u8 {
        // SAFETY: as in `outb`.
        unsafe { Port::<u8>::new(self.channel.control).read() }
    }

    /// Choisit ce disque, avec les bits 24 à 27 du LBA, et attend 400 ns.
    fn select(&self, lba_high: u8) {
        self.outb(6, 0xE0 | (u8::from(self.slave) << 4) | (lba_high & 0x0F));
        for _ in 0..4 {
            self.alternate_status();
        }
    }

    /// Attend que le disque ne soit plus occupé ; rend son état.
    fn wait_ready(&self) -> Result<u8, AtaError> {
        for _ in 0..SPINS {
            let status = self.alternate_status();
            if status & STATUS_BSY == 0 {
                if status & (STATUS_ERR | STATUS_DF) != 0 {
                    return Err(AtaError::Device(status, self.inb(1)));
                }
                return Ok(status);
            }
        }
        Err(AtaError::Timeout(self.alternate_status()))
    }

    /// Attend que le disque demande des données (DRQ).
    fn wait_data(&self) -> Result<(), AtaError> {
        let status = self.wait_ready()?;
        if status & STATUS_DRQ == 0 {
            return Err(AtaError::Device(status, self.inb(1)));
        }
        Ok(())
    }

    /// Lance la commande `command` sur `count` secteurs depuis `lba`.
    fn command(&self, command: u8, lba: u64, count: usize) -> Result<(), AtaError> {
        if count == 0 || count > 256 || lba.checked_add(count as u64).is_none_or(|end| end > LBA28_LIMIT) {
            return Err(AtaError::OutOfRange);
        }
        // SAFETY: as in `outb`: the control register of this channel.
        unsafe { Port::<u8>::new(self.channel.control).write(CONTROL_NIEN) };
        self.select((lba >> 24) as u8);
        self.wait_ready()?;
        self.outb(2, count as u8); // 256 is written as 0
        self.outb(3, lba as u8);
        self.outb(4, (lba >> 8) as u8);
        self.outb(5, (lba >> 16) as u8);
        self.outb(7, command);
        Ok(())
    }

    /// IDENTIFY DEVICE : le nombre de secteurs du disque ; `NoDevice` sans
    /// disque ATA à cette place (bus flottant, ou disque ATAPI).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (attente active).
    pub fn identify(&self) -> Result<u64, AtaError> {
        // SAFETY: as in `outb`: the control register of this channel.
        unsafe { Port::<u8>::new(self.channel.control).write(CONTROL_NIEN) };
        self.select(0);
        if self.alternate_status() == 0xFF {
            return Err(AtaError::NoDevice); // floating bus
        }
        for register in 2..=5 {
            self.outb(register, 0);
        }
        self.outb(7, COMMAND_IDENTIFY);
        if self.inb(7) == 0 {
            return Err(AtaError::NoDevice);
        }
        let status = match self.wait_ready() {
            Ok(status) => status,
            // ATAPI aborts IDENTIFY DEVICE, and says so in LBA mid and high.
            Err(AtaError::Device(..)) => return Err(AtaError::NoDevice),
            Err(error) => return Err(error),
        };
        if self.inb(4) != 0 || self.inb(5) != 0 || status & STATUS_DRQ == 0 {
            return Err(AtaError::NoDevice);
        }
        let mut words = [0u16; 256];
        // The data register of this channel.
        let mut data = Port::<u16>::new(self.channel.base);
        for word in &mut words {
            // SAFETY: the drive offers the 256 words of its identity (DRQ).
            *word = unsafe { data.read() };
        }
        Ok(identified_sectors(&words))
    }

    /// Lit `out.len() / 512` secteurs (256 au plus) depuis `lba`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (attente active).
    pub fn read_sectors(&self, lba: u64, out: &mut [u8]) -> Result<(), AtaError> {
        if out.is_empty() || !out.len().is_multiple_of(SECTOR) {
            return Err(AtaError::OutOfRange);
        }
        self.command(COMMAND_READ_SECTORS, lba, out.len() / SECTOR)?;
        // The data register of this channel.
        let mut data = Port::<u16>::new(self.channel.base);
        for sector in out.chunks_exact_mut(SECTOR) {
            self.wait_data()?;
            for pair in sector.chunks_exact_mut(2) {
                // SAFETY: the drive offers a sector's words (DRQ).
                pair.copy_from_slice(&unsafe { data.read() }.to_le_bytes());
            }
        }
        Ok(())
    }

    /// Écrit les `data.len() / 512` secteurs de `data` (256 au plus) depuis
    /// `lba`. Ils peuvent rester dans le cache du disque jusqu'à [`flush`].
    ///
    /// [`flush`]: Self::flush
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (attente active).
    pub fn write_sectors(&self, lba: u64, data: &[u8]) -> Result<(), AtaError> {
        if data.is_empty() || !data.len().is_multiple_of(SECTOR) {
            return Err(AtaError::OutOfRange);
        }
        self.command(COMMAND_WRITE_SECTORS, lba, data.len() / SECTOR)?;
        // The data register of this channel.
        let mut port = Port::<u16>::new(self.channel.base);
        for sector in data.chunks_exact(SECTOR) {
            self.wait_data()?;
            for pair in sector.chunks_exact(2) {
                // SAFETY: the drive takes a sector's words (DRQ).
                unsafe { port.write(u16::from_le_bytes([pair[0], pair[1]])) };
            }
        }
        self.wait_ready().map(drop)
    }

    /// FLUSH CACHE : ce qui est écrit atteint le support.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (attente active).
    pub fn flush(&self) -> Result<(), AtaError> {
        // SAFETY: as in `outb`: the control register of this channel.
        unsafe { Port::<u8>::new(self.channel.control).write(CONTROL_NIEN) };
        self.select(0);
        self.wait_ready()?;
        self.outb(7, COMMAND_FLUSH_CACHE);
        self.wait_ready().map(drop)
    }
}

/// Le nombre de secteurs que dit l'identité `words` : les mots 100 à 103
/// pour un disque LBA 48 bits (mot 83, bit 10), sinon les mots 60 et 61.
pub fn identified_sectors(words: &[u16; 256]) -> u64 {
    if words[83] & (1 << 10) != 0 {
        (0..4).map(|i| u64::from(words[100 + i]) << (16 * i)).sum()
    } else {
        u64::from(words[60]) | u64::from(words[61]) << 16
    }
}

/// Le maître du canal secondaire, pour l'ancien chargeur.
const LEGACY: AtaDrive = AtaDrive::new(SECONDARY, false);

/// Un disque est au maître du canal secondaire (l'ancien chargeur).
pub fn probe() -> bool {
    LEGACY.identify().is_ok()
}

/// Lit un secteur du maître du canal secondaire (l'ancien chargeur) ;
/// `Err(état)` en cas d'erreur.
///
/// # IRQL
/// <= DISPATCH_LEVEL (attente active).
pub fn read_sector(lba: u32, buf: &mut [u8]) -> Result<(), u8> {
    if buf.len() != SECTOR {
        return Err(0xFF);
    }
    LEGACY.read_sectors(u64::from(lba), buf).map_err(|error| match error {
        AtaError::Timeout(status) | AtaError::Device(status, _) => status,
        AtaError::NoDevice | AtaError::OutOfRange => 0xFF,
    })
}

/// Redémarre la machine par le contrôleur du clavier (impulsion sur la ligne
/// RESET) ; sous QEMU avec `-no-reboot`, QEMU s'arrête.
///
/// # IRQL
/// Tout niveau ; ne revient pas.
pub fn reset() -> ! {
    // SAFETY: the keyboard controller's command port; pulsing the reset line
    // is the intent, nothing runs after it.
    unsafe {
        let mut status = Port::<u8>::new(0x64);
        for _ in 0..SPINS {
            if status.read() & 0x02 == 0 {
                break;
            }
        }
        Port::<u8>::new(0x64).write(0xFE);
    }
    loop {
        x86_64::instructions::interrupts::disable();
        x86_64::instructions::hlt();
    }
}

#[cfg(test)]
mod tests {
    use super::identified_sectors;

    #[test]
    fn the_identity_gives_the_size() {
        let mut words = [0u16; 256];
        words[60] = 0x1000;
        words[61] = 0x0002;
        assert_eq!(identified_sectors(&words), 0x0002_1000, "LBA 28");
        words[83] = 1 << 10;
        words[100] = 0x5678;
        words[101] = 0x1234;
        words[102] = 0x0001;
        assert_eq!(identified_sectors(&words), 0x0001_1234_5678, "LBA 48");
    }
}
