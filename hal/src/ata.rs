//! ATA PIO disk driver — reads sectors from IDE channel 1 (ports 0x170-0x177).
//!
//! Channel 0 (0x1F0) is used by QEMU for the ESP boot disk.
//! Channel 1 (0x170) is for the game data disk.
//!
//! Uses 28-bit LBA PIO mode — supports up to 128 GiB, plenty for game data.
//! No DMA, no IRQ — synchronous polled reads only.
//!
//! # IRQL: PASSIVE_LEVEL

use x86_64::instructions::port::Port;

const ATA1_DATA:    u16 = 0x170;
const ATA1_ERROR:   u16 = 0x171;
const ATA1_SECT_CT: u16 = 0x172;
const ATA1_LBA_LO:  u16 = 0x173;
const ATA1_LBA_MID: u16 = 0x174;
const ATA1_LBA_HI:  u16 = 0x175;
const ATA1_DRIVE:   u16 = 0x176;
const ATA1_STATUS:  u16 = 0x177;
const ATA1_CMD:     u16 = 0x177;

const ATA_CMD_READ: u8 = 0x20;
const ATA_SR_BSY:   u8 = 0x80;
const ATA_SR_DRQ:   u8 = 0x08;
const ATA_SR_ERR:   u8 = 0x01;

/// Check if an ATA drive is present on channel 1, master.
pub fn probe() -> bool {
    unsafe {
        // Select drive 0 (master) on channel 1
        Port::<u8>::new(ATA1_DRIVE).write(0xA0);
        // Small delay (read status 4 times)
        for _ in 0..4 { let _ = Port::<u8>::new(ATA1_STATUS).read(); }
        let status = Port::<u8>::new(ATA1_STATUS).read();
        // 0xFF = floating bus (no drive), 0x00 = also no drive
        status != 0xFF && status != 0x00
    }
}

/// Read a single 512-byte sector from channel 1, master drive.
///
/// `lba` is the 28-bit Logical Block Address.
/// `buf` must be exactly 512 bytes.
///
/// Returns `Ok(())` on success, `Err(status)` on error.
///
/// # IRQL: PASSIVE_LEVEL (spins waiting for BSY/DRQ).
pub fn read_sector(lba: u32, buf: &mut [u8]) -> Result<(), u8> {
    if buf.len() != 512 { return Err(0xFF); }

    unsafe {
        let mut drive_port  = Port::<u8>::new(ATA1_DRIVE);
        let mut sect_port   = Port::<u8>::new(ATA1_SECT_CT);
        let mut lba_lo_port = Port::<u8>::new(ATA1_LBA_LO);
        let mut lba_mi_port = Port::<u8>::new(ATA1_LBA_MID);
        let mut lba_hi_port = Port::<u8>::new(ATA1_LBA_HI);
        let mut cmd_port    = Port::<u8>::new(ATA1_CMD);
        let mut status_port = Port::<u8>::new(ATA1_STATUS);
        let mut data_port   = Port::<u16>::new(ATA1_DATA);

        // Select master drive + LBA bits 24-27
        drive_port.write(0xE0 | ((lba >> 24) & 0x0F) as u8);

        // Sector count = 1
        sect_port.write(1);

        // LBA address
        lba_lo_port.write(lba as u8);
        lba_mi_port.write((lba >> 8) as u8);
        lba_hi_port.write((lba >> 16) as u8);

        // Send READ SECTORS command
        cmd_port.write(ATA_CMD_READ);

        // Wait for BSY to clear
        let mut timeout = 1_000_000u32;
        loop {
            let s = status_port.read();
            if s & ATA_SR_BSY == 0 { break; }
            timeout -= 1;
            if timeout == 0 { return Err(s); }
        }

        // Check for errors
        let status = status_port.read();
        if status & ATA_SR_ERR != 0 { return Err(status); }
        if status & ATA_SR_DRQ == 0 { return Err(status); }

        // Read 256 words (512 bytes)
        for i in 0..256 {
            let word = data_port.read();
            buf[i * 2]     = word as u8;
            buf[i * 2 + 1] = (word >> 8) as u8;
        }
    }

    Ok(())
}
