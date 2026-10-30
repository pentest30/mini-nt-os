//! `KUSER_SHARED_DATA` (02 §4.1) : une page de section, projetée en lecture
//! seule en `0x7FFE0000` dans chaque processus
//! ([`AddressSpace::map_shared_data`]) ; le noyau l'écrit par son alias dans
//! le HHDM ([`kernel_alias`]), l'horloge à chaque tick.

use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use abi::ntstatus::NtStatus;
use abi::shared_data::{KUserSharedData, KUSER_SHARED_DATA_VA};

use crate::address_space::AddressSpace;
use crate::section::Section;
use crate::vad::PageProtect;
use crate::virtual_alloc::PAGE_SIZE;

/// La section de la page, laissée à vie (`Arc::into_raw`) ; nulle avant
/// [`init`].
static SECTION: AtomicPtr<Section> = AtomicPtr::new(ptr::null_mut());
/// L'alias du noyau ; nul avant [`init`].
static ALIAS: AtomicPtr<KUserSharedData> = AtomicPtr::new(ptr::null_mut());

/// Crée la page, à zéro, et rend son alias du noyau.
///
/// # Panics
/// Au second appel.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn init() -> Result<*mut KUserSharedData, NtStatus> {
    let section = Section::create_pagefile(PAGE_SIZE, PageProtect::READWRITE)?;
    let page = section.page(0)?;
    let hhdm = crate::HHDM_OFFSET.load(Ordering::Acquire);
    let alias = (hhdm + page.to_phys()) as *mut KUserSharedData;
    let raw = Arc::into_raw(section).cast_mut();
    assert!(
        SECTION.compare_exchange(ptr::null_mut(), raw, Ordering::AcqRel, Ordering::Acquire).is_ok(),
        "KUSER_SHARED_DATA set up twice"
    );
    ALIAS.store(alias, Ordering::Release);
    Ok(alias)
}

/// L'alias du noyau de la page, où il l'écrit ; `None` avant [`init`].
///
/// # IRQL
/// Tout niveau.
pub fn kernel_alias() -> Option<*mut KUserSharedData> {
    let alias = ALIAS.load(Ordering::Acquire);
    (!alias.is_null()).then_some(alias)
}

impl AddressSpace {
    /// Projette la page en lecture seule en `0x7FFE0000` ; rien avant
    /// [`init`] (tests hôte).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn map_shared_data(&self) -> Result<(), NtStatus> {
        let raw = SECTION.load(Ordering::Acquire);
        if raw.is_null() {
            return Ok(());
        }
        // SAFETY: `raw` comes from `Arc::into_raw` in `init`, never released:
        // one more strong count for this clone.
        let section = unsafe {
            Arc::increment_strong_count(raw);
            Arc::from_raw(raw)
        };
        self.map_view(&section, u64::from(KUSER_SHARED_DATA_VA), 0, PAGE_SIZE, PageProtect::READONLY)?;
        Ok(())
    }
}
