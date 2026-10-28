# Ghost Recon (2001) — notes de compatibilité

Jeu de référence du jalon M8 ([05 — Feuille de route](../05-feuille-de-route.md#m8--multimédia-et-jeux)).
Ce fichier conserve ce que l'ancienne architecture (Win32 dans le noyau, commit `6d3e235`) a appris sur le jeu,
comme le demande l'audit ([04 §5](../04-audit-reutilisation.md#5-la-connaissance-à-conserver-sans-le-code)).
Le code correspondant disparaîtra, pas ces informations.

## Version visée

- **Version GOG 1.4, sans DRM, uniquement.** La version disque utilise SafeDisc v2, hors périmètre ([01 — Vision](../01-vision.md#ce-qui-nest-pas-dans-le-périmètre)).
- Lancement avec `-nointro` pour sauter les vidéos d'introduction. Sous l'ancienne architecture, elles plantaient faute de `ddraw.dll`.
  À revérifier quand `ddraw` (Wine, via ReactOS) sera disponible (ADR-006).
- Un `dbghelp.dll` présent dans le dossier du jeu entre en conflit : le renommer en `dbghelp.old.dll`.

## Ce que le jeu attend du système

| Point | Attente | Composant concerné |
|---|---|---|
| Version de Windows | XP 5.1.2600 (ADR-003) | PEB, `KUSER_SHARED_DATA`, registre |
| `QueryPerformanceFrequency` | Certains moteurs de l'époque attendent `1193182` (fréquence du PIT) | Ke (horloges), `NtQueryPerformanceCounter` |
| `timeBeginPeriod(1)` | Résolution réelle de 1 ms | Ke (timers), `NtSetTimerResolution` |
| `CreateMutexA("DirectDrawDeviceHandle")` | Mutant nommé dans `\BaseNamedObjects\` | Ob (espace de noms), Ex (mutants) |

### Clés de registre lues

```
HKLM\Software\Microsoft\DirectX\Version                              = "4.08.00.0400"
HKLM\Software\Microsoft\DirectX\InstalledVersion                     = "4.08.00.0400"
HKLM\Software\Microsoft\Windows NT\CurrentVersion\CurrentVersion     = "5.1"
HKLM\Software\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber = "2600"
```

Elles doivent figurer dans les ruches générées par `mkhive` (ADR-012).

## Ce qu'a montré l'ancienne architecture

Observé entre les commits `bc5bdd4` et `6d3e235`, avec des stubs Win32 dans le noyau.
Ces observations décrivent le comportement du jeu, pas celui de Mino.

- **Démarrage du CRT** (CRT statique du jeu) : `_heap_init` → `_mtinit` → `_ioinit` → `GetCommandLineA` → `_setenvp` →
  `_setargv` → `GetCPInfo` → `GetModuleFileNameA` → `HeapReAlloc` → `_cinit` → `_initterm`.
- `_setenvp` exige un bloc d'environnement valide, terminé par deux NUL : `GetEnvironmentStringsA` ne doit pas renvoyer `NULL`.
- Les pages commitées doivent être remplies de zéros, sinon la `.bss` hérite de données périmées.
- `_initterm` exécute **4 constructeurs C++ globaux** (`0x6F2ED9`, `0x6F66DE`, `0x702E73`, `0x6FAEC9`), puis `WinMain` est atteint.
- Environ 200 appels avant le plantage, dont ~162 opérations sur des sections critiques et ~11 `HeapAlloc` : de vraies sections critiques sont nécessaires (M1, M5).
- **Dernier blocage observé** : appel via une vtable `NULL` (`RIP=0`) depuis un objet global. Hypothèse : un `CoCreateInstance` qui échoue.
  Avec l'architecture cible, c'est `ole32` (ReactOS) qui répond (ADR-019).

## À compléter

- Les autres quirks contenus dans les handlers `win32_*` de `kernel/src/syscall.rs`, avant leur suppression.
- La liste des imports observés (`docs/compat/imports-observes.md`) et des méthodes D3D8 appelées (`docs/compat/d3d8-appels.md`), voir [04 §5](../04-audit-reutilisation.md#5-la-connaissance-à-conserver-sans-le-code).
