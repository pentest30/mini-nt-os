# Listes de services de ReactOS 0.4.16

Les deux listes de services de ce dossier sont copiées telles quelles de ReactOS. `tools/syscall-gen` les lit pour
générer `abi/src/services.rs` (ADR-002, 02 §6.2) : ce sont les seules sources des numéros d'appel système de Mino.

| Fichier | Origine | SHA-256 |
|---|---|---|
| `sysfuncs.lst` | `ntoskrnl/sysfuncs.lst` | `7e90e3dc704d609abc13bc9d7ba36cea318abe8c3f4436c28739e5ac6e78bc6c` |
| `w32ksvc32.h` | `win32ss/w32ksvc32.h` | `e9eab8bc07c062524ea915b818863e1c233ab0dd62faa5348a3e7dbcd7b505ae` |

`w32k-ntstatus.lst` n'est pas copié : c'est la liste des services de `w32ksvc32.h` dont le prototype rend `NTSTATUS`,
tirée des en-têtes du même commit (un service sans handler rend alors `STATUS_NOT_IMPLEMENTED` ; les autres, qui
rendent une valeur, rendent 0 : `abi::service::Service::returns_status`). Les 738 services de `w32ksvc32.h` ont un
prototype dans l'un de ces en-têtes ; le type rendu est le mot qui précède `NTAPI`, `APIENTRY` ou `WINAPI` devant le
nom, commentaires ôtés, au premier prototype trouvé dans cet ordre :

| En-tête | SHA-256 |
|---|---|
| `win32ss/include/ntuser.h` | `147758fd4d0f11afe0ca58db3240680b8393829f8656efb711bba0b662d61b9c` |
| `sdk/include/psdk/ntgdi.h` | `9098efa6504bbfd3e323ddeea93b089d11088a48a414dcae8b78963a13b9fd04` |
| `win32ss/include/ntgdibad.h` | `e6247d156b7d1ec3cc5468f9cc5ca77f09565426ced6bf180e93eda59d506e5c` |
| `win32ss/gdi/ntgdi/intgdi.h` | `8fe6d44cae5f5c075ea2fe4b68b80486cb97342525c48e04ebd411e05dbd73a6` |

- **Dépôt** : <https://github.com/reactos/reactos>, étiquette `0.4.16`, commit
  `51bfc7037359b594876a349b46b992e363e79838`.
- **Licence** : celle de ReactOS, GNU GPL version 2 (`COPYING` de ce commit). Ces fichiers ne décrivent que l'interface
  (noms des services, nombre d'arguments, ordre) ; aucun code de ReactOS n'en est tiré.
- **Variante** : i386, comme les binaires publiés : `DBG` défini, `_WIN64` non défini. Les cinq services de
  `w32ksvc32.h` sous `#if DBG` font donc partie de la table (les suivants, de `NtGdiMakeObjectXferable` à la fin, en
  dépendent), pas celui sous `#ifdef _WIN64`. Les stubs de `ntdll`, `user32` et `gdi32` de la version publiée le
  montrent : avec `DBG` à 0, 26 stubs de `user32` appelaient le mauvais service (MonitorFromWindow tombait sur
  `NtGdiDdDDICreateAllocation`). `syscall-gen --check` (`cargo xtask lint`) vérifie ces stubs quand l'espace
  utilisateur a été téléchargé.
- Les listes `ntoskrnl` de 0.4.15 et 0.4.16 sont identiques ; 0.4.16 ajoute 55 services D3DKMT à la fin de celle de
  win32k.

Changer de version de ReactOS est un chantier explicite (ADR-002) : nouveau dossier, nouvelles valeurs dans
`tools/syscall-gen/src/main.rs`, puis `cargo xtask syscall-gen` et toute la suite de tests.
