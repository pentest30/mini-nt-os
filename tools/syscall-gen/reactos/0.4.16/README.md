# Listes de services de ReactOS 0.4.16

Les deux fichiers de ce dossier sont copiés tels quels de ReactOS. `tools/syscall-gen` les lit pour générer
`abi/src/services.rs` (ADR-002, 02 §6.2) : ce sont les seules sources des numéros d'appel système de Mino.

| Fichier | Origine | SHA-256 |
|---|---|---|
| `sysfuncs.lst` | `ntoskrnl/sysfuncs.lst` | `7e90e3dc704d609abc13bc9d7ba36cea318abe8c3f4436c28739e5ac6e78bc6c` |
| `w32ksvc32.h` | `win32ss/w32ksvc32.h` | `e9eab8bc07c062524ea915b818863e1c233ab0dd62faa5348a3e7dbcd7b505ae` |

- **Dépôt** : <https://github.com/reactos/reactos>, étiquette `0.4.16`, commit
  `51bfc7037359b594876a349b46b992e363e79838`.
- **Licence** : celle de ReactOS, GNU GPL version 2 (`COPYING` de ce commit). Ces fichiers ne décrivent que l'interface
  (noms des services, nombre d'arguments, ordre) ; aucun code de ReactOS n'en est tiré.
- **Variante** : i386, version de publication (`DBG` à 0, `_WIN64` non défini). Les services de `w32ksvc32.h` sous
  `#if DBG` ou `#ifdef _WIN64` n'en font donc pas partie, et les suivants prennent leurs numéros. Le spike S3 le
  vérifiera sur les stubs de `user32`.
- Les listes `ntoskrnl` de 0.4.15 et 0.4.16 sont identiques ; 0.4.16 ajoute 55 services D3DKMT à la fin de celle de
  win32k.

Changer de version de ReactOS est un chantier explicite (ADR-002) : nouveau dossier, nouvelles valeurs dans
`tools/syscall-gen/src/main.rs`, puis `cargo xtask syscall-gen` et toute la suite de tests.
