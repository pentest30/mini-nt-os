# M4 : le `smss.exe` de ReactOS sous la sonde

Observations de la découverte qui ouvre le M4 ([05](../05-feuille-de-route.md#m4--es-registre-systèmes-de-fichiers)) :
ce que fait le `smss.exe` de ReactOS 0.4.16 (i386, version de publication, image native de 135 Kio qui n'importe
que `ntdll`, 101 fonctions) quand le noyau le lance comme premier processus. Scénario `smss` (feature du noyau
`test-smss`, `cargo xtask fetch-userland` d'abord) ; à mettre à jour à chaque étape du M4.

## La sonde

`ntoskrnl::userland::run_smss_probe`, après les programmes du spike S1 : `SMSS.EXE` du disque de démarrage, lancé
par `run_native` comme le premier processus d'XP (paramètres : image et ligne de commande
`\SystemRoot\System32\smss.exe`, répertoire courant et chemin des DLL dans `C:\WINDOWS\system32`, environnement
`Path` et `SystemRoot`), terminé au bout de 10 s s'il ne s'arrête pas avant. Le journal porte le préfixe `[m4]`.

Deux ajouts au noyau pour la sonde :

- **`DbgPrompt`** (`int 2Dh`, `BREAKPOINT_PROMPT`) : `smss` est compilé avec ses assertions ; après un échec,
  `RtlAssert` demande au débogueur quoi faire, et redemande sans fin sans réponse (plus de 6 000 lignes de journal en
  10 s). Faute de débogueur, le noyau écrit la question et répond `i` (Ignore), et le journal le dit
  (`DbgPrompt: no debugger, answered "i"`). Les assertions restent visibles.
- **`NtQueryVirtualMemory`** (`MemoryBasicInformation`, sur `mm::virtual_alloc::query`) : sans lui,
  `RtlCreateEnvironment` échoue et `smss` s'arrête avant le registre (« Unable to allocate default environment »).

## Où `smss` s'arrête

Après l'initialisation de `ntdll` (les mêmes appels que les programmes de S1, `compat/s1-ntdll.md`), dans l'ordre :

| Service | Arguments | Ce qu'en fait `smss` | Composant |
|---|---|---|---|
| `NtSetInformationThread` | thread courant, classe 0x12 (`ThreadBreakOnTermination`), 4 octets | `RtlSetThreadIsCritical` ; assertion (`smss.c:472`), ignorée | Ps |
| — | | « RtlCreateTagHeap is UNIMPLEMENTED » : un manque de `ntdll`, sans effet | |
| `NtCreatePort` | `\SmApiPort`, messages de 0x130 octets | son port d'API ; assertion (`sminit.c:2532`), ignorée | Lpc (M5) |
| `NtWriteVirtualMemory` | soi-même, 4 octets | `RtlCreateUserThread` : le paramètre sur la pile | Mm |
| `NtCreateThread` | soi-même, contexte et `INITIAL_TEB` | les threads de son port d'API ; assertions (`sminit.c:2546`, `2557`), ignorées | Ps |
| `NtCreateEvent` | `\Device\VolumesSafeForWriteAccess`, notification | « Unable to create … event » ; assertion, ignorée | Ex |
| `NtQueryVirtualMemory` | | l'environnement par défaut ; **fait** | Mm |
| `NtOpenKey` (dans `RtlQueryRegistryValues`) | `Session Manager` | « SMSS: RtlQueryRegistryValues failed » : **`SmpInit` échoue** | **Cm** |
| `NtOpenThreadToken` | | « Retrieving token handle failed » | Se |
| `NtRaiseHardError` | `STATUS_SYSTEM_PROCESS_TERMINATED` (`0xC000021A`), 4 paramètres | l'erreur fatale du sous-système ; puis fin | Ex |

Statut de sortie : `STATUS_NOT_IMPLEMENTED`, le statut de `SmpInit`. Sur XP, la fin de `smss` arrête le système
(STOP 0xC000021A) ; Mino ne l'émule pas encore (`ThreadBreakOnTermination` n'existe pas).

## Ce qu'il en tire pour le M4

- **Le registre est le premier mur**, avant Io et les disques : `smss` lit `Session Manager` dès `SmpInit`. Une ruche
  `SYSTEM` générée par `tools/mkhive` et lue en mémoire (le chargeur la met là, comme le prévoit l'ADR-017) suffit à
  passer cette étape ; la persistance (critère 2 du M4) viendra avec l'écriture sur disque.
- **Des objets d'Ex et des services de Ps** que la feuille de route place plus tard sont demandés tout de suite :
  événements nommés (`NtCreateEvent`), threads créés depuis le mode utilisateur (`NtCreateThread`,
  `NtWriteVirtualMemory`), thread critique (`ThreadBreakOnTermination`).
- **LPC** (`NtCreatePort`), prévu au M5 : sans lui, `smss` n'a pas de port d'API et ne pourra pas parler à `csrss`.
  Sa création échoue sans arrêter `smss`, qui continue jusqu'au registre.
- Les fichiers (Io, FAT32 en écriture) viendront ensuite : `\KnownDlls`, `autochk`, le fichier d'échange, puis
  l'ouverture des images de `csrss` et `winlogon`.
