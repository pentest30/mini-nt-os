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

## Étape 1 : le registre en lecture

Le noyau monte désormais la ruche SYSTEM du disque de démarrage en `\REGISTRY\MACHINE\SYSTEM` (en attendant
`tools/mkhive`, celle que ReactOS a générée de ses `.inf`, `system32/config/system` de l'espace utilisateur
épinglé), avec `CurrentControlSet` vers `ControlSet001` (`Select\Current`). Ce qu'il a fallu :

- `libs/regf` : lecture des ruches en mémoire, sans copie ; un constructeur de ruches pour les tests ;
- `kernel/cm` : le type `Key` et la procédure *parse* de `\REGISTRY`, ruches montées en lecture, liens ;
- Ob : un nom relatif à une clé ouverte va à la procédure *parse* de la clé ;
- les services `NtOpenKey`, `NtQueryKey`, `NtEnumerateKey`, `NtQueryValueKey`, `NtEnumerateValueKey`
  (classes `KEY_BASIC`, `NODE`, `FULL_INFORMATION` et `KEY_VALUE_BASIC`, `FULL`, `PARTIAL_INFORMATION`), et la
  capture des `OBJECT_ATTRIBUTES`.

`smss` lit alors sa configuration : `NtOpenKey` (10 appels), `NtEnumerateValueKey` (54), `NtQueryValueKey` (18 ;
le premier rend `STATUS_INVALID_HANDLE`, juste, au handle invalide que `ntdll` passe après l'échec de son
`NtOpenKey` des options d'exécution, faute de ruche SOFTWARE). Il s'arrête ensuite :

| Service | Arguments | Ce qu'en fait `smss` | Composant |
|---|---|---|---|
| `NtDeleteValueKey` | une clé ouverte | une valeur à effacer ; échec toléré | Cm (écriture) |
| `NtCreateDirectoryObject` | `\Windows`, `\RPC Control` (de `ObjectDirectories`) | « Unable to create … object directory » ; toléré | Ob |
| `NtOpenDirectoryObject` | `\??` | « SMSS: Unable to open \?? directory », puis « Unable to initialize DosDevices configuration » : **`SmpInit` échoue** | **Ob** |

Prochaine étape : les services de répertoires d'Ob (`NtCreateDirectoryObject`, `NtOpenDirectoryObject`, sans doute
`NtCreateSymbolicLinkObject` pour les entrées de `DOS Devices`), sur les répertoires qu'Ob a déjà.

## Étape 2 : répertoires et liens d'Ob

`NtCreateDirectoryObject`, `NtOpenDirectoryObject`, `NtCreateSymbolicLinkObject`, `NtOpenSymbolicLinkObject`
(`sys::object`, sur les répertoires et liens qu'Ob a déjà ; un lien ouvert comme lien n'est pas suivi en fin de nom).
`smss` crée alors `\Windows`, `\RPC Control` et ses liens de `DOS Devices` (`NtCreateDirectoryObject` ×5, dont le
premier rend `STATUS_OBJECT_NAME_EXISTS` sur un répertoire qui existe déjà ; `NtCreateSymbolicLinkObject` ×5),
ouvre `\??`, puis s'arrête :

| Service | Arguments | Ce qu'en fait `smss` | Composant |
|---|---|---|---|
| `NtOpenProcessToken` | processus courant | `RtlAdjustPrivilege` : « Retrieving token handle failed » ; toléré | Se |
| `NtOpenFile` | `C:\WINDOWS\system32`, un répertoire | « SMSS: Unable to open a handle to the KnownDll directory », puis « Unable to initialize KnownDll configuration » : **`SmpInit` échoue** | **Io** |

Le prochain mur est donc Io : un fichier (un répertoire) ouvert par son nom, à travers `\??\C:`, un volume et un
système de fichiers.

## Étape 3 : Io, le volume système et les sections de `\KnownDlls`

Le disque RAM de démarrage tient lieu du volume système (ADR-017, en attendant les pilotes de disque) : `tools/mkfat`
écrit des sous-répertoires, et `cargo xtask` range l'espace utilisateur dans `\WINDOWS\SYSTEM32` (ntdll, tables NLS,
`smss.exe`, `CONFIG\SYSTEM`) avec les 21 KnownDLLs de la ruche épinglée (`Session Manager\KnownDLLs`, toutes en noms
8.3). Le chargeur accepte un disque RAM de 64 Mio (27 Mio avec les KnownDLLs). Ce qu'il a fallu :

- **Io** (`kernel/io`) : un volume FAT32 monté (`io::volume`, en lecture, sans noms longs), le type `Device`, dont la
  procédure *parse* ouvre un fichier ou un répertoire du volume (IopParseDevice), et le type `File`, dont la procédure
  *parse* résout un nom relatif à un répertoire ouvert (IopParseFile). Au démarrage, `\Device\Ramdisk0`, avec
  `\GLOBAL??\C:` et `\SystemRoot` (`\Device\Ramdisk0\WINDOWS`). Le noyau lit désormais ntdll, les tables NLS, la ruche
  et `smss` par Io (`\SystemRoot\System32\…`).
- **Services d'Io** : NtCreateFile (ouverture d'un fichier existant ; le volume est en lecture seule), NtOpenFile,
  NtQueryAttributesFile, NtQueryFullAttributesFile, NtQueryInformationFile (FileBasic, FileStandard, FilePosition,
  FileNetworkOpenInformation), NtQueryVolumeInformationFile (FileFsDeviceInformation, que ntdll demande pour son
  répertoire courant, `RtlSetCurrentDirectory_U`).
- **Services des sections** (Mm) : NtCreateSection (fichier d'échange, données, image d'un fichier ouvert), NtOpenSection,
  NtMapViewOfSection, NtUnmapViewOfSection.

`smss` crée alors `\KnownDlls` (le répertoire existait déjà : `OBJ_OPENIF`), y met le lien `KnownDllPath`
(`C:\WINDOWS\system32`), ouvre `C:\WINDOWS\system32` comme répertoire, puis, pour chaque KnownDLL : l'ouvre relativement
à ce répertoire, la vérifie (`LdrVerifyImageMatchesChecksum` : une section de données `SEC_COMMIT` sur le handle avec son
bit d'étiquette, une vue, FileStandardInformation, la liste des imports), et en fait une section d'image nommée et
permanente dans `\KnownDlls`. Les imports des KnownDLLs s'ajoutent à la liste ; ceux qui ne sont pas sur le disque
(`comctl32`, `shlwapi`…) sont sautés, comme sur XP pour un fichier absent. Bilan : 21 sections d'image dans `\KnownDlls`
(journal `[m4] \KnownDlls: 21 sections`), 36 NtOpenFile, 42 NtCreateSection, 21 vues projetées et retirées.

Ensuite :

| Service | Arguments | Ce qu'en fait `smss` | Composant |
|---|---|---|---|
| — | `PagingFiles` vide dans la ruche de ReactOS | « SMSS:PFILE: No paging file was requested » : pas de fichier d'échange | |
| `NtInitializeRegistry` | 0 | les ruches restantes ; échec toléré | Cm |
| `NtQuerySystemInformation` | `SystemProcessorInformation` (classe 1), 12 octets | « SMSS: Unable to query system processor information » : **`SmpInit` échoue** | **Ex** |

Le prochain mur est donc `SystemProcessorInformation` (architecture, niveau, révision et fonctions du processeur), puis,
dans la même fonction (`SmpCreateDynamicEnvironmentVariables`), l'écriture du registre : NtOpenKey en `GENERIC_WRITE`
sur `Session Manager\Environment` et NtSetValueKey (`OS`, `PROCESSOR_ARCHITECTURE`, `PROCESSOR_LEVEL`…), l'étape 4.
