# M5 : `smss` lance `csrss.exe`

Observations du début du M5 ([05](../05-feuille-de-route.md#m5--mode-console-puis-spike-s2)) : ce que fait le
`smss.exe` de ReactOS 0.4.16 quand `csrss.exe` et ses DLL serveur sont sur le disque, puis ce que fait `csrss.exe`.
La sonde est celle du M4 ([`m4-smss.md`](m4-smss.md)), scénario `smss` ; à mettre à jour à chaque étape du M5.
Elle journalise aussi chaque processus que `smss` a créé (`ps::child_processes`), relevé avant la fin de `smss`
tant que ses handles le tiennent, attendu 2 s puis terminé : « [m4] SMSS.EXE created csrss.exe (PID 20): exit
status 0xc0000002 ». Les appels système comptés sont ceux de `smss` et de ses processus.

## Étape 1 : `csrss.exe` sur le disque

`cargo xtask` met sur le disque de démarrage, dans `WINDOWS\SYSTEM32`, le sous-système Win32 de ReactOS :
`csrss.exe` (image native, base `0x400000`, n'importe que `ntdll` et `csrsrv`), `csrsrv.dll` (native, `ntdll`
seule), `basesrv.dll` (`ntdll`, `csrsrv`) et `winsrv.dll` (`basesrv`, `csrsrv`, `gdi32`, `kernel32`, `ntdll`,
`user32` ; les trois dernières sont des KnownDLLs, déjà sur le disque). La valeur `Windows` de
`Session Manager\SubSystems` donne sa ligne de commande :

```text
C:\WINDOWS\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On
SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3
ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16
```

`RtlDosSearchPath_U` trouve désormais l'image (« Unable to find subsystem » disparaît). `SmpLoadSubSystem` crée
d'abord l'événement que `csrss` signalera une fois connecté au port d'API de `smss` :

| Service | Arguments | Ce qu'en fait `smss` | Composant |
|---|---|---|---|
| `NtCreateEvent` | sans nom, notification, non signalé | `STATUS_NO_MEMORY` : « Subsystem execute failed », **`SmpInit` échoue** | **Ex** |

Ce qui suit, d'après les sources de `smss` et de `ntdll` (`SmpLoadSubSystem`, `SmpExecuteImage`,
`RtlCreateUserProcess`, `RtlCreateUserThread`) :

1. `RtlCreateUserProcess` : NtOpenFile sur l'image, NtCreateSection (`SEC_IMAGE`), **NtCreateProcess** (parent
   `smss`, sans héritage de handles), **NtQuerySection** (`SectionImageInformation`),
   **NtQueryInformationProcess** (`ProcessBasicInformation`, pour l'adresse du PEB).
2. `RtlpInitEnvironment`, dans le nouveau processus : NtAllocateVirtualMemory du premier Mio à partir de l'adresse 4
   (`RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB`, que `smss` demande pour un sous-système ; un échec fait échouer la
   création), puis de l'environnement et des paramètres, **NtWriteVirtualMemory** de chacun et du pointeur
   `Peb->ProcessParameters`.
3. `RtlCreateUserThread` : la pile (NtAllocateVirtualMemory, NtProtectVirtualMemory pour la page de garde), le
   paramètre (le PEB) sur la pile par NtWriteVirtualMemory, puis **NtCreateThread**, suspendu.
4. `SmpSetProcessMuSessionId` : **NtSetInformationProcess** (`ProcessSessionInformation`), dont le statut est celui
   de `SmpExecuteImage`.
5. **NtResumeThread**, puis NtWaitForSingleObject sur l'événement, jusqu'à ce que `csrss` se connecte à
   `\SmApiPort` (LPC).

## Étape 2 : les événements et les attentes

Le crate `ex` (02 §5.10) donne le type `Event` : un KEVENT de Ke dans un objet d'Ob, de notification ou de
synchronisation. Services : NtCreateEvent (attributs facultatifs : un objet sans nom), NtOpenEvent, NtSetEvent,
NtResetEvent, NtClearEvent, NtPulseEvent, NtQueryEvent (`EventBasicInformation`) ; et les attentes,
NtWaitForSingleObject et NtWaitForMultipleObjects (`WaitAny`, `WaitAll`), sur un processus, un thread ou un
événement (un fichier, qu'XP attend par son événement, rend `STATUS_OBJECT_TYPE_MISMATCH` jusqu'aux E/S
asynchrones). Test : `event_service_self_test` (un programme du mode utilisateur, dont une attente sans échéance que
le noyau termine en signalant l'événement par son nom).

`smss` crée alors `\Device\VolumesSafeForWriteAccess` (l'assertion du M4 disparaît) et l'événement du sous-système,
puis :

| Service | Arguments | Ce qu'en fait `smss` | Composant |
|---|---|---|---|
| `NtCreateProcess` | `PROCESS_ALL_ACCESS`, parent `NtCurrentProcess()`, sans héritage, la section de `csrss.exe` | « Failed load of \??\C:\WINDOWS\system32\csrss.exe » ; NtSetEvent sur l'événement du sous-système (le chemin d'échec), **`SmpInit` échoue** | **Ps** |

## Étape 3 : un processus créé depuis le mode utilisateur

Ce que `RtlCreateUserProcess` demande au noyau, fait et testé par des programmes du mode utilisateur
(`process_memory_self_test`, `suspend_self_test`, `process_creation_self_test`) :

- **Mm** : une plage désignée peut commencer sous 64 Kio, jusqu'à la page 0, comme sous XP (le premier Mio réservé
  depuis l'adresse 4) ; NtReadVirtualMemory et NtWriteVirtualMemory, page par page du processus visé
  (`STATUS_PARTIAL_COPY` et le compte de ce qui précède quand une page échoue) ; NtQuerySection
  (`SectionImageInformation` à la disposition d'XP SP2, `SectionBasicInformation`). Les tables NLS se projettent
  désormais le plus haut possible, sous `KUSER_SHARED_DATA` (en `0x7FFB0000`, comme XP) : en bas, elles occupaient le
  premier Mio et la réservation de `RtlpInitEnvironment` échouait (`STATUS_CONFLICTING_ADDRESSES`).
  NtMapViewOfSection honore `MEM_TOP_DOWN`.
- **Ke et Ps** : un thread suspendu (KeSuspendThread : un APC noyau qui attend l'événement de la reprise), créé
  suspendu sans exécuter une instruction du mode utilisateur (Ke le crée sans le rendre prêt, et le trampoline de
  `hal::ring3` livre ses APC noyau avant le mode utilisateur, où ils attendaient la première interruption) ; un
  thread démarré d'un contexte du mode utilisateur, assaini.
- **Services** : NtCreateProcess(Ex), NtCreateThread, NtSuspendThread, NtResumeThread, NtTerminateThread,
  NtQueryInformationProcess (`ProcessBasicInformation`, `ProcessSessionInformation`), NtSetInformationProcess
  (`ProcessSessionInformation`). `ProcessExecuteFlags` reste à faire : le `ntdll` de ReactOS y passe 0 sous `OptIn`
  (« LDR: Could not set process execute flags 0x0 »), que la règle du M3 (exactement `DISABLE` ou `ENABLE`) refuse ;
  à trancher avec l'ADR-020.

`smss` crée alors `csrss.exe` (NtCreateProcess, NtQuerySection, ProcessBasicInformation, le premier Mio, ses
paramètres et sa pile par NtWriteVirtualMemory, son thread suspendu, sa session), le reprend (NtResumeThread) et
attend son événement. Ses deux threads d'API (`SmpApiLoop`) tournent désormais : sans port (NtCreatePort échoue),
NtReplyWaitReceivePort rend `STATUS_NOT_IMPLEMENTED` et la boucle recommence sans fin (des millions d'appels en
10 s). `csrss` démarre sous `ntdll` (son TEB en `0x7FFDE000`) :

| Service | Arguments | Ce qu'en fait `csrss` (son chargeur) | Composant |
|---|---|---|---|
| `NtQueryInformationProcess` | `ProcessCookie` | « Failed to receive the process cookie » ; toléré | Ps |
| `NtQuerySymbolicLinkObject` | `\KnownDlls\KnownDllPath` | « LDR: Process initialization failure for \??\C:\WINDOWS\system32\csrss.exe » (`STATUS_APP_INIT_FAILURE` par NtRaiseHardError), **`csrss` se termine** | **Ob** |

`smss`, qui attend toujours, est terminé par la sonde au bout de 10 s.

## Étape 4 : le chargeur de `csrss` va au bout

NtQuerySymbolicLinkObject (Ob, `SYMBOLIC_LINK_QUERY`) : la cible du lien dans le UNICODE_STRING de l'appelant ;
comme ReactOS, avec la longueur rendue demandée, la cible est copiée avec son zéro final et cette taille est
rendue, même quand le tampon est trop petit (`STATUS_BUFFER_TOO_SMALL`). Test : `object_directory_self_test`.

Le chargeur de `csrss` lit alors `\KnownDlls\KnownDllPath`, projette `csrsrv.dll` (absente de `\KnownDlls` :
NtOpenSection rend `STATUS_OBJECT_NAME_NOT_FOUND`, puis NtOpenFile, NtCreateSection, NtMapViewOfSection), écrit
« Failed to create the implicit act ctx » (pas de manifeste, toléré), et entre dans `main` :

| Service | Arguments | Ce qu'en fait `csrss` | Composant |
|---|---|---|---|
| `NtSetInformationProcess` | `ProcessBasePriority` (5) | sa priorité ; échec ignoré | Ps |
| `NtSetInformationProcess` | `ProcessUserModeIOPL` (0x10) | l'IOPL du mode utilisateur, pour les registres VGA : « CSRSS: Could not raise IOPL », NtRaiseHardError(`STATUS_IO_PRIVILEGE_FAILED`) ; toléré | Ps (le noyau garde IOPL 0, `hal::ring3`) |
| `NtOpenProcessToken` | soi-même, `TOKEN_QUERY` | `CsrSetProcessSecurity` (le jeton, `TokenUser`, puis NtSetSecurityObject sur le processus) : « CsrSetProcessSecurity failed », « CSRSS: Unable to initialize server », **`csrss` se termine** | **Se** |

Le prochain mur de `csrss` est donc Se (02 §5.8, ADR-011) : un jeton par processus (NtOpenProcessToken,
NtQueryInformationToken), les descripteurs de sécurité des objets (NtSetSecurityObject).

## Étape 5 : le port d'API de `smss` (Lpc)

Le crate `lpc` (02 §5.9) commence par ce que `smss` demande avant tout client : le type `Port`, un port de
connexion nommé dans l'espace de noms, et sa file de messages, que compte un sémaphore de Ke. Services :
NtCreatePort (`STATUS_INVALID_PARAMETER_3` ou `_4` au-delà de `PORT_MAXIMUM_MESSAGE_LENGTH`, 0x148 octets) et
NtReplyWaitReceivePort, qui attend le prochain message et le copie, en-tête `PORT_MESSAGE` (abi) puis données. Le
noyau peut envoyer un datagramme à un port (`Port::request`, LpcRequestPort). Test : `port_self_test` (une attente
qu'un datagramme du noyau termine). Pas encore : la connexion, les ports de communication, les réponses
(NtReplyWaitReceivePort avec un message de réponse rend `STATUS_NOT_IMPLEMENTED`), les messages volumineux.

`smss` crée `\SmApiPort` et ses deux threads d'API y attendent, au lieu de tourner (l'étape 3) : rien ne s'y
connecte encore, `csrss` s'arrêtant avant (Se).

## Étape 6 : Se, les jetons

Le crate `se` (02 §5.8, ADR-011) donne les SID, les ACL (vérifiées comme RtlValidAcl), les descripteurs de
sécurité (capturés sous forme absolue ou relative, gardés sous forme relative) et le type `Token`. Chaque processus a
son jeton primaire : System celui de LocalSystem, un processus créé une copie de celui de son créateur
(SeSubProcessToken). Le jeton de System :

| Partie | Valeur |
|---|---|
| Utilisateur | S-1-5-18 (LocalSystem) |
| Groupes | Administrators (S-1-5-32-544, `SE_GROUP_OWNER`, propriétaire par défaut), Everyone (S-1-1-0), Authenticated Users (S-1-5-11) |
| Groupe principal | LocalSystem |
| DACL par défaut | `GENERIC_ALL` à LocalSystem ; `GENERIC_READ`, `GENERIC_EXECUTE`, `READ_CONTROL` à Administrators |
| Privilèges | 24 ; actifs par défaut : Tcb, CreatePagefile, LockMemory, IncreaseBasePriority, CreatePermanent, Debug, Audit, ChangeNotify, ProfileSingleProcess, Impersonate, CreateGlobal |
| Session d'ouverture, source | `SYSTEM_LUID` (0x3E7), `*SYSTEM*` |

Les objets ont un descripteur dans leur en-tête (Ob le garde sans le lire). Services :

| Service | Ce qu'il fait |
|---|---|
| NtOpenProcessToken(Ex) | un handle sur le jeton primaire (`PROCESS_QUERY_INFORMATION`) |
| NtOpenThreadToken(Ex) | `STATUS_NO_TOKEN` : aucun thread n'emprunte d'identité |
| NtQueryInformationToken | User, Groups, Privileges, Owner, PrimaryGroup, DefaultDacl, Source, Type, ImpersonationLevel (`STATUS_INVALID_INFO_CLASS` pour un jeton primaire), Statistics, RestrictedSids, SessionId, SandBoxInert ; la taille toujours rendue, `STATUS_BUFFER_TOO_SMALL` si le tampon est plus petit |
| NtAdjustPrivilegesToken | l'état d'avant des privilèges qui changent ; rien ne change sans la place de le rendre ; `STATUS_NOT_ALL_ASSIGNED` pour un privilège absent |
| NtSetSecurityObject, NtQuerySecurityObject | le descripteur d'un objet (parties remplacées et lues, `NtCurrentProcess()` compris) |

Contrôle permissif (ADR-011) : Ob accorde les droits demandés, un descripteur ne refuse encore rien. Le contrôle
des **privilèges** s'applique (SeSinglePrivilegeCheck sur le jeton primaire) : les appelants activent d'abord celui
qu'il leur faut, comme `smss`. Test : `security_self_test`.

`csrss` passe `CsrSetProcessSecurity` : NtOpenProcessToken, la taille de `TokenUser` puis `TokenUser`, une DACL qui
donne à son utilisateur la lecture, l'écriture et la fin de son processus (NtSetSecurityObject). Mais `smss`, qui
obtient désormais `SeLoadDriverPrivilege` (SmpAcquirePrivilege, qui échouait jusque-là), prend un chemin qu'il sautait :

| Service | Arguments | Ce qu'en fait `smss` | Composant |
|---|---|---|---|
| `NtSetSystemInformation` | `SystemSessionCreate` (47), 4 octets | « SMSS: Session space creation failed », **`SmpInit` échoue** avant de lancer `csrss` | Mm, Ex |

## Étape 7 : la session de `smss` et win32k

`SmpLoadSubSystemsForMuSession`, pour la valeur `Kmode` de `Session Manager\SubSystems`, sous
`SeLoadDriverPrivilege` : crée la session (`ASSERT(MuSessionId == 0)` ensuite), charge win32k, et s'en détachera
après avoir lancé `winlogon`. NtSetSystemInformation, chaque classe sous ce privilège
(`STATUS_PRIVILEGE_NOT_HELD`) :

| Classe | Ce qu'elle fait ici |
|---|---|
| `SystemSessionCreate` (47) | une session neuve (le plus petit identifiant libre, 0 d'abord), où entre l'appelant, qui devient le meneur des sessions ; `ps::session` en tient le compte, sans espace de session (Mm) encore |
| `SystemSessionDetach` (48) | le meneur quitte sa session (`STATUS_UNABLE_TO_FREE_VM` sinon) |
| `SystemExtendServiceTableInformation` (38) | win32k fait partie du noyau (02 §7) : sa table de services est déjà là, rien n'est chargé ; un autre nom que `\SystemRoot\System32\win32k.sys` est refusé, comme ReactOS. Ses services rendent encore `STATUS_NOT_IMPLEMENTED` |

`smss` lance alors `csrss`, qui passe `CsrSetProcessSecurity`, initialise ses sessions et son processus racine, puis
lit sa ligne de commande (`CsrParseServerCommandLine`) :

| Service | Arguments | Ce qu'en fait `csrss` | Composant |
|---|---|---|---|
| `NtCreateSection` | sans fichier, 1 Mio (`SharedSection=1024`), `PAGE_EXECUTE_READWRITE`, `SEC_BASED \| SEC_RESERVE` | « CSRSS: *** Invalid syntax for SharedSection=1024 », `CsrParseServerCommandLine` échoue, **`csrss` se termine** | **Mm** |

La section partagée de `csrss` (CsrSrvCreateSharedSection) : une section du fichier d'échange dont les pages sont
réservées (`SEC_RESERVE` : commitées à la demande par NtAllocateVirtualMemory dans la vue, ici par le tas que
`RtlCreateHeap` y crée) et dont la base est fixée par sa première vue (`SEC_BASED` : chaque processus la projette à
la même adresse) ; projetée par `csrss` en `MEM_TOP_DOWN`, `PAGE_EXECUTE_READWRITE`, puis son adresse et son tas
écrits dans le PEB (`ReadOnlySharedMemoryBase`, `ReadOnlySharedMemoryHeap`, `ReadOnlyStaticServerData`). Chaque
client la projette ensuite à la connexion (CsrSrvAttachSharedSection). C'est le prochain mur, avant le port d'API de
`csrss` (LPC) et `SmConnectToSm`.

## Étape 8 : la section partagée de `csrss` (Mm)

Une section du fichier d'échange peut naître réservée (`SEC_RESERVE`) et basée (`SEC_BASED`) :

| Attribut | Ce qu'il fait ici |
|---|---|
| `SEC_RESERVE` | les pages de la section sont réservées ; NtAllocateVirtualMemory(`MEM_COMMIT`) dans une vue commite les pages **de la section** (un bit par page), donc dans toutes ses vues, dans chaque processus, comme les pages prototypes d'XP ; la faute de page et NtQueryVirtualMemory voient une page que la section n'a pas commitée comme réservée (`VadNode::page_state`) |
| `SEC_BASED` | la création donne à la section une adresse, la même dans chaque processus, cherchée du haut vers le bas sous MmHighSectionBase (`0x7F7F0000`, 8 Mio sous le haut du mode utilisateur) parmi les autres sections basées ; une vue sans adresse demandée y va (`MEM_TOP_DOWN` n'y change rien), ou nulle part (`STATUS_CONFLICTING_ADDRESSES`) ; l'adresse est rendue avec la section |

NtQuerySection(`SectionBasicInformation`) donne l'adresse d'une section basée et `SEC_RESERVE` ou `SEC_COMMIT`, avec
`SEC_BASED`. `SEC_RESERVE` ne change rien pour une section de fichier ; `SEC_BASED` pour un fichier rend
`STATUS_NOT_IMPLEMENTED`. Test : `shared_section_self_test`.

`csrss` crée sa section partagée de 1 Mio, la projette en `0x7F6F0000` (l'adresse d'XP), y bâtit son tas
(`RtlCreateHeap` : NtQueryVirtualMemory la voit réservée, puis NtAllocateVirtualMemory commite la première page),
écrit son adresse dans son PEB, puis charge ses DLL serveur (`ServerDll=`) : `basesrv` s'initialise, avec trois
assertions tolérées (`DbgPrompt` répond `i`) :

| Ligne de `basesrv/init.c` | Service | Composant |
|---|---|---|
| 449 | NtQuerySystemInformation(`SystemTimeOfDayInformation`, 3) | Ex |
| 572 | NtSetInformationObject(`ObjectSessionInformation`, 5) sur `\BaseNamedObjects` | Ob |
| 581 | NtQueryInformationProcess(`ProcessLUIDDeviceMapsEnabled`, 0x1C) | Ps |

puis `winsrv` ne se charge pas :

| Ce qui manque | Ce qu'en fait `csrss` | Composant |
|---|---|---|
| `advapi32_vista.dll`, importée par `rpcrt4.dll` (que `user32` atteint par `advapi32`) : « LdrpMapDll failed with status c0000135 » | « CSRSS: *** Failed loading ServerDll=winsrv (Status == 0xc0000135) », `CsrParseServerCommandLine` échoue, **`csrss` se termine** | **xtask** (le disque de démarrage) |

Les imports de `winsrv` : `basesrv`, `csrsrv`, `gdi32`, `kernel32`, `ntdll`, `user32` ; `user32` importe `advapi32`,
qui importe `rpcrt4`, qui importe `advapi32_vista`, `kernel32_vista`, `msvcrt` et `ws2_32`. Le disque de démarrage
n'a que `csrss` et ses trois DLL serveur, plus les KnownDLLs : il lui faut la fermeture de leurs imports.

## Étape 9 : le disque de démarrage, fermé pour les imports

Le disque de démarrage reçoit désormais la fermeture des imports de ses programmes et de ses DLL (`smss`, `csrss`,
`csrsrv`, `basesrv`, `winsrv`, les KnownDLLs), lue dans leurs tables d'imports par `libs/pe`
(`xtask/src/userland.rs`, `import_closure`) : `advapi32_vista.dll`, `kernel32_vista.dll`, `ntdll_vista.dll`,
`ws2_32.dll`, `ws2help.dll`, et les imports des KnownDLLs (`combase`, `comctl32`, `coml2`, `dbghelp`, `imm32`, `mpr`,
`normaliz`, `psapi`, `shlwapi`, `usp10`, `winspool.drv`). Aucune n'est absente de la version épinglée, et aucune n'est
importée en différé. Trois ont un nom que le format 8.3 ne tient pas : `tools/mkfat` écrit les noms longs (VFAT, avec
un alias `BASIS~N.EXT`), que le pilote FAT du noyau lit (par le nom long ou l'alias, sans casse). Le disque reçoit
aussi la table de la page de code 20127 (US-ASCII), que demande la locale C de `msvcrt` (`GetCPInfo` : le fichier que
la ruche SYSTEM nomme dans `Nls\CodePage`, ouvert par NtCreateFile, puis une section nommée `\Nls\NlsSectionCP20127`).

`smss` met alors 37 sections dans `\KnownDlls` : les KnownDLLs et leurs imports, qu'il projette aussi. `csrss`
charge `winsrv` et ses imports, `msvcrt` s'initialise, puis :

| Service | Arguments | Ce qu'en fait `csrss` | Composant |
|---|---|---|---|
| NtQuerySystemInformation | `SystemRangeStartInformation` (0x32) | toléré | Ex |
| NtQueryDebugFilterState | `0xC8`, 2 | toléré (`ntdll`, `DbgPrint` filtré) | Kd |
| NtQuerySystemTime | — | toléré | Ke, Ex |
| NtQueryPerformanceCounter | — | toléré | Ke, Hal |
| **NtUserProcessConnect** | `NtCurrentProcess()`, un tampon de 0x124 octets | `user32` (DllMain) échoue : « LDR: DLL_PROCESS_ATTACH for dll "user32.dll" failed », « CSRSS: *** Failed loading ServerDll=winsrv (Status == 0xc0000142) », **`csrss` se termine** | **win32k** |

`NtUserProcessConnect` est le premier service de win32k qu'appelle l'espace utilisateur : `user32`, que `winsrv`
importe, s'y connecte dès son chargement dans `csrss`. Même la console de `csrss` (`consrv`, dans `winsrv`) en dépend :
le M5 rejoint ici la partie minimale du M6 (05 : « sinon ce jalon dépend de la partie minimale de M6 »).

## Étape 10 : les services simples que `csrss` tolérait

Le temps d'abord (`hal`) : l'horloge temps réel du CMOS, lue au démarrage (`hal::rtc`), donne l'heure du démarrage, et
le temps système est elle plus le temps d'interruption ; `KUSER_SHARED_DATA.SystemTime` le donne désormais. Le RTC
est lu comme UTC (biais de fuseau nul). Le compteur de temps du processeur, calibré sur les 10 ms de PIT qui calibrent
le timer de l'APIC, donne le compteur de performance. Puis les services :

| Service | Ce qu'il rend | Demandé par |
|---|---|---|
| NtQuerySystemTime | le temps système, en 100 ns depuis 1601 | `msvcrt`, `kernel32` |
| NtQueryPerformanceCounter | le compteur de temps du processeur depuis la calibration, sa fréquence | `kernel32` |
| NtQuerySystemInformation(`SystemTimeOfDayInformation`, 3) | l'heure du démarrage, l'heure, un fuseau nul ; les premiers octets demandés, 48 au plus | `basesrv` (`init.c`, ligne 449) |
| NtQuerySystemInformation(`SystemRangeStartInformation`, 50) | `0x80000000` | `kernel32` |
| NtQueryDebugFilterState | `TRUE` : tout va au port série | `ntdll` (`DbgPrintEx`) |
| NtSetInformationObject(`ObjectHandleFlagInformation`, 4) | les attributs d'un handle (héritable, protégé contre la fermeture) | — |
| NtSetInformationObject(`ObjectSessionInformation`, 5) | le répertoire devient celui de la session de l'appelant, sous `SeTcbPrivilege` | `basesrv` (`\BaseNamedObjects`, ligne 572) |
| NtQueryInformationProcess(`ProcessLUIDDeviceMapsEnabled`, 0x1C) | 0 | `basesrv` (ligne 581) |
| NtQueryInformationProcess(`ProcessCookie`, 0x24) | le cookie du processus, tiré à la première demande ; le processus de l'appelant seulement | `ntdll` (« Failed to receive the process cookie ») |
| NtFlushInstructionCache | rien à vider sur x86 ; le processus vérifié | `ntdll` (le chargeur) |

Test : `information_services_self_test`. Les assertions de `basesrv` et les messages du cookie disparaissent ;
`csrss` s'arrête toujours à `NtUserProcessConnect` (win32k, étape 9). Restent tolérés : NtQueryDefaultLocale,
NtCreateKeyedEvent, NtSetInformationProcess(`ProcessExecuteFlags`, `ProcessBreakOnTermination`,
`ProcessBasePriority`, `ProcessDefaultHardErrorMode`, `ProcessUserModeIOPL`),
NtSetInformationThread(`ThreadBreakOnTermination`), NtInitializeRegistry et NtRaiseHardError.

## Étape 11 : les événements à clé, les processus critiques

Ce que `smss` règle à son début (`smss.c`), et ce dont les sections critiques de `ntdll` se servent sous contention.

Les événements à clé (`ex::keyed_event`, le type `KeyedEvent`) : un rendez-vous, dans un même processus, entre un
thread qui attend une clé et un thread qui la libère ; le premier arrivé attend l'autre (alertable, avec échéance), le
second le réveille et repart. Une clé est paire (`ntdll` y met des adresses). Un handle nul désigne l'événement de
`\KernelObjects\CritSecOutOfMemoryEvent`, créé au démarrage. Puis la priorité de base d'un thread dans Ke
(KeSetBasePriorityThread, `ke::sched::set_base_priority` : le boost reste, plafonné à 15 pour la classe variable ; un
thread prêt change de file) et, dans Ps, ce que le processus et ses threads gardent : critique, priorité de base (les
threads créés ensuite la prennent), mode d'erreur grave (`SEM_*`, hérité du créateur ; System :
`SEM_FAILCRITICALERRORS`).

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtCreateKeyedEvent, NtOpenKeyedEvent | un événement à clé (drapeaux nuls), ou celui d'un nom | `ntdll` (`RtlpInitializeKeyedEvent`) |
| NtWaitForKeyedEvent, NtReleaseKeyedEvent | le rendez-vous ; `KEYEDEVENT_WAIT`, `KEYEDEVENT_WAKE` ; une clé impaire refusée | `ntdll` (sections critiques, variables de condition) |
| NtSetInformationProcess(`ProcessBasePriority`, 5) | de 1 à 31, le bit du premier plan ignoré ; la relever demande `SeIncreaseBasePriorityPrivilege` | `smss` (11, `smss.c` ligne 472), `csrss` (13) |
| NtSetInformationProcess(`ProcessDefaultHardErrorMode`, 12), NtQueryInformationProcess | ses `SEM_*` | `smss`, `csrss` |
| NtSetInformationProcess(`ProcessBreakOnTermination`, 29), NtQueryInformationProcess | critique ou non, sous `SeDebugPrivilege` | `smss` (`RtlSetProcessIsCritical`), `csrss` après son initialisation |
| NtSetInformationThread(`ThreadBreakOnTermination`, 18) | critique ou non, sous `SeDebugPrivilege` | `smss` (`RtlSetThreadIsCritical`) |

La fin d'un processus ou d'un thread critique arrête le système : `CRITICAL_OBJECT_TERMINATION` (`0xF4` ; le type de
l'objet, 3 pour un processus et 6 pour un thread, l'objet, le nom de l'image, le message), quand on le termine
(« Terminating critical process ») et quand il finit de lui-même (« Critical thread exited », « Critical process
exited ») ; sans débogueur, rien ne demande s'il faut l'ignorer. La sonde, qui termine `smss` après 10 s, lui retire
d'abord ces drapeaux, à lui et à ses threads (`EProcess::clear_critical`), comme un débogueur qui répondrait « ignorer ».

Tests : hôte (`ex::keyed_event`, `ke::sched`), `keyed_event_self_test` (deux threads se rencontrent dans les deux
ordres), `process_settings_self_test`, et deux scénarios qui finissent sur l'écran STOP, `critical-process` (le
processus se termine) et `critical-thread` (le processus d'un thread critique se termine) ; vérifiés par mutation.
L'assertion de `smss` (ligne 472) et les classes 5, 12 et 29 disparaissent du journal ; `smss` se déclare critique, et
`csrss` s'arrête toujours à `NtUserProcessConnect`. Restent tolérés : NtQueryDefaultLocale,
NtSetInformationProcess(`ProcessExecuteFlags`, `ProcessUserModeIOPL`), NtInitializeRegistry, NtRaiseHardError
(`csrss` : `STATUS_IO_PRIVILEGE_FAILED`, faute d'IOPL), et NtSetInformationThread(`ThreadZeroTlsCell`, 10), que
`kernel32` appelle quand `csrss` décharge ses DLL après l'échec de `winsrv`.

## Étape 12 : win32k minimal ; `csrss` charge `winsrv` et va jusqu'à `smss`

Le mainteneur a choisi de faire entrer dans le M5 la partie minimale de win32k (05 : « sinon ce jalon dépend de la
partie minimale de M6 ») : l'initialisation de `user32`, premier critère du spike S3. Crate `win32k` (02 §7.2) :

- **La section partagée de USER** (`win32k::shared`) : 64 Kio du fichier d'échange, le `SERVERINFO` sur la première
  page, puis la table des handles (sa tête `USER_HANDLE_TABLE` et 4096 entrées vides, comme `UserCreateHandleTable`).
  Le noyau l'écrit par l'alias de ses pages (`Section::write_kernel`, Mm) ; chaque processus GUI la voit en lecture
  seule. Ses pointeurs sont des adresses du serveur sur 32 bits, la section étant en `0xBC000000` (ADR-021).
- **Les threads et processus GUI** (`win32k::gui`) : le premier appel d'un thread à win32k en fait un thread GUI
  (PsConvertToGuiThread, dans `sys::dispatch`) ; son processus reçoit sa vue de la section et, dans son PEB, la limite
  des lots de GDI (`GdiDCAttributeList`, 20) ; son TEB reçoit son `THREADINFO` (`Win32ThreadInfo`) et son
  `CLIENTINFO` (`Win32ClientInfo` : le `PROCESSINFO`, les `TIF_*`, la version qu'attend l'image). Ps garde pour
  win32k un emplacement par processus et par thread (`EProcess::win32_process`, `EThread::win32_thread`).
- `abi::user` : `USERCONNECT` (0x124 octets), `SHAREDINFO`, le début du `SERVERINFO`, la table des handles,
  `CLIENTINFO`, d'après `win32ss/include/ntuser.h`.

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtUserProcessConnect | le processus (`PROCESS_VM_OPERATION`) devient un processus GUI ; le `USERCONNECT` reçoit le `SERVERINFO` et la table des handles dans sa vue, l'écart des adresses du serveur ; `STATUS_UNSUCCESSFUL` pour un tampon nul ou d'une autre taille | `user32` (`Init`), `winsrv` |
| NtUserInitializeClientPfnArrays | une fois : les procédures de fenêtre de `user32` dans le `SERVERINFO` (et, comme ReactOS, `aStoCidPfn`) | `user32` (`RegisterClientPFN`) |
| NtGdiInit | TRUE | `gdi32` (`GdiDllInitialize`) |
| NtUserInitialize | une fois, dans `csrss` : USER retient `csrss` (ses threads sont des threads de `csrss`), l'événement des demandes d'alimentation, et crée `\Windows\WindowStations` ; une autre version de USER arrête le système (`WIN32K_INIT_OR_RIT_FAILURE`) | `winsrv` (`UserServerDllInitialization`) |
| NtCreateSemaphore, NtOpenSemaphore, NtReleaseSemaphore, NtQuerySemaphore | les sémaphores d'Ex (`ex::semaphore`, sur le KSEMAPHORE de Ke), attendables | `consrv` (`ConServerDllInitialization`) |
| NtQueryObject(`ObjectHandleFlagInformation`, 4) | les attributs d'un handle, deux BOOLEAN alignés sur un octet | `csrsrv` |

`gdi32` charge aussi `lpk.dll` au démarrage (`GdiInitializeLanguagePack`) : `xtask` la met sur le disque, avec ses
imports.

Ce qui manque encore à USER, et que NtUserInitialize ne fait pas (M6) : la vidéo (InitVideo), GDI (DirectX,
polices), les paramètres système, le pinceau gris ; la pile noyau agrandie des threads GUI, les files de messages,
les bureaux, les dispositions du clavier (`hKL` et `CodePage` restent nuls), la table des handles de GDI
(`PEB.GdiSharedHandleTable` reste nul).

Tests : hôte (`abi::user`, `win32k`, `ex::semaphore`), `win32k_self_test` (conversion, NtUserProcessConnect et ses
refus, lecture de la table dans la vue, sémaphores, NtQueryObject), et dans le scénario `smss` le résumé que journalise
la sonde : `[m4] USER: started by csrss (PID 20), \Windows\WindowStations created; 23 of 23 client procedures of
user32 (at 0x77a20000) in SERVERINFO` ; vérifiés par mutation.

`csrss` charge désormais `winsrv` en entier : USER, puis la console (`consrv`). `csrsrv` crée son port d'API et son
port pour `smss`, puis se connecte à `smss` (`SmConnectToSm`) : **NtConnectPort**, pas encore implémenté (étape 7 de
la passation, la connexion LPC). Restent tolérés : NtQueryDefaultLocale (`winsrv`, `harderror.c`),
NtSetInformationProcess(`ProcessExecuteFlags`, `ProcessUserModeIOPL`), NtInitializeRegistry, NtRaiseHardError.

## Étape 13 : la connexion LPC ; `csrss` et `smss` se connectent

Le crate `lpc` connaît maintenant trois sortes de ports (`lpc::port`) : le port de connexion, nommé, d'un serveur ; le
port client d'un client connecté ; le port de communication du serveur. Ce qu'un client envoie va dans la file du port
de connexion, avec le contexte du port du serveur (PortContext) ; ce que le serveur envoie, dans la file du port
client. Les deux extrémités se désignent sans se garder en vie : l'une partie, l'autre est déconnectée. Un thread qui
attend sa connexion ou une réponse est inscrit par son TID, avec l'identifiant du message, et attend son propre
événement (`lpc::conversation`). Un client peut partager une section : projetée chez lui à la connexion, chez le
serveur quand il accepte, chacun apprend où l'autre la voit.

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtConnectPort, NtSecureConnectPort | la demande de connexion (`LPC_CONNECTION_REQUEST`) au port nommé, avec ses données (tronquées à ce que le port admet) et sa section ; attend l'acceptation (`STATUS_PORT_CONNECTION_REFUSED` sinon) ; le SID de l'utilisateur du serveur, s'il est donné (`STATUS_SERVER_SID_MISMATCH`) | `csrsrv` (`SmConnectToSm`), `smss` (vers le port SB de `csrss`), plus tard `kernel32` (`CsrClientConnectToServer`) |
| NtListenPort | attend une demande de connexion, en laissant passer le reste | — |
| NtAcceptConnectPort | refuse (le client se réveille), ou accepte : le port de communication du serveur, son contexte (le handle s'il est nul), la section du client projetée chez lui ; `STATUS_INVALID_CID`, `STATUS_REPLY_MESSAGE_MISMATCH` | `smss` (`SmpHandleConnectionRequest`), `csrsrv` |
| NtCompleteConnectPort | réveille le client accepté | idem |
| NtRequestWaitReplyPort, NtRequestPort, NtReplyPort | une requête et sa réponse, un datagramme, une réponse ; les longueurs vérifiées, un type choisi par l'appelant refusé | `smss`, `csrsrv`, `smlib` |
| NtReplyWaitReceivePort, NtReplyWaitReceivePortEx | répondre puis recevoir, avec le contexte ; une demande de connexion arrive avec ses seules données ; un port du serveur lit la file de son port de connexion ; avec un délai pour l'Ex | `smss` (`SmpApiLoop`), `csrsrv` |
| NtSetDefaultHardErrorPort | une fois, sous `SeTcbPrivilege` : le port des erreurs graves (rien ne l'emploie encore) | `csrsrv` |
| NtOpenProcess, NtOpenThread | un handle par le CLIENT_ID (ou un nom) ; `STATUS_INVALID_PARAMETER_MIX`, `STATUS_INVALID_CID` | `smss` (le processus d'un client qui se connecte) |
| NtQuerySystemInformation(`SystemFlagsInformation`, 9) | les drapeaux globaux, aucun | `smss` (`smss.c`, son assertion) |

Les tests hôte de `hal` tenaient l'IRQL pour un seul processeur : des tests lancés en même temps se changeaient
l'IRQL l'un de l'autre en prenant un verrou. L'IRQL de l'hôte est maintenant propre à chaque thread (`#[thread_local]`).

La sonde, pendant qu'elle tourne, laisse passer la fin d'un processus ou d'un thread critique en la journalisant, comme
un débogueur qui répondrait « ignorer » (`ps::set_critical_breaks_ignored`) : `smss` peut maintenant finir de
lui-même, critique, et la sonde montre où.

Tests : hôte (`lpc` : routage, acceptation et refus, réponses, longueurs ; `hal` : un IRQL par thread),
`lpc_connection_self_test` (un serveur et un client dans un processus : refus par le SID et par le serveur, section
partagée vue des deux côtés, données de connexion récrites et tronquées, contexte, requête et réponse, datagramme,
refus ; NtOpenProcess, NtOpenThread, `SystemFlagsInformation`, le port des erreurs graves sans privilège) ; vérifiés
par mutation.

`csrss` se connecte à `smss` (`SmConnectToSm`) : `smss` ouvre son processus, accepte et complète la connexion, puis se
connecte au port SB de `csrss`, qui l'accepte ; `smss` signale l'événement de `csrss`. `csrss` donne son port des
erreurs graves, se déclare critique et termine son premier thread : **`csrss` est démarré**. `smss` lance ensuite sa
commande initiale, `winlogon.exe`, qui n'est pas sur le disque (« Initial command image (winlogon.exe) not found ») :
il abandonne (`SmpTerminate`) et finit. Restent tolérés : NtQueryDefaultLocale, NtRaiseHardError,
NtSetInformationProcess(`ProcessExecuteFlags`, `ProcessUserModeIOPL`), NtInitializeRegistry.

## Étape 14 : `winlogon.exe` sur le disque ; NtDuplicateObject

`cargo xtask` met `winlogon.exe` dans `WINDOWS\SYSTEM32`, avec la fermeture de ses imports (aucune DLL de plus :
celles qu'il importe sont déjà sur le disque). `smss` trouve sa commande initiale et crée son processus
(`SmpExecuteImage`), puis garde un handle sur lui (`SmpExecuteInitialCommand`, `smss.c`) :

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtDuplicateObject | un handle dans le processus cible sur l'objet d'un handle du processus source (`ob::duplicate`) ; les deux processus désignés dans le processus courant, avec `PROCESS_DUP_HANDLE` ; `NtCurrentProcess()` et `NtCurrentThread()` comme handle source, avec tous les droits de leur type ; les droits et les attributs de la source (`DUPLICATE_SAME_ACCESS`, `DUPLICATE_SAME_ATTRIBUTES`) ou ceux demandés (`OBJ_INHERIT`, `OBJ_PROTECT_CLOSE`) ; sans processus cible, la source se ferme seulement (`DUPLICATE_CLOSE_SOURCE`, sinon `STATUS_INVALID_PARAMETER`) ; avec `DUPLICATE_CLOSE_SOURCE`, la source se ferme quel que soit le résultat (un handle protégé reste) ; `*TargetHandle` mis à zéro d'abord | `smss` (le processus de `winlogon`, `PROCESS_ALL_ACCESS`), `csrss` |

Un processus cible qui ne s'ouvre pas rend son statut (après la fermeture de la source, avec
`DUPLICATE_CLOSE_SOURCE`) ; ReactOS rend dans ce cas le résultat d'une duplication sans cible.

Sans NtDuplicateObject, `smss` terminait `winlogon` (« SMSS: DupObject Failed », « Execute Initial Command
failed »), puis finissait. Désormais il le confie à `csrss` (`SmExecPgm` sur son propre port d'API, puis
`CsrSbCreateSession` par le port SB de `csrss`), et attend `csrss` et `winlogon` : la sonde le termine au bout de
10 s. `csrss` fait de `winlogon` un processus CSR et s'arrête à son port d'exception :
**NtSetInformationProcess(`ProcessExceptionPort`)**, pas encore implémenté (`CsrSbCreateSession`,
`csrsrv/session.c`) ; il demandera ensuite les temps de son premier thread (NtQueryInformationThread,
`ThreadTimes`), sa priorité d'arrière-plan (`ProcessForegroundInformation`, dont l'échec est toléré), puis
reprendra le thread : `winlogon` démarrera.

Tests : hôte (`ob` : sans cible, pseudo-handle, source fermée quel que soit le résultat), `duplicate_object_self_test`
(un programme duplique un événement dans son processus et dans un autre, ses pseudo-handles, et chaque refus : sans
`PROCESS_DUP_HANDLE`, sans cible, processus source ou cible invalide, `*TargetHandle` à une adresse invalide ; les
handles fermés se voient au compte de handles de leur objet, une entrée libérée étant la suivante reprise).

## Étape 15 : `winlogon` devient un processus CSR et se connecte à `csrss`

`csrss` fait de `winlogon` un processus CSR (`CsrSbCreateSession`, `csrsrv/session.c`), puis reprend son thread :

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtSetInformationProcess(`ProcessExceptionPort`, 8) | sous `SeTcbPrivilege`, un port LPC, une seule fois (`STATUS_PORT_ALREADY_SET`) ; gardé dans l'EPROCESS, le noyau ne s'en sert pas encore | `csrsrv` (`CsrSbCreateSession`) |
| NtQueryInformationThread(`ThreadBasicInformation` 0, `ThreadTimes` 1, `ThreadIsTerminated` 20) | le TEB, le CLIENT_ID, le statut de fin, la priorité ; la création et la fin (les temps noyau et utilisateur restent nuls) ; 1 si la fin du thread est demandée ou en cours (PsIsThreadTerminating) | `csrsrv` (`CsrSbCreateSession` : la création du premier thread ; `CsrInsertThread` : ce thread ne doit pas être déjà en fin) |

`winlogon` démarre. Son `kernel32` se connecte à `csrss` (`CsrClientConnectToServer`, NtSecureConnectPort sur
`\Windows\ApiPort`, avec une section) : `csrss` **refusait la connexion** (« CSRSS: Rejecting Connection Request from
ClientId: 1c.30 », puis « Failed to connect to CSR (Status c0000041) ») et `winlogon` finissait avec
`STATUS_PORT_CONNECTION_REFUSED`. Le CLIENT_ID n'y était pour rien (`CsrLocateThreadByClientId` trouvait le thread
inscrit par `CsrSbCreateSession`) : `CsrApiHandleConnectionRequest` projette sa section partagée chez le client
(`CsrSrvAttachSharedSection`, `csrsrv/server.c`), avec NtMapViewOfSection(…, `ViewUnmap`, **`SEC_NO_CHANGE`**,
`PAGE_EXECUTE_READ`), et NtMapViewOfSection refusait ce type d'allocation (`STATUS_INVALID_PARAMETER_9`) ; `csrsrv`
refuse alors la connexion sans journaliser le statut.

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtMapViewOfSection, `AllocationType` | ceux de ReactOS (MmMapViewOfSection) : `MEM_TOP_DOWN`, `MEM_RESERVE`, `SEC_NO_CHANGE`, `MEM_LARGE_PAGES`, `MEM_DOS_LIM` ; une vue `SEC_NO_CHANGE` garde sa protection (le nœud de la VAD est marqué : `VadNode::no_change`, `AddressSpace::map_view_with`, `ViewOptions`), NtProtectVirtualMemory y rend `STATUS_INVALID_PAGE_PROTECTION`, la retirer reste permis ; `MEM_LARGE_PAGES` et `MEM_DOS_LIM` rendent `STATUS_NOT_IMPLEMENTED`, journalisé une fois (le refus d'un type valide cachait l'échec) | `csrsrv` (`CsrSrvAttachSharedSection`) |

`kernel32` se connecte ; `winlogon` charge ses DLL (tolérés : contextes d'activation absents,
manifeste de `mpr.dll`, `ProcessExecuteFlags`, `nfs41_np.dll` absent, la clé `Tcpip\Parameters` absente), `user32`
se connecte à win32k (NtUserProcessConnect, son second client) et NtRegisterThreadTerminatePort manque (toléré).
Puis **USER**, que le win32k minimal n'a pas encore (M6) :

- `RegisterLogonProcess` (`user32/misc/logon.c`) : NtUserCallTwoParam (PID de `winlogon`, TRUE, `0x69`) manque ; dans
  `csrss`, `winsrv` appelle NtUserSetInformationThread, absent : « Failed to register logon process with CSRSS » ;
- la station de fenêtres et les bureaux : NtUserCreateWindowStation, NtUserSetProcessWindowStation,
  NtUserGetProcessWindowStation, NtUserCreateDesktop, NtUserSetThreadDesktop, NtUserSwitchDesktop,
  NtUserSetWindowStationUser ; `csrss` répond « We are logged off » (`winsrv/usersrv/init.c`) ; NtImpersonateThread
  manque (« CSRSS: Can't impersonate client thread », `csrsrv/procsup.c`) ;
- le clavier : NtUserLoadKeyboardLayoutEx, NtUserSetImeHotKey, NtUserGetKeyboardLayoutList.

Chacun de ces services rend `STATUS_NOT_IMPLEMENTED`, que `user32` lit comme un handle (la station de fenêtres
`0xC0000002`, passée ensuite à NtUserSetProcessWindowStation) ou comme un compte (NtUserGetKeyboardLayoutList) :
`user32` lit au-delà de son tas et faute (`0xC0000005` en `0x77A71C23`, lecture en `0x233000`). `winlogon` finit ;
`smss` (« Initial command 'winlogon.exe' terminated when it wasn't supposed to ») abandonne (`SmpTerminate`) et finit
de lui-même, critique : la sonde le laisse passer.

Tests : hôte (`mm` : une vue `SEC_NO_CHANGE` refuse toute protection, une vue sans lui l'accepte),
`shared_section_self_test` (une vue `SEC_NO_CHANGE` depuis le mode utilisateur : NtProtectVirtualMemory refusé,
NtUnmapViewOfSection permis ; `MEM_COMMIT` refusé comme type d'une vue), `thread_information_self_test`
(`ThreadIsTerminated` : 0 pour lui-même, 1 pour un thread fini).

## Étape 16 : les services de win32k qui manquent échouent proprement ; `winlogon` s'inscrit

Un service de win32k sans handler rendait `STATUS_NOT_IMPLEMENTED` (`0xC0000002`), que `user32` lisait comme un
handle de station de fenêtres ou comme un compte, puis faute. Il rend maintenant ce que rend win32k quand il échoue :

| Ce que rend le service | Sans handler |
|---|---|
| un `NTSTATUS` (78 services : NtUserProcessConnect, NtUserSetInformationThread, NtGdiFlush, les D3DKMT…) | `STATUS_NOT_IMPLEMENTED` |
| une valeur (BOOL, HANDLE, DWORD, compte…) | 0, et `ERROR_CALL_NOT_IMPLEMENTED` (120) comme dernière erreur du thread (`TEB.LastErrorValue`, `win32k::set_last_error`) |

Le type rendu vient des prototypes de ReactOS épinglé : `tools/syscall-gen/reactos/0.4.16/w32k-ntstatus.lst`
(origine et méthode dans le `README.md` du dossier), que `tools/syscall-gen` porte dans les tables
(`Service::returns_status`, `Service::value`). Le premier appel reste journalisé, suivi de « 0 returned ».

`winlogon` s'inscrit alors comme processus de logon (`RegisterLogonProcess`, `user32/misc/logon.c`) :

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtUserCallTwoParam(`TWOPARAM_ROUTINE_REGISTERLOGONPROCESS`, `0x69`) | inscrit le processus de logon (un seul ; TRUE), ou le désinscrit (lui seul) ; FALSE et `ERROR_INVALID_PARAMETER` pour un PID sans processus (`win32k::logon`) ; une autre routine rend 0 et `ERROR_CALL_NOT_IMPLEMENTED`, journalisée une fois | `user32` de `winlogon` |
| NtUserSetInformationThread(`UserThreadCsrApiPort`, 10) | pour `csrss` seul (`STATUS_ACCESS_DENIED`), sur un thread ouvert avec `THREAD_SET_INFORMATION` : le handle d'un port LPC (4 octets, `STATUS_INFO_LENGTH_MISMATCH`) devient le port d'API de `csrss` pour win32k (`win32k::csrss::set_api_port`) ; les autres classes rendent `STATUS_NOT_IMPLEMENTED` | `winsrv` (`SrvRegisterLogonProcess`, `usersrv/register.c`), quand `winlogon` s'inscrit |

Puis `winlogon` crée sa station de fenêtres (`CreateWindowStationAndDesktops`, `winlogon/wlx.c`) :
NtUserCreateWindowStation rend NULL, « WL: Failed to create window station (120) », et `winlogon` finit (NtRaiseHardError
manque, puis `ExitProcess(1)`) ; `smss` finit avec lui. Le dernier processus de logon n'est pas oublié à sa fin (pas
encore de rappel de sortie pour un processus GUI).

Tests : hôte (`syscall-gen` : la liste lue, chaque nom un service de win32k ; `win32k::logon` : un seul processus de
logon), `win32k_self_test` (NtGdiAbortDoc sans handler rend 0 et `ERROR_CALL_NOT_IMPLEMENTED`, NtGdiGetStats
`STATUS_NOT_IMPLEMENTED` sans toucher la dernière erreur ; RegisterLogonProcess depuis le mode utilisateur : une fois, pas
deux, désinscription par un autre refusée, PID sans processus, routine inconnue ; NtUserSetInformationThread refusé hors
de `csrss`).

## Étape 17 : les stations de fenêtres ; `winlogon` crée `WinSta0`

`winlogon` crée la station interactive et la prend (`CreateWindowStationAndDesktops`, `winlogon/wlx.c`) :

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtUserCreateWindowStation | la station que nomment les attributs (`WinSta0`, sous `\Windows\WindowStations` ouvert par `user32`), ouverte si elle existe, créée sinon (type d'Ob `WindowStation`, `win32k::winsta`) ; la première que crée le processus de logon devient la station interactive (`InputWindowStation`, journalisé), les autres n'ont ni entrée ni sortie (`WSS_NOIO`) ; rend son handle. Sans nom (nommée d'après la session de logon) : pas encore (`STATUS_NOT_IMPLEMENTED`, journalisé une fois) | `winlogon` (`CreateWindowStationW`) |
| NtUserOpenWindowStation | un handle sur la station nommée | — |
| NtUserSetProcessWindowStation, NtUserGetProcessWindowStation | la station du processus (`PROCESSINFO` : handle, station, droits du handle ; 0 : plus aucune) | `winlogon`, `user32` (`CreateDesktopW`) |
| NtUserCloseWindowStation | ferme le handle d'une station ; FALSE (`ERROR_BUSY`) pour celui de la station du processus | — |
| NtUserSetWindowStationUser | pour le processus de logon seul (`ERROR_ACCESS_DENIED`) : la LUID de l'utilisateur de la station, et son SID (au plus 68 octets, une limite que ReactOS n'a pas) | `winlogon` |

Ces services rendent une valeur : un échec rend 0, avec l'erreur Win32 du statut comme dernière erreur
(SetLastNtError, `abi::winerror::dos_error`, pour les statuts que le noyau rend).

`winlogon` crée ensuite son bureau `Default` : NtUserCreateDesktop manque (« WL: Failed to create Default desktop
(120) »), et `winlogon` finit.

Pas encore : les bureaux d'une station (sa procédure *parse*), la table des atomes, le thread du bureau et le thread
d'entrée que ReactOS crée avec la station interactive, le handle de station gardé dans l'EPROCESS (hérité par un
processus créé), NtUserLockWindowStation.

Tests : hôte (`win32k::winsta` : une seule station interactive, celle du processus de logon ; la correspondance
générique ; l'utilisateur d'une station ; `abi::winerror`), `window_station_self_test` (créée, recréée et ouverte : un
seul objet, pas interactif ; la station du processus, que NtUserCloseWindowStation garde ; un autre handle fermé une
fois ; NtUserSetWindowStationUser refusé hors du processus de logon, puis accepté, un SID trop long refusé ; le processus
de logon qui ouvre une station existante ne la rend pas interactive) ; le scénario `smoke` interdit la station
interactive (pas de processus de logon).

## Étape 18 : les bureaux ; `winlogon` crée les siens et s'y place

`winlogon` crée ses trois bureaux, se place sur `Winlogon` et en fait le bureau d'entrée
(`CreateWindowStationAndDesktops`, `winlogon/wlx.c`) :

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtUserCreateDesktop | le bureau que nomment les attributs, sur sa station (la racine, celle du processus pour `user32`, ou le chemin qui précède son nom), ouvert s'il existe (`OBJ_OPENIF`, sinon `ERROR_ALREADY_EXISTS`), créé sinon : type d'Ob `Desktop` (`win32k::desktop`), tenu et nommé par sa station (procédure *parse* : `WinSta0\Default`), un tas de 3 Mio (128 Kio pour `Winlogon` et hors de la station interactive) dans une section, avec une adresse du serveur sur 32 bits (`0xA0000000`–`0xBBFFFFFF`, ADR-021), et son `DESKTOPINFO` en tête (`abi::user::DeskInfoHead32` : bornes du tas, chaînes de crochets vides, nom) ; rend son handle | `winlogon` (`Default`, `Winlogon`, `Screen-Saver`) |
| NtUserOpenDesktop | un handle sur le bureau nommé | — |
| NtUserSetThreadDesktop | le thread passe sur le bureau : son processus voit le tas en lecture seule (`SEC_NO_CHANGE`, une vue par bureau, retirée avec le dernier thread), un `CLIENTTHREADINFO` y est pris pour lui, son `CLIENTINFO` les désigne (`pDeskInfo`, `ulClientDelta`, `pClientThreadInfo`) ; le premier bureau d'un thread client (ni de `csrss` ni du système) devient le bureau de démarrage du processus ; sans bureau : `csrss` seul | `winlogon` |
| NtUserSwitchDesktop | le bureau (`DESKTOP_SWITCHDESKTOP`) devient le bureau d'entrée, s'il est sur la station interactive de la session de l'appelant (sinon `ERROR_ACCESS_DENIED`) ; rien n'est dessiné | `winlogon` |
| NtUserCloseDesktop | ferme le handle d'un bureau ; FALSE (`ERROR_BUSY`) pour celui du bureau du thread ou du bureau de démarrage | — |

`winlogon` donne ensuite l'utilisateur de la station (NtUserSetWindowStationUser) ; `winsrv` le note (« We are logged
off ») et `csrsrv` ne peut emprunter son identité (NtImpersonateThread manque, toléré). Puis `winlogon` charge ses
dispositions de clavier (`InitKeyboardLayouts`, `winlogon.c`) : NtUserLoadKeyboardLayoutEx manque (« WL: Could not
preload keyboard layouts »), et `winlogon` finit.

Pas encore : la fenêtre du bureau et la fenêtre des messages (ReactOS les crée avec le bureau : `spwnd` reste nul), les
crochets, le dessin du bureau d'entrée, NtUserGetThreadDesktop, ce qui est rendu à la fin d'un thread ou d'un
processus GUI (son bureau, ses vues : rendus quand ses objets partent).

Tests : hôte (`win32k::desktop` : plages libres prises et fusionnées, chaînes de crochets vides, tailles des tas ;
`win32k::gui` : qui donne un bureau de démarrage), `desktop_self_test` (un bureau créé sur sa station, recréé (ouvert),
refusé sans `OBJ_OPENIF`, un second ouvert par son nom complet, trouvé par l'espace de noms à travers sa station ;
NtUserSetThreadDesktop : `DESKTOPINFO` et `CLIENTTHREADINFO` lus par le `CLIENTINFO` dans une vue en lecture seule, le
même bureau deux fois ne change rien, l'ancienne vue retirée au changement ; le bureau du thread gardé par
NtUserCloseDesktop ; NtUserSwitchDesktop refusé hors de la station interactive ; NtUserSetThreadDesktop refuse
l'absence de bureau hors de `csrss` et le handle d'une station).

## Étape 19 : les dispositions de clavier ; `winlogon` charge `00000409`

`winlogon` charge ses dispositions de clavier (`InitKeyboardLayouts`, `winlogon.c`) : sans `Keyboard Layout\Preload`
dans `HKCU` (pas encore de ruche de l'utilisateur), il charge `00000409` (`LoadKeyboardLayoutW`, `KLF_ACTIVATE |
KLF_SUBSTITUTE_OK | KLF_REPLACELANG | KLF_SETFORPROCESS`), puis `user32` prépare les raccourcis de l'IME
(`CliImmInitializeHotKeys`) :

| Service | Ce qu'il fait | Demandé par |
|---|---|---|
| NtUserLoadKeyboardLayoutEx | la disposition du HKL (`0x04090409`), chargée si elle ne l'est pas : le noyau lit `Layout File` sous `HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\<KLID>` (un nom de fichier seul) et le fichier de `\SystemRoot\System32` (`kbdus.dll`, mis sur le disque par `xtask`) ; win32k n'exécute pas `KbdLayerDescriptor` (ReactOS le fait, et le note comme dangereux) : il lit son code, `mov eax, offset ; ret`, d'où la RVA des tables (`0x1000`) ; puis l'active (`KLF_ACTIVATE`) pour le thread ou chaque thread GUI du processus (`KLF_SETFORPROCESS`) : `hKL` et `CodePage` de leur `CLIENTINFO` (la page ANSI du système). NULL pour un HKL nul, sans station ou hors de la station interactive ; `ERROR_INVALID_FLAGS` pour un drapeau inconnu | `winlogon` (`LoadKeyboardLayoutW`) |
| NtUserGetKeyboardLayoutList | le nombre des dispositions chargées, ou leurs HKL dans la limite du tampon | `user32` (`CliImmInitializeHotKeys`) |

NtUserSetImeHotKey manque (rend 0, toléré : pas d'IME). `winlogon` démarre ensuite son serveur RPC (`StartRpcServer`,
`rpcserver.c`) : `RpcServerUseProtseqEpW` sur le tube nommé `\pipe\winreg` (`CreateNamedPipe` de `kernel32`) demande
**NtCreateNamedPipeFile**, le système de fichiers des tubes nommés d'Io (NPFS, `\Device\NamedPipe`), pas encore fait :
« WL: Could not start the RPC server », et `winlogon` finit. (NPFS est fait à l'étape 24.)

Pas encore : la traduction des touches par les tables (avec la file d'entrée, M6), la page de code d'une langue autre
que celle du système, l'IME, le déchargement d'une disposition (`hOldKL`, NtUserUnloadKeyboardLayout), le
réordonnancement (`KLF_REORDER`), la notification du shell, le fichier donné par `hFile`.

Tests : hôte (`libs/pe` : octets lus à une RVA ; `win32k::keyboard` : les tables lues et non exécutées, et chaque refus ;
une disposition chargée une fois, listée, pas relue ; un fichier illisible ou invalide pas listé ; rien sans HKL ni hors
de la station interactive ; le nom du fichier de disposition), `desktop_self_test` (NtUserLoadKeyboardLayoutEx refuse un
drapeau inconnu et ne lit rien hors de la station interactive ; NtUserGetKeyboardLayoutList compte les dispositions) ; le
scénario `smss` attend la disposition chargée, ses tables et ses HKL listés.

## Étape 20 : premier affichage ; le fond du bureau d'entrée

Premier pas de GDI et du pilote d'affichage (M6, choisi avec le mainteneur avant les tubes nommés) : quand `winlogon`
fait de `Winlogon` le bureau d'entrée (NtUserSwitchDesktop), win32k en peint le fond sur l'écran.

- **Pilote d'affichage** (`win32k::display`) : un trait interne, `DisplayDriver` (mode, surface, prise de l'écran),
  implémenté par `drivers/video/gopfb` sur le framebuffer UEFI que décrit le chargeur (GOP, 1280×800, BGR sous QEMU ;
  vu par le HHDM). Le noyau l'installe au démarrage. win32k dessine directement dans le framebuffer, comme un pilote
  d'XP associe sa surface à GDI ; la première fois, le pilote prend l'écran à la console de démarrage (`hal::fb`), qui
  cesse d'y écrire. Les dessins passent un à un sous un `KSpinLock` (en attendant un mutex à PASSIVE_LEVEL).
- **Moteur DIB** (`win32k::gdi::dib`) : surface de 32 bits par pixel (`Bitmap` : largeur, hauteur, pas, ordre des
  octets `Bgrx` ou `Rgbx`), couleurs COLORREF converties en pixels, PatBlt d'un pinceau plein (`fill_rect`, coupé
  aux bords).
- **Couleur système** (`win32k::gdi::syscolor`) : `COLOR_BACKGROUND`, RGB(58, 110, 165) (la table par défaut de
  ReactOS, `win32ss/gdi/ntgdi/stockobj.c`).
- **Le fond du bureau** : NtUserSwitchDesktop peint tout l'écran de cette couleur (journalisé : « win32k: the input
  desktop Winlogon painted, 1280x800 »), en attendant la fenêtre du bureau, que ReactOS montre (co_IntShowDesktop)
  et peint à son WM_PAINT (IntPaintDesktop).
- **L'ancien lanceur** (`launcher.rs`, ancienne architecture) dessinait sur tout l'écran après la phase 1 : il ne le
  fait plus quand win32k a pris l'écran (le thread de démarrage reste au repos) ; sinon, rien ne change.
- **Le banc d'essai** (`xtask/src/screen.rs`) : un scénario peut demander des pixels (`screen = X Y RRGGBB`) ; une
  fois ses marqueurs trouvés, le moniteur de QEMU (sur un socket Unix du répertoire du run) fait une capture
  (`screendump`, `screen.ppm`) où chacun doit avoir sa couleur.

Le scénario `smss` attend le fond `3A6EA5` au centre et aux deux coins de l'écran.

Pas encore : la fenêtre du bureau (classes, fenêtres, WM_PAINT), le fond d'écran (une image), les contextes de
périphérique et les objets GDI, le texte (ADR-013), les autres profondeurs et ROP, le changement de mode
(`bochs-dispi`), le curseur, l'entrée (i8042, thread d'entrée).

Tests : hôte (`win32k::gdi::dib` : couleurs et ordres des octets, rectangle rempli dans la surface, coupé, vide ou
dehors, surface trop courte ; `xtask` : pixels attendus lus, PPM lu et vérifié), scénario `smss` (la capture de
l'écran).

## Étape 21 : la fenêtre du bureau et son WM_PAINT

Chaque bureau a maintenant sa fenêtre, comme dans ReactOS (IntCreateDesktop, par IntCreateWindow), et le fond du
bureau d'entrée est peint par le chemin d'une fenêtre (WM_PAINT) au lieu de l'être directement à NtUserSwitchDesktop :

- **La table des handles USER** (`win32k::handles`), dans la section partagée, où `user32` la lit (ValidateHandle) :
  l'entrée `i` a le handle `0x20 + 2 i`, sa génération dans le mot haut (2 pour une entrée neuve, la suivante pour
  une entrée reprise, comme UserAllocHandle) ; la tête de la table dit combien d'entrées ont servi (`nb_handles`, la
  borne de `user32`), le `SERVERINFO` combien sont prises (`cHandleEntries`).
- **`WND` et `CLS`** (`abi::user::Wnd32`, 0xEC octets ; `Cls32`, 0x60 octets ; assertions de layout) : la fenêtre du
  bureau a son `WND` dans le tas du bureau (et 8 octets de plus : le PID et le TID que DesktopWindowProc y range), sa
  classe aussi (atome `#32769`, `FNID_DESKTOP`, procédure côté serveur, pinceau `COLOR_BACKGROUND + 1`) ; son handle
  est dans la table (`TYPE_WINDOW`), et le `DESKTOPINFO` la désigne (`spwnd`). Ses pointeurs sont des adresses du
  serveur ; `rpdesk` est l'adresse du serveur du tas du bureau (le bureau n'en a pas d'autre sur 32 bits).
- **Sa procédure** (`win32k::window`, comme DesktopWindowProc) tourne dans win32k (`WNDS_SERVERSIDEWINDOWPROC`) :
  WM_PAINT valide la région à mettre à jour (BeginPaint : un rectangle), envoie d'abord WM_ERASEBKGND s'il faut
  effacer le fond, puis finit (EndPaint) ; WM_ERASEBKGND peint le fond (IntPaintDesktop) dans le rectangle de la
  peinture.
- **NtUserSwitchDesktop** cache la fenêtre du bureau d'entrée d'avant et montre la sienne (co_IntShowDesktop) : à la
  taille de l'écran, visible, invalidée entière (fond compris), puis mise à jour aussitôt (UpdateWindow : WM_PAINT
  envoyé directement, en attendant le thread du bureau et les files de messages).

Le scénario `smss` attend « win32k: the desktop window of Winlogon erased (WM_ERASEBKGND), 1280x800 » et le fond
`3A6EA5` sur la capture de l'écran.

Pas encore : les autres fenêtres (NtUserCreateWindowEx), les classes de `user32` et la table des atomes, la fenêtre
des messages du bureau, les files de messages et le thread du bureau, les régions, les contextes de périphérique
(WM_ERASEBKGND reçoit 0), les verrous d'objets USER, la classe du bureau dans le tas partagé (ReactOS l'y met ; elle est
ici dans le tas du bureau, où `user32` la trouve aussi).

Tests : hôte (`win32k::handles` : handles, index et générations, entrées reprises, génération qui reboucle ;
`win32k::window` : rectangles invalidés réunis dans la zone cliente, BeginPaint qui valide et dit s'il faut effacer ;
`Rect::union`), `desktop_self_test` (la fenêtre du bureau vue comme `user32` la voit : `spwnd`, son `WND` dans la vue
du processus avec son handle, son style, son fnid et sa classe `#32769`, l'entrée de son handle dans la section
partagée et `nb_handles` ; montrée puis cachée ; son handle rendu avec son bureau), scénario `smss` (la capture).

## Étape 22 : les files de messages

Chaque thread GUI a sa file de messages (`win32k::queue`, dans son `THREADINFO`), comme dans ReactOS
(MsqCreateMessageQueue à la création du thread GUI) :

| Service | Ce qu'il fait |
|---|---|
| NtUserPostThreadMessage | le message, à la fin de la file du thread nommé par son TID (un thread GUI), daté du compte de ticks ; FALSE pour un message qui porte un pointeur (`ERROR_MESSAGE_SYNC_ONLY` : la table `message_pointer_flags` de ReactOS, ses valeurs tirées de `winuser.h` et `undocuser.h`) ou un TID sans thread (`ERROR_INVALID_PARAMETER`) |
| NtUserPostMessage | sans fenêtre : au thread courant ; à toutes les fenêtres (`HWND_BROADCAST`) : à aucune encore (aucune fenêtre n'a de thread) ; à une fenêtre : pas encore (`ERROR_INVALID_WINDOW_HANDLE`, journalisé une fois) |
| NtUserPeekMessage | le premier message que demandent la fenêtre (0 : tous ; -1 : ceux du thread ; sinon cette fenêtre seule) et l'intervalle, sorti avec `PM_REMOVE` ; WM_QUIT une fois les messages postés sortis ; `ERROR_INVALID_FLAGS` pour un drapeau inconnu (PM_BADMSGFLAGS) |
| NtUserGetMessage | de même, sorti ; attend sinon qu'il en arrive un (un événement de synchronisation par file, une attente du mode utilisateur que la fin du thread interrompt) ; FALSE pour WM_QUIT, et pour un intervalle au-delà de `WM_MAXIMUM` (`ERROR_INVALID_PARAMETER`) |
| NtUserWaitMessage | attend un message s'il n'y en a pas |
| NtUserCallOneParam | `ONEPARAM_ROUTINE_POSTQUITMESSAGE` (`0x33`) : WM_QUIT avec son code ; `ONEPARAM_ROUTINE_GETQUEUESTATUS` (`0x2b`) : `(fsChangeBits & flags) \| (fsWakeBits & flags) << 16`, les bits de changement demandés effacés ; une autre routine rend 0 et `ERROR_CALL_NOT_IMPLEMENTED`, journalisée une fois |

Les bits de réveil et de changement d'une file (`QS_POSTMESSAGE | QS_ALLPOSTMESSAGE` tant qu'un message posté ou WM_QUIT
attend) sont reportés dans le `CLIENTTHREADINFO` du thread, dans le tas de son bureau, où `user32` les lit ; un thread
qui change de bureau y retrouve ceux de sa file.

Pas encore : les messages envoyés (SendMessage entre threads, et vers une procédure du client : KeUserModeCallback),
les messages postés à une fenêtre, les entrées (clavier, souris, thread d'entrée), WM_PAINT et WM_TIMER synthétisés,
les crochets, le filtre par fenêtre fille, la position du curseur (`pt` est nul), MsgWaitForMultipleObjects.

**NtUserCreateWindowEx** attend deux préalables : la création d'une fenêtre envoie WM_GETMINMAXINFO, WM_NCCREATE,
WM_NCCALCSIZE, WM_CREATE… à sa procédure, qui est dans `user32` pour les classes du client (il faut KeUserModeCallback :
le noyau appelle `user32` par `KiUserCallbackDispatcher`, qui revient par NtCallbackReturn) ; et la classe doit être
enregistrée (NtUserRegisterClassExWOW, la table des atomes d'une station). Le premier est fait à l'étape 23.

Tests : hôte (`win32k::queue` : messages à pointeur, filtres par fenêtre et intervalle, ordre puis WM_QUIT, WM_QUIT
après les messages postés même filtrés, bits de réveil et de changement), `message_queue_self_test` (file vide, messages
postés à soi par TID et sans fenêtre, GetQueueStatus, refus, PeekMessage par intervalle, GetMessage dans l'ordre, WM_QUIT
une fois, une attente réveillée par un autre thread), `desktop_self_test` (les bits de la file dans le
`CLIENTTHREADINFO`, recopiés au changement de bureau, effacés quand le message sort, reportés à un nouveau message).

## Étape 23 : les rappels en mode utilisateur (KeUserModeCallback)

win32k appelle `user32` dans le thread qui lui fait un appel système : c'est ainsi qu'il atteint les procédures de
fenêtre du client, ses crochets, ses chargements de ressources. `user32` met sa table de routines dans
`PEB.KernelCallbackTable` (`apfnDispatch`, à son initialisation, avant son premier appel à win32k), et le noyau passe
par `ntdll!KiUserCallbackDispatcher`, qui appelle la routine de l'index donné ; elle finit par NtCallbackReturn.
La spécification suivie est celle de ReactOS : `ntoskrnl/ke/i386/usercall.c`, `usercall_asm.S`,
`dll/ntdll/dispatch/i386/dispatch.S`.

| Partie | Ce qu'elle fait |
|---|---|
| `ps::callback::user_mode_callback` (KeUserModeCallback) | copie l'argument sous l'ESP de la trame du service (aligné sur 4 octets), puis le cadre du répartiteur : `[0, index, &argument, longueur]` et 8 octets pour son enregistrement SEH ; garde la tête de la liste SEH du TEB (`ExceptionList`) et la remet au retour, sauf après `STATUS_CALLBACK_POP_STACK` ; rend le résultat copié dans le noyau (au plus ce que l'appelant attend), ou le statut d'échec du rappel ; refuse un thread dont la fin est demandée (`STATUS_THREAD_IS_TERMINATING`) |
| `ke::callout::call_user_mode` (KiCallUserMode) | garde le contexte du noyau (`Callout`, dans sa trame) ; la pile initiale du thread (TSS.RSP0, SYSENTER_ESP, et ce que reprend chaque commutation) descend sous ses trames ; le thread part en mode utilisateur par le retour des portes (`hal::callout`, `hal_trap_exit`), avec la trame du service, EIP au répartiteur et ESP sur son cadre |
| NtCallbackReturn, `int 2Bh` (`sys::callback`, `sys::gates`) | `ke::callout::callback_return` : la pile initiale et le rappel englobant redeviennent ceux d'avant, et le thread reprend dans `call_user_mode` ; les trames de l'appel sont abandonnées ; sans rappel en cours, `STATUS_NO_CALLBACK_ACTIVE` ; avec `STATUS_CALLBACK_POP_STACK` (une exception déroulée au-delà du répartiteur), la trame du service reprend l'état utilisateur de l'appel (FS, EDI, ESI, EBX, EBP, EIP, CS, EFLAGS, ESP, SS) |
| `mm::kstack::grow` (MmGrowKernelStack) | la pile noyau grandit en place, dans la réserve de son emplacement, pour garder 16 Kio libres sous chaque rappel, jusqu'à 72 Kio (`STATUS_STACK_OVERFLOW` au-delà) ; ses pages sont rendues à la fin du thread |

Les rappels s'emboîtent : un rappel peut faire des appels système, et un appel système un autre rappel. Le thread
peut être préempté en mode utilisateur pendant un rappel : les interruptions arrivent sur la pile initiale du rappel.

Deux rappels de win32k (`win32k::callback`, index de `u32cb.h`) :

| Rappel | Quand |
|---|---|
| ClientThreadSetup (7) | un thread client (ni du système ni de `csrss`) devient un thread GUI, comme à la fin d'InitThreadCallback |
| GetCharsetInfo (9) | une disposition de clavier est chargée : `TranslateCharsetInfo(TCI_SRCLOCALE)` de `gdi32` donne le jeu de caractères, la page de code et la signature de police de sa langue (le KLID) ; s'il échoue, ANSI_CHARSET, FS_LATIN1 et CP_ACP, journalisé |

Dans le scénario `smss`, `winlogon` fait les deux, avec les vrais `ntdll`, `user32`, `gdi32` et `kernel32` de
ReactOS : son thread est préparé par ClientThreadSetup, et `00000409` reçoit le jeu 0, la page de code 1252 et la
signature 0x1 (FS_LATIN1) ; NtCallbackReturn est appelé deux fois (par SYSENTER sur Intel). `winlogon` s'arrête
toujours à son serveur RPC.

Écarts et limites :
- Un thread qui se termine pendant un rappel le fait sur la pile du rappel, comme NT : les trames des rappels en cours
  sont abandonnées, sans que ce qu'elles possèdent soit rendu. Les appelants ne tiennent ni verrou ni objet à rendre
  pendant un rappel (NtUserLoadKeyboardLayoutEx lâche son processus et son `PROCESSINFO` avant).
- Un APC utilisateur en attente n'est pas livré à l'entrée du rappel, mais au retour suivant vers le mode utilisateur.
- Les appels GDI en lot du TEB (`GdiBatchCount`) ne sont pas exécutés après un rappel (GDI n'a pas de lots) :
  journalisé une fois.
- Un ClientThreadSetup qui échoue laisse le thread converti (ReactOS défait la conversion).
- La pile noyau ne rapetisse pas après un rappel.

Tests : hôte (`ke::callout` : la trame sous la pile initiale, ce que prend `STATUS_CALLBACK_POP_STACK` ;
`ps::callback` : la pile utilisateur du rappel, le cadre du répartiteur ; `mm::kstack` : croissance en place jusqu'à
la limite ; `win32k::keyboard` : le KLID en LCID, la réponse de GetCharsetInfo et ses valeurs par défaut ;
`abi::user` : `GET_CHARSET_INFO`) ; `user_callback_self_test` (smoke, sur les deux CPU : 8 rappels emboîtés, par un
répartiteur du programme, qui reçoivent leur argument, restent 50 ms en mode utilisateur, font un appel système,
reviennent par `int 2Bh` et NtCallbackReturn, le dernier en échec ; ESP, EBX, ESI, EDI, EBP et la liste SEH du
programme retrouvés ; la pile noyau agrandie) ; `kernel_stack_self_test` (croissance, pages remises à zéro et
rendues) ; le scénario `smss` (les deux rappels de `winlogon`). Mutations : RSP0 ou SYSENTER_ESP non déplacés, pile
initiale non gardée par le thread, liste SEH non remise, pile agrandie oubliée, pages non remises à zéro,
résultat non copié, statut ignoré, rappel ClientThreadSetup absent, mauvais index : toutes détectées.

## Étape 24 : les tubes nommés (NPFS) ; `winlogon` démarre son serveur RPC

`winlogon` démarre son serveur RPC (`StartRpcServer`, `rpcserver.c`) : `RpcServerUseProtseqEpW("ncacn_np",
"\pipe\winreg")`, puis `RpcServerListen(1, 20, TRUE)`. Le transport `ncacn_np` de `rpcrt4` (`rpc_transport.c`) crée le
tube par `CreateNamedPipeA` (`\\.\pipe\winreg`, `PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED`, type et lecture en mode
message, instances sans limite, avec un descripteur de sécurité), et son thread serveur (`RPCRT4_server_thread`) met
l'instance à l'écoute par NtFsControlFile(FSCTL_PIPE_LISTEN) avec un événement, puis attend (WaitForMultipleObjectsEx).
Le client (`rpcrt4_conn_open_pipe`) attend une instance (`WaitNamedPipeA`), ouvre le tube et passe en mode message
(`SetNamedPipeHandleState`) ; lectures et écritures sont des NtReadFile et NtWriteFile avec un événement ;
l'annulation est NtCancelIoFile.

Il faut donc le système de fichiers des tubes nommés d'Io. La spécification suivie est le pilote de ReactOS 0.4.16
(`drivers/filesystems/npfs` : `create.c`, `statesup.c`, `fsctrl.c`, `read.c`, `readsup.c`, `write.c`, `writesup.c`,
`datasup.c`, `fileinfo.c`, `waitsup.c`) et `kernel32` (`client/file/npipe.c`, `rw.c`, `iocompl.c`), sans en porter le
code.

| Partie | Ce qu'elle fait |
|---|---|
| `io::npfs` (NPFS) | `\Device\NamedPipe`, créé au démarrage (`io::mount_named_pipes`) ; `\??\PIPE` vient de `smss` (`DOS Devices` de la ruche SYSTEM), comme sous XP. Un tube (FCB) : nom sans casse, type, configuration (tirée du partage de sa création : entrant, sortant, les deux), instances au plus, délai par défaut. Une instance (CCB) : état (déconnectée, à l'écoute, connectée, en fermeture), modes de lecture et de fin par extrémité, deux files de données avec leur quota, écoutes en attente. Tout NPFS sous un verrou ; les demandes finies sous le verrou le sont une fois le verrou rendu (NpCompleteDeferredIrps) |
| `io::npfs::queue` | la file d'un sens : des lectures en attente, ou des données écrites (une entrée par écriture : un message, ou un morceau du flux) ; une lecture en mode message prend au plus un message (`STATUS_BUFFER_OVERFLOW` et le reste en tête s'il ne tient pas), en mode octet d'une entrée à l'autre ; une écriture au-delà du quota attend que des lectures le libèrent (ses données sont déjà dans la file) ; les lectures en attente prennent les écritures d'abord |
| `io::npfs::PipeFile` | l'objet fichier d'un tube, du type `File` : la procédure *parse* de `\Device\NamedPipe` en crée un pour la racine (`\`) ou pour un nom, que l'ouverture ou la création lie à son instance (comme IRP_MJ_CREATE et IRP_MJ_CREATE_NAMED_PIPE) ; son événement (FILE_OBJECT.Event) ; la procédure de fermeture du type `File` fait sa fermeture au dernier handle (IRP_MJ_CLEANUP : NpSetClosingPipeState) |
| `io::request` | une demande en attente (`Request`, ce que garde un IRP en attente) et sa fin (`Requester::deliver`, IopCompleteRequest), hors des verrous du pilote |
| NtCreateNamedPipeFile (`sys::pipe`) | une instance du tube, créé s'il n'existe pas (FILE_CREATED, FILE_OPENED) ; le handle est son extrémité serveur, à l'écoute. Refus : un tube neuf sans délai par défaut négatif ou sans instance, `FILE_OPEN` d'un tube absent, un partage qui n'est pas une configuration, le mode message d'un tube d'octets ; toutes les instances prises (`STATUS_INSTANCE_NOT_AVAILABLE`) ; `FILE_CREATE` ou un autre partage pour un tube qui existe (`STATUS_ACCESS_DENIED`) ; un nom hors de NPFS (`STATUS_INVALID_DEVICE_REQUEST`). Le descripteur de sécurité est ignoré |
| NtCreateFile, NtOpenFile d'un tube | la racine, ou un client connecté à la première instance à l'écoute (ses écoutes finissent) ; refus : tube absent (`STATUS_OBJECT_NAME_NOT_FOUND`), aucune instance à l'écoute (`STATUS_PIPE_NOT_AVAILABLE`), lire un tube entrant ou écrire un tube sortant (`STATUS_ACCESS_DENIED`) |
| NtReadFile, NtWriteFile d'un tube | lire ce que l'autre extrémité a écrit, ou attendre ; sans données, `STATUS_PIPE_BROKEN` si l'autre extrémité est fermée, `STATUS_PIPE_EMPTY` en mode non bloquant ; écrire (`STATUS_PIPE_CLOSING` si l'autre extrémité est fermée) ; en mode non bloquant, un message qui ne tient pas dans le quota n'est pas écrit |
| NtFsControlFile | FSCTL_PIPE_LISTEN (le serveur attend un client ; `STATUS_PIPE_CONNECTED` s'il est là), FSCTL_PIPE_DISCONNECT (les données et les demandes des deux sens finissent, le client perd l'instance), FSCTL_PIPE_PEEK (l'état, les octets à lire, les messages et la longueur du premier, des données sans les prendre), FSCTL_PIPE_WAIT sur la racine (une instance du tube à l'écoute, ou l'attendre jusqu'au délai : `STATUS_IO_TIMEOUT`) ; le droit que demande un contrôle se vérifie sur le handle |
| NtQueryInformationFile, NtSetInformationFile | FilePipeInformation (modes de lecture et de fin ; `STATUS_PIPE_BUSY` pour le mode non bloquant pendant que des demandes attendent), FilePipeLocalInformation (le tube et l'instance vus d'une extrémité), FileNameInformation (`\nom`) ; NtQueryVolumeInformationFile : FileFsDeviceInformation (FILE_DEVICE_NAMED_PIPE, le FILE_TYPE_PIPE de GetFileType) |
| NtCancelIoFile | les demandes du thread courant sur ce fichier finissent avec `STATUS_CANCELLED` |
| NtWaitForSingleObject, NtWaitForMultipleObjects | un fichier de tube s'attend par son événement : remis à zéro au début de chaque E/S, signalé à sa fin (ce qu'attendent ConnectNamedPipe, ReadFile et GetOverlappedResult de `kernel32` sans événement) |

Une E/S de tube finit tout de suite, ou attend. Sur un fichier synchrone, le thread attend sa fin dans l'appel, puis
écrit lui-même les données et le bloc d'état. Sur un fichier asynchrone (`FILE_FLAG_OVERLAPPED`), l'appel rend
`STATUS_PENDING` ; le thread qui termine la demande (celui qui écrit, se connecte, ferme…) écrit les données et le bloc
d'état dans le processus du demandeur (`EProcess::write_memory`, MmCopyVirtualMemory), signale son événement et celui du
fichier et met en file son APC de fin, comme IopCompleteRequest. Une erreur rendue tout de suite n'écrit ni le bloc
d'état ni l'événement, comme sous NT.

Dans le scénario `smss`, `rpcrt4` crée `\pipe\winreg` (NtCreateNamedPipeFile : `STATUS_SUCCESS`), son thread serveur
l'écoute (NtFsControlFile : `STATUS_PENDING`), et `winlogon` passe à `StartServicesManager` : `services.exe` n'est pas
sur le disque (« WL: Failed to execute services (error 2) », « WL: Could not start services.exe »), et `winlogon`
finit. NtSetInformationThread(`ThreadNameInformation`, 0x26, SetThreadDescription du thread serveur de `rpcrt4`) et
NtIsProcessInJob manquent, tolérés.

Écarts et limites :
- La sécurité des tubes : le descripteur de leur création est ignoré, le contrôle d'accès d'un client est celui du
  type `File` (ADR-011) ; FSCTL_PIPE_IMPERSONATE (ImpersonateNamedPipeClient, que le serveur de `rpcrt4` appellera pour
  chaque appel) manque, comme FSCTL_PIPE_TRANSCEIVE (TransactNamedPipe), les événements de tube
  (FSCTL_PIPE_ASSIGN_EVENT, FSCTL_PIPE_QUERY_EVENT) et le processus client : `STATUS_NOT_IMPLEMENTED`, journalisé une
  fois.
- FSCTL_PIPE_WAIT attend dans l'appel, même sur un fichier asynchrone ; une attente synchrone ne s'interrompt pas pour
  une APC (`FILE_SYNCHRONOUS_IO_ALERT` vaut `NONALERT`) ; pas de ports de complétion.
- La fin d'un thread n'annule pas ses demandes (IoCancelThreadIo) : une demande dont le thread se termine est
  abandonnée (une lecture ne prend plus de données), finie sans rien livrer.
- Les lectures en attente ne prennent pas de quota (NPFS les compte) ; ce qu'une extrémité peut écrire
  (`WriteQuotaAvailable`) est le quota libre du sens où elle écrit (ReactOS prend, pour le client, le quota de l'autre
  sens).
- Ni énumération de la racine (NtQueryDirectoryFile), ni notifications, ni alias de noms, ni FileBasic,
  FileStandard ou FileAllInformation d'un tube.

Tests : hôte (`abi::pipe` : FILE_PIPE_WAIT_FOR_BUFFER lu, refusé court ou avec son nom au-delà, les informations ;
`io::npfs`, 22 tests : création et limites, paramètres refusés, connexion qui finit l'écoute, configurations, écoute
non bloquante, messages lus un à un et en partie, lecteur d'octets d'un message à l'autre, lecture en attente servie
par une écriture et message vide, demande abandonnée, écriture au-delà du quota qui attend, message non bloquant qui ne
tient pas, aperçu, fermetures du client puis du serveur, déconnexion et nouvelle écoute, attente d'instance servie,
échue, ou dont le tube disparaît, annulation par thread et fichier, modes, informations locales, noms relatifs à la
racine) ; le scénario `pipes` (`tests/native/pipe1.c`, à la place de `winlogon.exe`, AMD et Intel) : un tube de messages
au serveur asynchrone comme celui de `rpcrt4` (écoute en attente servie par le client, aperçu, lecture en partie
`ERROR_MORE_DATA`, lecture en attente finie par la fermeture du client `ERROR_BROKEN_PIPE`, GetNamedPipeInfo,
déconnexion, écoute annulée `ERROR_OPERATION_ABORTED`, deux instances au plus et tube occupé `ERROR_PIPE_BUSY`,
attente échue `ERROR_SEM_TIMEOUT`, tube disparu avec sa dernière instance), puis un tube anonyme (CreatePipe : lecture
de deux écritures, écriture au-delà du quota qui attend les lectures, lecture qui attend une écriture, tube cassé) ;
le scénario `smss` (le serveur RPC de `winlogon`).

## Étape 25 : `services.exe` et `lsass.exe` ; `winlogon` va jusqu'à sa fenêtre SAS

Après son serveur RPC, `winlogon` (`winlogon.c`) lance `services.exe` (StartServicesManager), puis `lsass.exe`
(StartLsass), attend LSA (WaitForLsass), charge ses DLL de notification, sa GINA (`msgina`), crée sa fenêtre SAS
(InitializeSAS) et entre dans sa boucle. `xtask` met sur le disque `services.exe`, `lsass.exe`, les ruches SECURITY et
SAM, et deux DLL chargées par leur nom, hors de la fermeture des imports : `msv1_0.dll` (le paquet d'authentification
de `lsasrv`, `Lsa\Authentication Packages`) et `msgina.dll`.

| Partie | Ce qu'elle fait | Demandé par |
|---|---|---|
| `ntoskrnl::srm` (Se) | au démarrage, le répertoire `\Security` et son événement `LSA_AUTHENTICATION_INITIALIZED` (SepInitializationPhase1), le port de connexion `\SeRmCommandPort` et l'événement `\SeLsaInitEvent` (SeRmInitPhase1), et un thread noyau qui attend l'événement, accepte la connexion de `lsass`, se connecte en retour à son `\SeLsaCommandPort`, puis sert RmCreateLogonSession, RmDeleteLogonSession et RmAuditSetCommand (`abi::security::RmRequest`) et répond à chacune | `lsasrv` (LsapRmInitializeServer, StartAuthenticationPort) |
| `se::logon` | les sessions de logon du moniteur (celles de LocalSystem et de l'utilisateur anonyme dès le démarrage ; `STATUS_LOGON_SESSION_EXISTS`, `STATUS_NO_SUCH_LOGON_SESSION`) et l'état de l'audit | le serveur du SRM |
| `ps::ethread::reserve_system_thread_id`, `client_exists` | un TID du processus System pour le thread du SRM, qui n'a pas d'objet thread : Lpc le reconnaît comme client (`check_client` de NtAcceptConnectPort et NtReplyPort) | `lsass` (NtAcceptConnectPort de la connexion du noyau) |
| ruches SECURITY et SAM (`userland::mount_machine_hives`) | montées comme SOFTWARE sous `\REGISTRY\MACHINE` | `lsasrv` (LsapOpenServiceKey), `samsrv` |
| NtQueryInformationThread(`ThreadAmILastThread`) | 1 si le processus du thread n'a pas d'autre thread vivant | `kernel32` (ExitThread) |
| NtSetDefaultLocale | les paramètres régionaux du système : validés (`Nls\Locale` connaît le LCID et son groupe de langues est installé, ExpValidateNlsLocaleId), écrits dans `Nls\Language\Default`, puis gardés par `ex::locale` ; 0 les relit ; ceux de l'utilisateur (`HKCU`, pas monté) : `STATUS_OBJECT_NAME_NOT_FOUND` | `winlogon` (SetDefaultLanguage, dans InitializeSAS) |
| NtUserSetLogonNotifyWindow (`win32k::logon`) | la fenêtre SAS du processus de logon (hwndSAS), où USER postera WM_LOGONNOTIFY ; FALSE pour une fenêtre inconnue ou un autre processus (`ERROR_ACCESS_DENIED`) | `winlogon` (InitializeSAS) |

`services.exe` se croit sur le LiveCD (la ruche SYSTEM épinglée a `Setup\CmdLine` avec `-mini`), crée son serveur RPC
(`\pipe\ntsvcs`) et lance ses services automatiques : leurs images (`svchost.exe`, `eventlog.exe`, `rpcss.exe`…) ne sont
pas sur le disque (« Starting 'DcomLaunch' failed with error 2 »), toléré. `lsass` se connecte au moniteur de
références, ouvre SECURITY, charge `msv1_0`, crée `\LsaAuthenticationPort` et son serveur RPC (`\pipe\lsarpc`) ; son
pool de threads demande NtCreateIoCompletion (manque : « couldn't queue work item »). `winlogon` charge `msgina`, crée
sa fenêtre SAS, en fait la fenêtre de notification du logon, fixe les paramètres régionaux du système, change de bureau
et reste dans sa boucle ; il va ensuite plus loin par USER : un message envoyé à la fenêtre d'un autre thread avec un
tampon du noyau (« message 0x46 with a kernel buffer sent to another thread: not yet », la fenêtre d'état de
`msgina`), M6. Manquent aussi, tolérés : `sfc.dll`, `wlnotify.dll`, `shsvcs.dll` (DLL de notification),
NtQueryDirectoryObject, NtQuerySystemInformation(0x2C), NtCreateIoCompletion, NtUserDestroyWindow,
NtUserSystemParametersInfo(0x100A), NtApphelpCacheControl, NtUserNotifyProcessCreate.

Vu en chemin, un défaut du noyau : l'horloge écrivait la page `KUSER_SHARED_DATA` de l'ancien chargeur par son adresse
utilisateur (`0x7FFE0000`), valable dans l'espace du système seulement ; `services.exe` et `lsass.exe` survivent à la
sonde (ce sont des petits-enfants de `smss`), et quand un de leurs threads était courant à un tick, l'écriture tombait
sur leur page en lecture seule, à CLOCK_LEVEL : STOP 0x0A. L'horloge écrit maintenant cette page par son alias du noyau
(`set_legacy_shared_data` : la page physique par le HHDM).

Écarts et limites : le thread du SRM n'est pas un thread de Ps (pas de PsCreateSystemThread) ; le noyau ne partage pas
de section avec `lsass` et ne lui envoie rien (fin de session, audit) ; la fin de `lsass` n'est pas vue ; les sessions
de logon ne comptent pas les jetons qui les tiennent ; la sonde ne termine pas les petits-enfants de `smss`.

Tests : hôte (`abi::security` : RmRequest lu de ses données, résultat posé à sa place ; `se::logon` : sessions connues,
création et suppression, audit) ; le scénario `smss` (les ruches, le SRM et la connexion de `lsass`, `\pipe\lsarpc`,
`\pipe\ntsvcs`, NtSetDefaultLocale, NtUserSetLogonNotifyWindow, aucun échec de `winlogon` ni de `lsass` ; un STOP y
est interdit, ce qui a révélé le défaut de l'horloge).

## Étape 26 : un tampon du noyau envoyé à la fenêtre d'un autre thread ; `winlogon` et la ruche du LiveCD

Après InitializeSAS, `winlogon` montre puis retire la fenêtre d'état de `msgina` : un SetWindowPos fait par un thread
sur la fenêtre d'un autre fait envoyer par win32k WM_WINDOWPOSCHANGING, dont `lParam` est un WINDOWPOS du noyau, au
thread de la fenêtre. win32k le refusait (« message 0x46 with a kernel buffer sent to another thread: not yet »).

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::sent::send_buffer` | le message emporte une copie du tampon (`SentMessage::with_buffer`) ; le thread de la fenêtre la prend le temps de la procédure et l'emballe vers son mode utilisateur comme pour un envoi à lui-même (`LParam::Buffer`, le rappel de la procédure) ; à la réponse, ce que la procédure y a écrit revient dans le tampon de l'envoyeur, pour un message qui y écrit (WM_WINDOWPOSCHANGING, WM_NCCALCSIZE, WM_GETMINMAXINFO…). ReactOS passe le pointeur du noyau lui-même (co_MsqSendMessage), l'envoyeur attendant ; la copie revient au même |
| `win32k::window::send_message` | vers un autre thread : une valeur par `sent::send`, un tampon par `sent::send_buffer` |

`winlogon` va ensuite au bout de son initialisation, puis lit `Setup\SetupType` : la ruche SYSTEM épinglée est celle du
LiveCD de ReactOS (`SetupType` non nul, `CmdLine` = `setup -mini`). Il lance donc l'installation (RunSetup : un thread
qui passe sur le bureau Default et crée `setup -mini`), au lieu de poster WLX_WM_SAS à sa fenêtre SAS pour le logon ;
`setup.exe` n'est pas sur le disque, le thread revient sur le bureau Winlogon, et `winlogon` attend dans sa boucle des
messages qui ne viennent pas. Le chemin du logon (WlxDisplaySASNotice de `msgina`, `userinit`, `explorer` : le critère
du M6) demande une ruche d'un système installé (`SetupType` = 0) : la couche Mino des ruches (ADR-012, `tools/mkhive`,
qui doit aussi porter l'ouverture de session automatique), à trancher.

Tests : hôte (`win32k::sent` : la copie va au destinataire, revient si la procédure y écrit, reste sinon) ; le scénario
`send-messages` (`tests/native/send1.c` : le thread de travail fait SetWindowPos de W, la fenêtre du thread principal ;
W reçoit WM_WINDOWPOSCHANGING dans son thread, y élargit la fenêtre, et la largeur écrite est prise ; sans le retour du
tampon, W garde sa largeur : mutation détectée) ; le scénario `smss` interdit le refus d'avant.

## Étape 27 : la couche Mino des ruches ; le premier démarrage en mode installation, puis le logon

La décision est l'ADR-023 (proposée) : la couche Mino de l'ADR-012 est `tools/mkhive/mino.inf`, dans la syntaxe des
couches de ReactOS (`boot/bootdata/livecd.inf`), qu'applique `tools/mkhive` aux ruches épinglées quand `xtask` construit
le disque. Elle ramène les ruches du LiveCD à celles d'un système installé (profils sous `Documents and Settings`,
dossiers du shell, ouverture de session automatique d'`Administrator` sans mot de passe, nom `MINO`) et met le premier
démarrage en mode installation : `samsrv` n'y crée les comptes que là (SampIsSetupRunning lit `SetupType`), et
`winlogon` y lance `SYSTEM\Setup\CmdLine`, `minoinit.exe`, qui fait la part d'InstallReactOS dont dépend le logon.

| Partie | Ce qu'elle fait |
|---|---|
| `tools/mkhive` | lit `[DelReg]` puis `[AddReg]` d'une couche (types, « ne pas écraser », « la clé seule », ajout à une `REG_MULTI_SZ`, continuations, guillemets), route chaque ligne vers sa ruche (`HKLM\SYSTEM`…, `HKCU` et `HKU\.DEFAULT` vers DEFAULT, `HKCR`), `CurrentControlSet` vers le jeu de `Select\Current` ; `layered` relit une ruche, l'applique, la réécrit |
| `regf::builder::KeyNode::read` | l'arbre d'une ruche, que `build` réécrit (classes et dates gardées) |
| `xtask` (`userland::layer_hives`) | les ruches que la couche change sont réécrites dans `target/xtask/hives/` et prennent la place des épinglées sur le disque ; DEFAULT y va aussi ; `secur32.dll` (chargé par son nom pour LsaLogonUser) ; `MINOINIT.EXE` dans `WINDOWS\SYSTEM32` |
| `ntoskrnl::userland` | DEFAULT montée en `\REGISTRY\USER\.DEFAULT`, réécrite par NtFlushKey comme les autres ; `smss` reçoit `SystemDrive=C:`, comme ExpLoadInitialProcess le lui donne (sans lui, `%SystemDrive%` restait tel quel dans `userenv`) |
| `tests/native/minoinit.c` | attend `Administrator` dans la SAM (une valeur de `Users\Names`), InitializeProfiles (ordinal 100 de `userenv`), HKU\.DEFAULT réécrite puis copiée en `NTUSER.DAT` de `Default User` (la part de SaveDefaultUserHive), `SetupType` = 0, `SystemSetupInProgress` = 0, `CmdLine` vide, les ruches réécrites, NtShutdownSystem(reboot) ; chaque étape dit son résultat (« [minoinit] … ») |

Ce que le premier démarrage demandait au noyau, dans l'ordre où il s'est arrêté :

1. **Les ports de complétion d'E/S** (`io_manager::completion`, le type `IoCompletion` ; `sys::completion` :
   NtCreateIoCompletion, NtOpenIoCompletion, NtSetIoCompletion, NtRemoveIoCompletion, NtQueryIoCompletion). `samsrv`
   demande le domaine du compte à `lsasrv` (LsaOpenPolicy) par RPC sur `\pipe\lsarpc`, dans le même processus : le
   serveur RPC reçoit la requête, puis la confie au pool de threads de `ntdll` (QueueUserWorkItem), qui crée son
   port de complétion ; sans lui, « couldn't queue work item for worker thread » : la requête est perdue, `samsrv`
   attend sans fin et la SAM reste vide. Les paquets sous un verrou et un sémaphore de Ke qui les compte, comme la
   file d'un port LPC. Pas encore : le nombre de threads concurrents, l'association d'un fichier, l'attente d'un port
   par NtWaitForSingleObject.
2. **`SystemDrive`** dans l'environnement : voir le tableau.
3. **Les répertoires à nom long** (`io::fat::FatVolume::create_directory` : les entrées VFAT et l'alias 8.3 d'un
   répertoire, comme d'un fichier depuis 36b6714) : InitializeProfiles crée `C:\Documents and Settings`.

Au second démarrage, `winlogon` va au logon (WLX_SAS_TYPE_CTRL_ALT_DEL posté, la touche Ctrl+Alt+Del demandée :
NtUserRegisterHotKey, pas encore) ; `msgina` ouvre la session d'`Administrator` (AutoAdminLogon) par LsaLogonUser, qui
demandait **NtAllocateLocallyUniqueId** (fait : `se::allocate_luid`) ; `msv1_0` trouve le compte et son mot de passe vide
dans la SAM, puis `lsasrv` s'arrête à **NtCreateToken** (le jeton de la session : l'utilisateur, ses groupes, ses
privilèges, son DACL par défaut) : la suite, Se.

Vu en chemin : `msgina` montre aussi sa fenêtre de logon, dont le contrôle d'édition de `user32` lève des exceptions
(curseur d'insertion : NtUserCreateCaret, pas encore ; les barres de défilement sont venues depuis, M6, étape 17) ;
`services.exe` parle aux services qu'il lance par FSCTL_PIPE_TRANSCEIVE (TransactNamedPipe, pas encore) ; deux lignes
du journal série pouvaient se couper (corrigé depuis : 4bac731, une ligne en une seule prise du verrou). Le disque de
démarrage a grossi (`secur32.dll` et ses imports) : l'ESP du plan de l'installateur ne le tenait plus, elle
passe à 56 Mio, la cible de test à 128 Mio ([`io-install.md`](io-install.md), « Le plan agrandi »).

Tests : hôte (`regf` : relire l'arbre d'une ruche ; `mkhive` : la lecture, l'application, `mino.inf` sur des ruches
construites et sur les ruches épinglées ; `io` : les paquets d'un port de complétion, un répertoire à nom long et ce
qu'il tient, vérifié par `fsck.vfat`) ; le scénario `logon` (deux démarrages sur le disque système : le premier va
au bout de `minoinit`, avec `SystemDrive` ; le second s'arrête à NtCreateToken) ; `security_self_test`
(NtAllocateLocallyUniqueId : deux LUID neufs) ; `object_manager_self_test` (le type `IoCompletion`).
