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

