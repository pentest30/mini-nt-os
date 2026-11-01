# M5 : `smss` lance `csrss.exe`

Observations du début du M5 ([05](../05-feuille-de-route.md#m5--mode-console-puis-spike-s2)) : ce que fait le
`smss.exe` de ReactOS 0.4.16 quand `csrss.exe` et ses DLL serveur sont sur le disque, puis ce que fait `csrss.exe`.
La sonde est celle du M4 ([`m4-smss.md`](m4-smss.md)), scénario `smss` ; à mettre à jour à chaque étape du M5.

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
