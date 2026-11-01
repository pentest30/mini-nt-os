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
