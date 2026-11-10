# M5 — les apitests de ReactOS, le dernier critère

Le dernier critère de sortie du M5 ([05](../05-feuille-de-route.md#m5--mode-console-puis-spike-s2)) : les `rostests`
`ntdll` et `kernel32` (les apitests de ReactOS) dépassent un seuil de réussite fixé au moment du jalon, puis suivi
dans le temps. Le seuil est **50 %** des tests qui tournent (`THRESHOLD`, `xtask/src/rostests.rs`) ; le suivi se fait
par un plancher par scénario, qui ne baisse pas.

## Le banc

- **Les sources** : `cargo xtask rostests-fetch` clone, par Git et en éparse, l'arbre de ReactOS 0.4.16 (la même
  version que l'espace utilisateur épinglé) dans `third_party/reactos-0.4.16/` (ignoré par Git) : les apitests
  `ntdll` et `kernel32`, leurs en-têtes, le SDK (`psdk`, `ndk`, `xdk`, `wine`…) et PSEH. Sans cet arbre, les
  scénarios sont sautés, comme sans MinGW.
- **La compilation** (`cargo xtask rostests-build`, aussi faite par `cargo xtask test`) : MinGW i686, contre une
  copie du PSDK où `winnt.h`, que ReactOS génère à sa construction, est généré par `xtask` (le gabarit
  `xdk/winnt.template.h` et ses huit en-têtes XDK, directives `$if`/`$define` évaluées pour le PSDK i386) ; la SAL
  neutralisée (`no_sal2.h`), les macros de test que `wine/test.h` ne définit qu'en `STANDALONE`
  (`xtask/rostests-src/apitest-macros.h`), PSEH en bibliothèque statique. Un test qui ne compile pas est écarté et
  listé ; la liste des tests est relue des symboles des objets compilés (le nom d'un `START_TEST` peut différer de
  celui de son fichier).
- **Deux programmes par module** : le **coureur** (`NTAPIRUN.EXE`, `K32APIRUN.EXE` ; sous-système console, le `main`
  de `wine/test.h` : `argv[1]` est le test, le code de sortie son nombre d'échecs, todo compris) et le **pilote**
  (`NTAPITST.EXE`, `K32APITST.EXE` ; `xtask/rostests-src/testdriver.c`, sous-système WINDOWS), commande initiale de
  `smss` à la place de winlogon. Comme winlogon (et comme `CONSOLE1.EXE`), le pilote s'inscrit comme processus de
  logon et prend `WinSta0\Default` ; puis il lance chaque test dans un coureur, **détaché** (`DETACHED_PROCESS` :
  pas de console, donc pas de fenêtre de `consrv` par test), sur ce bureau, sa sortie standard et d'erreur dans
  `C:\APITEST.OUT`. Il attend le coureur 20 s au plus (un test qui pend coûte son délai, pas le banc), puis relaie
  sa sortie et son verdict par `DbgPrint` :

  ```text
  [apitest] | LdrFindResource_U.c:24: Test failed: Status = c000008a, expected 0
  [apitest] | LdrFindResource_U: 1 tests executed (0 marked as todo, 1 failure), 0 skipped.
  [apitest] LdrFindResource_U: FAIL (exit 1)
  [apitest] TOTALS: tests=85 failures=… skipped=0
  ```

  Un test passe quand son coureur rend 0. Un code de sortie qui est un statut NT (`c0000005`, `c0000142`…) dit que
  le coureur est mort avant son bilan.
- **Les scénarios** : `rostests` (ntdll) et `rostests-kernel32` (un module par démarrage : une seule commande
  initiale). L'hôte lit le bilan et le juge (`rostests::judge`) : sous `apitests-floor`, le scénario échoue ; la part
  des tests qui passent est comparée au seuil du M5 et rapportée, sans faire échouer. Quand plus de tests passent,
  le rapport le dit (« le plancher peut monter à N ») : monter le plancher dans `scenario.txt` fait partie du
  commit qui les fait passer.

## Ce que le banc a mis au jour

Trois défauts empêchaient le banc de mesurer quoi que ce soit (le premier bilan était de 0 sur 84) : deux du banc,
un du noyau.

### Les clients morts de `csrss` ne partaient pas (Ps, Lpc)

Le premier bilan du banc était de 0 sur 84, et à partir du 45ᵉ test, CreateProcess échouait
(`ERROR_NO_SYSTEM_RESOURCES`, « Creating the main thread failed: c000009a ») : la table des threads de Ke (64
emplacements) était pleine. Un thread fini garde son emplacement tant que son objet thread est référencé, et
`csrss` gardait ses handles sur chaque processus et thread de ses clients : il apprend leur mort par un message
`LPC_CLIENT_DIED` (CsrApiRequestThread : CsrDestroyThread, puis CsrDestroyProcess au dernier thread, qui ferment
ses handles), que le noyau n'envoyait pas.

PspExitThread envoie ce message à chaque port de fin du thread (NtRegisterThreadTerminatePort), ou, s'il n'en a pas,
au port d'exception de son processus — celui que `csrss` pose sur chaque processus de Win32 (CsrCreateProcess,
`ProcessExceptionPort`). Le message (CLIENT_DIED_MSG) porte le CLIENT_ID du thread et son heure de création, que
`csrss` compare à celle qu'il a lue (ThreadTimes) ; sa sorte reste `LPC_CLIENT_DIED`, sans
`LPC_KERNELMODE_MESSAGE`, que `csrss` ne reconnaîtrait pas. C'est fait : `ps::exit` (`notify_client_died`) et
`lpc::request_port` (LpcRequestPort pour une sorte de message donnée). Tests : `lpc` (hôte), et
`process_settings_self_test` (scénario `smoke`) : les deux threads d'un processus au port d'exception posé
annoncent leur fin sur ce port ; vérifié par mutation (sans l'appel, le scénario s'arrête sur l'assertion).

Pas encore : `LPC_PORT_CLOSED` (le dernier handle d'un port client fermé), la liste de plusieurs ports de fin par
thread (le dernier enregistré remplace le précédent).

### Les coureurs n'avaient pas de console

Les coureurs, programmes console, mouraient à leur initialisation (`c0000142`, « Failed to connect to the Console
Server ») : `consrv` ne pouvait pas leur créer de console, faute de station. Le pilote ne prenait pas de bureau, et
le chemin de bureau de ses fils ne nommait pas de station (« a desktop path without a window station: not yet »,
`win32k::startup`, IntResolveDesktop). Le pilote fait maintenant ce que fait winlogon (et `CONSOLE1.EXE`), et ses
fils partent détachés, sans console. La station par défaut d'un chemin qui n'en nomme pas reste à faire dans
win32k ; un vrai système passe toujours `WinSta0\Default` (winlogon, puis l'héritage des paramètres).

### PSEH sans pointeur de trame (le banc)

Neuf tests mouraient sans rien écrire (`c0000027`, STATUS_UNWIND, dans `Return246` de PSEH) : chaque fois qu'un
`__except` attrapait une exception. Le `_SEH2GlobalUnwind` de PSEH2 (`framebased-gcchack.c`) pousse quatre mots
puis la trame cible, un opérande `"g"` que GCC adressait par ESP (le banc compilait sans pointeur de trame) : la
trame passée à RtlUnwind était fausse, RtlUnwind parcourait toute la chaîne sans la trouver et levait son propre
enregistrement STATUS_UNWIND. ReactOS compile tout code i386 avec `-fno-optimize-sibling-calls
-fno-omit-frame-pointer -mstackrealign` (`sdk/cmake/gcc.cmake`) ; le banc aussi maintenant (`I386_FLAGS`), PSEH
compris (refaite à chaque construction). La trame cible est `0xc(%ebp)`, l'argument du gestionnaire.

## Mesures

Le 2026-11-10, QEMU, processeur par défaut (chemin `int 2Eh`) ; ce sont les planchers des scénarios.

| Module | Lancés | Écartés | Passent | Part | Plancher |
|---|---:|---:|---:|---:|---:|
| ntdll | 84 | 23 | 33 | 39 % | 33 |
| kernel32 | 29 | 12 | 11 | 38 % | 11 |
| **Ensemble** | **113** | 35 | **44** | **39 %** | |

Le seuil du M5 (50 %) n'est pas atteint : il manque 9 tests en ntdll (42 sur 84), 4 en kernel32 (15 sur 29),
13 sur l'ensemble (57 sur 113).

- **ntdll, passent** : DllLoadNotification, LdrLoadDll, NtAcceptConnectPort, NtAccessCheck,
  NtAccessCheckByTypeResultList, NtAdjustPrivilegesToken, NtCreateFile, NtCreateThread, NtDuplicateObject, NtMutant,
  NtOpenProcessToken, NtSetInformationFile, RtlCopyMappedMemory, RtlDebugInformation, RtlDeleteAce,
  RtlDetermineDosPathNameType, RtlFirstFreeAce, RtlGetFullPathName_U, RtlGetFullPathName_Ustr,
  RtlGetLengthWithoutLastFullDosOrNtPathElement, RtlGetLengthWithoutTrailingPathSeperators,
  RtlGetLongestNtPathLength, RtlGetProcessHeaps, RtlHandle, RtlImageDirectoryEntryToData, RtlImageRvaToVa, RtlLocale,
  RtlMultipleAllocateHeap, RtlRemovePrivileges, RtlUnhandledExceptionFilter, RtlUnicodeStringToAnsiString,
  RtlValidateUnicodeString, RtlpEnsureBufferSize.
- **ntdll, meurent ou pendent** (le reste échoue sur des assertions, détaillées dans le journal) : NtContinue,
  RtlGenerate8dot3Name, RtlUnicodeStringToCountedOemString, RtlxUnicodeStringToAnsiSize, RtlxUnicodeStringToOemSize
  (`c0000005`) ; NtApphelpCacheControl, NtProtectVirtualMemory, RtlReAllocateHeap (20 s dépassées).
- **kernel32, passent** : ConsoleCP, GetCurrentDirectory, GetLocaleInfo, GetVolumeInformation, InitOnce,
  SetCurrentDirectory, SystemFirmware, WideCharToMultiByte, interlck, lstrcpynW, lstrlen.
- **kernel32, meurent ou pendent** : LoadLibraryExW (`c0000005`) ; QueueUserAPC, TerminateProcess (20 s
  dépassées).
- **Écartés** (ne compilent pas avec MinGW : écarts de déclarations entre MinGW et le SDK de ReactOS, `swprintf`,
  `ok_size_t`…) : ntdll LdrEnumResources, NtDeleteKey, NtLoadUnloadKey, NtMapViewOfSection,
  NtQueryInformationProcess, NtQueryInformationThread, NtQueryInformationToken, NtQueryKey, NtSetInformationProcess,
  NtSetInformationThread, RtlBitmap, RtlComputePrivatizedDllName_U, RtlCriticalSection, RtlDoesFileExists,
  RtlDosPathNameToNtPathName_U, RtlDosSearchPath_U, RtlMemoryStream, RtlpApplyLengthFunction, StackOverflow,
  UserModeException, load_notifications, probelib, sprintf ; kernel32 CreateProcess, DeviceIoControl, FLS,
  FormatMessage, GetCPInfo, GetFinalPathNameByHandle, GetModuleFileName, LCMapString, LocaleNameToLCID,
  MultiByteToWideChar, TunnelCache, UEFIFirmware.

La suite, vers le seuil : les huit tests qui meurent ou pendent d'abord (un plantage cache tout ce que le test
vérifiait après), puis les assertions, test par test, en montant le plancher à chaque commit qui en fait passer ;
et les écartés, qui comptent dans le suivi.

## Reprendre

```bash
cargo xtask rostests-fetch                                   # une fois : l'arbre 0.4.16, par Git
cargo xtask test --boot --scenario rostests                  # ntdll ; journal dans target/xtask/boot/rostests-default/
cargo xtask test --boot --scenario rostests-kernel32         # kernel32
```

- Lire un bilan : `grep -a "\[apitest\]" target/xtask/boot/rostests-default/serial.log`.
- Un test seul, à la main : le coureur prend son nom (`NTAPIRUN.EXE NtReadFile`) ; `--list` donne la liste.
- Sous Windows, ajouter MinGW au `PATH` (`/c/msys64/mingw32/bin`) et donner QEMU par la variable `QEMU`.
