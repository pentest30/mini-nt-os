# Spike S1 : le `ntdll` de ReactOS et un programme natif

Observations du spike S1 (ADR-002, [05](../05-feuille-de-route.md#m3--frontière-nt-puis-spike-s1)) : ce que fait le
`ntdll` de ReactOS 0.4.16 (i386, version de publication) quand un processus natif démarre sous Mino. On les relève
dans le journal série du scénario `userland` (`cargo xtask fetch-userland`, puis
`cargo xtask test --boot --scenario userland`) ; chaque étape du spike met ce document à jour.

## Le programme

`ntoskrnl::userland::run_native_probe`, à la fin des tests de la phase 1, une fois `NTDLL.DLL` installée comme DLL
système :

- une image PE32 construite dans le noyau (`pe::builder`), sous-système NATIVE, base `0x400000`, qui importe
  `DbgPrint` et `NtTerminateProcess` de `ntdll.dll` ;
- son code écrit `[s1] hello from a native process` par `DbgPrint`, puis appelle
  `NtTerminateProcess(NtCurrentProcess(), 0x5151)` ;
- Ps crée le processus (image, `KUSER_SHARED_DATA`, `ntdll` à sa base, PEB), écrit ses paramètres
  (`ps::process_parameters`, depuis l'étape 2 : image `C:\WINDOWS\system32\s1native.exe`, répertoire courant et
  chemin des DLL dans `C:\WINDOWS\system32`, environnement `Path`, `SystemDrive`, `SystemRoot`, `windir`) et crée
  son thread, qui démarre par `KiUserApcDispatcher` → `LdrInitializeThunk(NULL, base de ntdll, NULL)` ;
- le noyau attend la fin du processus (10 s au plus), puis journalise son statut de sortie et les appels système
  faits, dans l'ordre de leur premier appel, avec le nombre d'appels et ce qu'a rendu le premier
  (`sys::service_calls`).

Le dispatcher journalise aussi le premier appel d'un service sans handler, avec l'adresse de retour dans l'appelant
du stub `Zw` et les arguments ; et une exception que le processus ne reçoit pas (code, adresse, paramètres).

## Étape 1 : le programme n'est pas encore atteint

Statut de sortie : `STATUS_ACCESS_VIOLATION` (`0xC0000005`), sur les deux chemins (`int 2Eh` et SYSENTER).

| Ordre | Service | Appels | Premier retour | Appelant | Ce qu'en fait `ntdll` |
|---:|---|---:|---|---|---|
| 1 | `NtQueryInformationProcess` | 1 | `STATUS_NOT_IMPLEMENTED` | `0x7c96086c` | classe 0x24 (`ProcessCookie`), 4 octets : « Failed to receive the process cookie! » (`sdk/lib/rtl/process.c:407`), puis continue |
| 2 | `NtCreateEvent` | 1 | `STATUS_NOT_IMPLEMENTED` | `0x7c94949e` | l'événement d'une section critique disputée : « Failed to Create Event! » (`sdk/lib/rtl/critical.c:72`), repli sur l'événement à clé global |
| 3 | `NtWaitForKeyedEvent` | 1 | `STATUS_NOT_IMPLEMENTED` | `0x7c949664` | attente sur la section critique `0x7c9af070`, qui échoue |

Ce qui se passe :

1. Au début de l'initialisation du processus, `ntdll` lit `Peb->ProcessParameters` (`0x7c9278fb`), puis son
   `ImagePathName` (`+0x3C`) : le PEB n'en a pas, d'où une faute de lecture en `0x3C` (`0x7c9278fe`).
2. Le noyau la livre à `KiUserExceptionDispatcher`. `RtlDispatchException` appelle d'abord les gestionnaires
   vectorisés, dont le verrou (`0x7c9af070`) et la liste ne sont pas encore initialisés : ce sont des zéros. Le
   verrou semble pris et son attente échoue (services 2 et 3) ; vient ensuite, dans le parcours de la liste, une
   faute de lecture en `0xC` (`0x7c96bcd3`, le compteur de références d'une entrée nulle).
3. Cette faute repasse par le même chemin, environ un millier de fois, jusqu'à ce que la pile utilisateur (1 Mio)
   ne reçoive plus le contexte : le processus se termine avec le code de l'exception.

Le point 2 est un comportement de `ntdll` (une exception levée avant `RtlpInitializeVectoredExceptionHandling` ne
peut pas être livrée), pas un défaut du noyau : il disparaît avec la cause du point 1.

## Étape 2 : avec ses paramètres, `ntdll` s'arrête à la création du tas

Le processus a désormais ses `RTL_USER_PROCESS_PARAMETERS` (`abi::process_parameters`, bloc normalisé de 0x290
octets et ses chaînes, environnement à part). Statut de sortie : `STATUS_NO_MEMORY` (`0xC0000017`), sur les deux
chemins.

| Ordre | Service | Appels | Premier retour | Appelant | Arguments, et ce qu'en fait `ntdll` |
|---:|---|---:|---|---|---|
| 1 | `NtQueryInformationProcess` | 1 | `STATUS_NOT_IMPLEMENTED` | `0x7c96086c` | `ProcessCookie` (0x24), 4 octets ; continue |
| 2 | `NtOpenKey` | 1 | `STATUS_NOT_IMPLEMENTED` | `0x7c9251f3` | accès 8 (`KEY_ENUMERATE_SUB_KEYS`), vraisemblablement les options d'exécution de l'image ; continue |
| 3 | `NtQueryValueKey` | 5 | `STATUS_NOT_IMPLEMENTED` | `0x7c925349` | sur un handle qui n'en est pas un (`0x7c94c239`, `NtOpenKey` ayant échoué), classe 2 (`KeyValuePartialInformation`), 0x400 octets ; continue |
| 4 | `NtQuerySystemInformation` | 1 | `STATUS_NOT_IMPLEMENTED` | `0x7c94eafa` | `SystemBasicInformation` (0), 0x2C octets : « Getting max usermode address failed » (`sdk/lib/rtl/heap.c:1512`), puis « Failed to create process heap » (`dll/ntdll/ldr/ldrinit.c:2042`) |
| 5 | `NtTestAlert` | 1 | `STATUS_SUCCESS` | | |
| 6 | `NtContinue` | 1 | un nouveau contexte | | |
| 7 | `NtRaiseHardError` | 1 | `STATUS_NOT_IMPLEMENTED` | `0x7c92788c` | `STATUS_APP_INIT_FAILURE` (`0xC0000145`), un paramètre |
| 8 | `NtRaiseException` | 1 | ne revient pas | | `STATUS_NO_MEMORY` en `0x7c92913f`, en seconde chance : fin du processus |

Sans tas, l'initialisation du processus échoue (« DbgPrint() failed! », `dll/ntdll/ldr/ldrinit.c:2577`) ;
`ntdll` le signale par une erreur dure, puis lève `STATUS_NO_MEMORY`, que personne ne traite.

## Étape 3 : le programme va au bout

Trois ajouts y suffisent, chacun révélé par la sonde :

1. `NtQuerySystemInformation(SystemBasicInformation)` : la limite haute du mode utilisateur, sans laquelle
   `RtlCreateHeap` échoue. Le tas du processus se crée.
2. Les **tables NLS** (`ps::nls`) : `RtlMultiByteToUnicodeN` (`0x7c95a5f3`) lisait la table ANSI par un pointeur nul
   (`Peb->AnsiCodePageData`), d'où deux fautes que `ntdll` attrapait elle-même et un échec de l'initialisation
   avec `STATUS_ACCESS_VIOLATION`. Le noyau projette désormais dans chaque processus une section en lecture seule
   qui tient `C_1252.NLS`, `C_437.NLS` et `L_INTL.NLS`, comme XP.
3. `NtProtectVirtualMemory` : « LDR: Unable to unprotect IAT for s1native.exe » ; le chargeur rend la table
   d'adresses des imports inscriptible pour la lier, puis la reprotège.

Statut de sortie : `0x5151`, celui du programme, qui écrit `[s1] hello from a native process` par `DbgPrint` ;
sur les deux chemins. Les 17 appels système, dans l'ordre de leur premier appel :

| Ordre | Service | Appels | Premier retour | Ce qu'en fait `ntdll` |
|---:|---|---:|---|---|
| 1 | `NtQueryInformationProcess` | 1 | `STATUS_NOT_IMPLEMENTED` | `ProcessCookie` (0x24) : « Failed to receive the process cookie! » ; continue |
| 2 | `NtOpenKey` | 1 | `STATUS_NOT_IMPLEMENTED` | options d'exécution de l'image ; continue |
| 3 | `NtQueryValueKey` | 5 | `STATUS_NOT_IMPLEMENTED` | sur un handle non valide (`NtOpenKey` ayant échoué) ; continue |
| 4 | `NtQuerySystemInformation` | 2 | `STATUS_SUCCESS` | `SystemBasicInformation` : le tas du processus |
| 5 | `NtAllocateVirtualMemory` | 7 | `STATUS_SUCCESS` | le tas |
| 6 | `NtQueryDefaultLocale` | 2 | `STATUS_NOT_IMPLEMENTED` | la langue par défaut (premier argument 1 : celle de l'utilisateur) ; continue |
| 7 | `NtFreeVirtualMemory` | 3 | `STATUS_SUCCESS` | |
| 8 | `NtOpenDirectoryObject` | 1 | `STATUS_NOT_IMPLEMENTED` | `\KnownDlls` (accès 3) ; continue sans |
| 9 | `NtOpenFile` | 4 | `STATUS_NOT_IMPLEMENTED` | accès `GENERIC_READ | SYNCHRONIZE` : le manifeste du contexte d'activation implicite (« Failed to create the implicit act ctx ») ; continue |
| 10 | `NtQueryAttributesFile` | 1 | `STATUS_NOT_IMPLEMENTED` | continue |
| 11 | `NtProtectVirtualMemory` | 2 | `STATUS_SUCCESS` | la table d'adresses des imports, déprotégée puis reprotégée |
| 12 | `NtFlushInstructionCache` | 1 | `STATUS_NOT_IMPLEMENTED` | après la liaison des imports (`0x403000`, 12 octets) ; continue |
| 13 | `NtCreateKeyedEvent` | 1 | `STATUS_NOT_IMPLEMENTED` | l'événement à clé global des sections critiques ; continue |
| 14 | `NtSetInformationProcess` | 1 | `STATUS_NOT_IMPLEMENTED` | `ProcessExecuteFlags` (0x22) à 0 : « LDR: Could not set process execute flags 0x0 » ; continue |
| 15 | `NtTestAlert` | 1 | `STATUS_SUCCESS` | |
| 16 | `NtContinue` | 1 | un nouveau contexte | fin de `LdrInitializeThunk` : le thread entre dans le programme |
| 17 | `NtTerminateProcess` | 1 | ne revient pas | appelé par le programme |

`NtRaiseHardError` et `NtRaiseException` ne sont plus appelés. Les services encore absents sont tolérés par
`ntdll` ; ceux qui donnent un résultat juste sans Io ni Cm viendront d'abord (`ProcessCookie`,
`ProcessExecuteFlags`, `NtFlushInstructionCache`, `NtOpenDirectoryObject` par Ob, `NtQueryDefaultLocale`) ; le
registre (`NtOpenKey`, `NtQueryValueKey`) et les fichiers (`NtOpenFile`, `NtQueryAttributesFile`) attendent Cm et
Io ; `NtCreateKeyedEvent` attend les événements à clé d'Ex.

## Étape 4 : un programme compilé avec MinGW

`tests/native/s1hello.c`, compilé par `cargo xtask` avec `i686-w64-mingw32-gcc` (GCC 13), sans bibliothèque C
(`-nostdlib`), sous-système NATIVE, point d'entrée `NtProcessStartup(PPEB)`, lié à `ntdll.dll` par une bibliothèque
d'import que `dlltool --kill-at` tire de `tests/native/ntdll.def` (les exports appelés, avec leurs octets
d'arguments). Le noyau le lance comme la sonde, depuis le disque de démarrage (`S1HELLO.EXE`), le PEB en argument
de son point d'entrée (une adresse de retour nulle sous laquelle pointe ESP, puis le PEB, comme
RtlCreateUserThread).

Résultat, sur les deux chemins : `[s1] hello from a MinGW native program, PEB 7FFDF000`, puis le statut `0x5152`
du programme ; les mêmes 17 appels système que la sonde. Le premier critère de sortie de S1 est atteint
(scénario `native`).

**Prochaine étape** : le test SEH (`__try`/`__except` sur une écriture à l'adresse 0).
