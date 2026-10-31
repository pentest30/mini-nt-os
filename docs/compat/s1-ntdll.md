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

**Prochaine étape** (services du chargeur) : `NtQuerySystemInformation(SystemBasicInformation)` d'abord ; puis
`ProcessCookie`, des réponses « introuvable » du registre (`NtOpenKey` : `STATUS_OBJECT_NAME_NOT_FOUND`), et
`NtRaiseHardError` journalisé ; relancer la sonde après chacun.
