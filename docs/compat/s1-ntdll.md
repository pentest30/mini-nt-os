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
- Ps crée le processus (image, `KUSER_SHARED_DATA`, `ntdll` à sa base, PEB) et son thread, qui démarre par
  `KiUserApcDispatcher` → `LdrInitializeThunk(NULL, base de ntdll, NULL)` ;
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

**Prochaine étape** : `RTL_USER_PROCESS_PARAMETERS` dans `abi` (assertions de layout) et dans chaque processus
de Ps, avec `ImagePathName`, `CommandLine`, `CurrentDirectory`, `DllPath` et un environnement.
