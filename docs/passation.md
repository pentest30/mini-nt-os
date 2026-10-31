# Notes de passation

Où en est le travail, ce qui vient ensuite, et comment le reprendre. Ces notes ne font pas foi (les documents 01 à
06 et `docs/compat/` font foi) ; elles servent à reprendre une session, depuis n'importe quel compte. Les mettre à
jour à chaque commit qui change l'état.

## État

- Jalon : **M3, spike S1** ([05](05-feuille-de-route.md#m3--frontière-nt-puis-spike-s1)). Tout le reste du M3 est
  fait (voir CLAUDE.md).
- Branche de travail : `claude/new-session-696xfc`. Les PR se fusionnent dans `main` ; après une fusion, repartir de
  `origin/main` (avance rapide si la branche y est déjà incluse : `git merge-base --is-ancestor HEAD origin/main`).
- Dernière PR fusionnée : #28 (`fetch-userland`). L'étape 1 du spike (sonde, commits `ed622d2`…`93be3c7`) est
  poussée, sans PR encore.
- Observations du spike : [`compat/s1-ntdll.md`](compat/s1-ntdll.md).

## Spike S1 : les étapes

Critères de sortie (05) : un programme natif compilé avec MinGW et lié au `ntdll` de ReactOS affiche par `DbgPrint`
et se termine ; un test SEH (`__try`/`__except` sur une écriture en 0) passe ; la liste des appels système
rencontrés est publiée.

1. [x] **Sonde** : `ntoskrnl::userland::run_native_probe` démarre une image native construite dans le noyau
   (`pe::builder`, imports `DbgPrint` et `NtTerminateProcess`) sous le vrai `ntdll`, et journalise sa fin et les
   appels système faits (`sys::service_calls`). Résultat : `LdrInitializeThunk` lit `Peb->ProcessParameters`,
   absent, et faute.
2. [ ] **Paramètres du processus** (en cours) : `RTL_USER_PROCESS_PARAMETERS` (32 bits, 0x290 octets) dans `abi`
   avec assertions de layout ; Ps l'écrit dans le processus (bloc normalisé, chaînes UTF-16 à la suite ;
   environnement dans une allocation à lui, car `RtlSetEnvironmentVariable` le réalloue et libère l'ancien) et met
   son adresse dans le PEB. Chemins sous `C:\WINDOWS` (la racine de `KUSER_SHARED_DATA`). Puis relancer la sonde
   et noter la suite dans `compat/s1-ntdll.md`.
3. [ ] **Services du chargeur** : ceux que la sonde révèle, un par un, selon la compétence `mino-syscall-impl`
   (handler dans `kernel/ntoskrnl/src/sys/`, entrée dans `IMPLEMENTED`, `cargo xtask syscall-gen` pour le rapport
   de couverture). Déjà vus : `NtQueryInformationProcess` (classe 0x24 `ProcessCookie`), `NtCreateEvent`,
   `NtWaitForKeyedEvent`. Attendus : `NtQuerySystemInformation`, `NtProtectVirtualMemory`,
   `NtQueryVirtualMemory`, `NtSetInformationProcess`, attentes et événements, réponses « introuvable » pour le
   registre (`NtOpenKey`) et `\KnownDlls`. Fin de l'étape : la sonde va au bout (statut `0x5151`, ligne
   `DbgPrint ... [s1] hello from a native process`).
4. [ ] **Programme MinGW** : `gcc-mingw-w64-i686` (apt, présent sur les runners Ubuntu et installable ici),
   `-nostdlib -Wl,--subsystem,native -e _NtProcessStartup@4`, bibliothèque d'import de `ntdll` (celle de MinGW, ou
   `llvm-dlltool` sur les exports de `ntdll.dll`). Source sous `tests/` ; `xtask` le construit et le met sur le
   disque de démarrage ; le noyau le lance comme la sonde. Le thread initial d'un programme natif reçoit le PEB en
   paramètre (`NtProcessStartup(PPEB)`) : `ps::create_thread` doit alors poser le paramètre sur la pile (ESP pointe
   sur une adresse de retour, le paramètre au-dessus), ce qu'il ne fait pas encore.
5. [ ] **Test SEH** : GCC ne connaît pas `__try`/`__except` en i386. clang
   `--target=i686-pc-windows-msvc -fasync-exceptions` (clang 18 et `lld-link` sont installés ici) les compile, mais
   appelle `__except_handler3`, que le `ntdll` de ReactOS n'exporte pas : le test fournit le sien (code écrit par
   nous, d'après la structure documentée de la table des portées). Recommandation : MinGW pour l'étape 4, clang pour
   l'étape 5.
6. [ ] Cocher les critères dans 05, passer l'ADR-002 à « Acceptée » si S1 conclut, mettre à jour CLAUDE.md.

## Ensuite (hors S1)

- Router #DB, #BR, #NP, #SS, #AC du mode utilisateur vers KiDispatchException (aujourd'hui seuls #DE, #BP, #UD,
  #GP, #PF et `int 2Ch`).
- KiDispatchException : si la pile utilisateur ne reçoit pas le contexte, le processus se termine avec le code de
  l'exception d'origine (XP lèverait plutôt l'exception de l'écriture sur la pile).
- Avant de supprimer l'ancien code (Win32 dans `syscall.rs`, stubs de `loader.rs`, `launcher.rs`, `win32/*`,
  `directx/*`), extraire la connaissance utile dans `docs/compat/` (audit §5).

## Reprendre

```bash
cargo xtask fetch-userland                                  # ReactOS 0.4.16 (SourceForge), une fois
cargo xtask test --boot --scenario userland --cpu intel     # la sonde ; journal dans target/xtask/boot/userland-intel/
cargo xtask lint && cargo xtask test                        # avant chaque commit poussé
```

- Lire la sonde : `grep -h "\[s1\]\|sys: \|DbgPrint" target/xtask/boot/userland-intel/*.log`. Un service sans
  handler est journalisé à son premier appel avec l'appelant et les arguments ; une exception qui termine un
  processus, avec son adresse et ses paramètres.
- Situer une adresse de `ntdll` (base `0x7c920000`) :
  `llvm-objdump -d --no-show-raw-insn --start-address=0x... --stop-address=0x... third_party/reactos/0.4.16/reactos/system32/ntdll.dll`
  (le symbole affiché est l'export le plus proche, pas forcément la fonction) ; exports :
  `llvm-readobj --coff-exports ...`.
- Points d'entrée du `ntdll` épinglé : `LdrInitializeThunk` `0x7c92f358`, `KiUserExceptionDispatcher`
  `0x7c92f46e`, `KiUserApcDispatcher` `0x7c92f381`.
- ReactOS sert de spécification (ses sources `ntdll`, en lecture) ; on ne porte pas son code noyau. Jamais de code
  Microsoft.
- Réseau : SourceForge passe ; les pages de publication et l'API de GitHub, et reactos.org, sont bloquées.

## Pratiques de la session

- Commits en français, `<composant>: <résumé à l'impératif>`, un sujet chacun ; chaque commit intermédiaire compile
  sans warning (le vérifier dans un worktree :
  `git worktree add --detach target/work/wt <commit>` puis
  `CARGO_TARGET_DIR=../wt-target cargo build -p ntoskrnl --target x86_64-unknown-none --profile kernel`).
- Tests par mutation des nouveaux tests : casser à la main la ligne testée, relancer le scénario, vérifier qu'il
  échoue, rétablir. Un script le fait pour une liste de mutations JSON `[nom, [[chemin, ancien, nouveau], ...]]`
  (`target/work/mutate.py`, hors dépôt : à réécrire au besoin, une vingtaine de lignes autour de
  `cargo xtask test --boot --scenario NOM --cpu CPU`).
- Un symptôme contourné est documenté ; un bogue corrigé vient avec le test qui l'aurait détecté.
