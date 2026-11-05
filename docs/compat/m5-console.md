# M5 — la console : un programme console lancé, et sa console

Le chemin des critères de sortie du M5 ([05](../05-feuille-de-route.md#m5--mode-console-puis-spike-s2)) : un
programme console (8 threads synchronisés par des sections critiques), puis `cmd.exe` interactif. Le `consrv`
épinglé n'a que son frontal graphique (`winsrv.dll`, `frontends/gui`) : la console est une fenêtre de USER, que
`consrv` crée dans `csrss` et peint avec une police à chasse fixe.

## Le banc d'essai : `CONSOLE1.EXE` lance `THREADS1.EXE`

Le scénario `console` met `CONSOLE1.EXE` (`tests/native/console1.c`, sous-système WINDOWS) à la place de
`winlogon.exe` : comme `winlogon`, il s'inscrit comme processus de logon et prend `WinSta0\Default`, puis lance par
CreateProcessW `THREADS1.EXE` (`tests/native/threads1.c`, sous-système CONSOLE, que `xtask` construit maintenant :
point d'entrée `ConsoleStartup`), attend sa fin et lit son code de sortie. Un programme console ne peut pas prendre
lui-même le bureau : `kernel32` le connecte à `consrv` avant son point d'entrée, et la console a besoin d'un bureau.

`THREADS1.EXE` est le programme du critère : 8 threads ajoutent 2000 fois 1 à un compteur sous une section critique,
en laissant les autres tourner tous les 64 tours pendant qu'ils la tiennent (Sleep(0)), pour qu'ils l'attendent ;
puis il écrit sur sa console (WriteConsoleW). Il ne va pas encore jusque-là : la console ne lui est jamais donnée.

## Étape 1 : CreateProcessW, l'emprunt d'identité, le bureau de la console

La sonde, dans l'ordre :

1. **CreateProcessW échoue** (`ERROR_PARTIAL_COPY`) : `kernel32` écrit les paramètres du nouveau processus, puis
   leur adresse dans son PEB, en `0x10` : il a pris le PEB à 0. Le noyau de ReactOS rend l'adresse du PEB d'un
   processus créé dans le TEB de son créateur, en `NtTib.ArbitraryUserPointer` (PspCreateProcess), et le
   CreateProcessInternalW de `kernel32` l'y lit, sans la demander (ProcessBasicInformation). C'est un écart de
   ReactOS sur XP, mais il fait partie de sa frontière noyau : NtCreateProcess(Ex) le fait maintenant, comme lui,
   pour tout créateur qui a un TEB.
2. **`csrss` ne peut pas emprunter l'identité du client** (« CSRSS: Can't impersonate client thread ») :
   NtImpersonateThread manquait. L'emprunt d'identité est fait :
   - `ps` : chaque thread peut emprunter un jeton (PS_IMPERSONATION_INFORMATION : jeton, niveau, copie à
     l'ouverture, effectif seul ; `EThread::impersonate`, `EThread::impersonation`) ;
   - `se` : `Token::duplicate` (SepDuplicateToken : un type et un niveau), `se::client::client_security`
     (SeCreateClientSecurity et SeImpersonateClientEx pour un client local : le jeton effectif du client, celui
     qu'il emprunte ou le jeton primaire de son processus ; une copie au niveau demandé en suivi statique, le jeton
     lui-même en suivi dynamique ; les niveaux vérifiés) ;
   - services : NtImpersonateThread (`THREAD_DIRECT_IMPERSONATION` sur le serveur, `THREAD_IMPERSONATE` sur le
     client), NtSetInformationThread(ThreadImpersonationToken) (un jeton d'emprunt d'identité, ou NULL : le retour à
     soi de CsrRevertToSelf), NtOpenThreadToken(Ex) qui rend le jeton emprunté (une copie, que le thread emprunte
     ensuite, quand l'emprunt vient d'un serveur : CopyOnOpen), `STATUS_NO_TOKEN` sans emprunt.
3. **Le frontal graphique ne se charge pas** : NtUserConsoleControl et NtUserResolveDesktop manquaient.
   - NtUserConsoleControl (`win32k::console`, `sys::console`) : l'atome de la classe des fenêtres console
     (GuiConsoleWndClassAtom), le thread d'entrée des consoles de chaque bureau
     (ConsoleCtrlDesktopConsoleThread : `Desktop::exchange_console_thread`, lu seulement avec
     INVALID_HANDLE_VALUE). Seul `csrss` peut l'appeler.
   - NtUserResolveDesktop (IntResolveDesktop) : la station et le bureau du processus console, ouverts dans `csrss` ;
     ceux d'un processus GUI qui les a déjà, sinon ceux du chemin `Station\Bureau` de ses paramètres (que
     CreateProcessW tient de `lpDesktop`), la station interactive n'allant qu'à un processus de la session
     d'ouverture de System ou de celle de son utilisateur.
4. **La fenêtre console n'est pas créée** : `consrv` crée son thread d'entrée (un thread de `csrss` sur le bureau),
   qui crée la fenêtre ; à WM_NCCREATE, InitFonts ne trouve ni la police « VGA », celle de la page de code 437, ni
   « Terminal », son repli (NtGdiGetFontFamilyInfo manque, et toute police donne Tahoma : `win32k::gdi::fontobj`).
   La sonde s'arrête là ; `kernel32` attend la console.

En passant, tolérés : `RtlOpenCurrentUser` échoue (pas de `\REGISTRY\USER\S-1-5-18`), `consrv` prend ses réglages
par défaut ; une assertion de `consrv` sur ses icônes (`GuiData->hIcon && GuiData->hIconSm` : USER ne charge pas
encore d'icônes, NtUserFindExistingCursorIcon manque), que la sonde laisse passer (`DbgPrompt` reçoit « i ») ;
NtUserGetObjectInformation, NtUserGetSystemMenu, NtGdiOpenDCW, NtUserNotifyProcessCreate manquent (0 rendu).

Pas encore : SeTokenCanImpersonate (un thread peut emprunter tout jeton : ils viennent tous de celui de System) ;
le DACL d'une copie à l'ouverture ; OpenAsSelf (sans contrôle d'accès, il ne change rien) ; `IsImpersonating` dans
le TEB ; pour NtUserResolveDesktop, la station par défaut d'un chemin qui n'en nomme pas (une station héritée, ou la
station des services `Service-0x0-3e7$` que ReactOS crée pour un processus de System : `STATUS_NOT_IMPLEMENTED`,
journalisé) ; ConsoleMakePalettePublic (pas de palettes) et ConsoleAcquireDisplayOwnership.

Tests : hôte (`se` : une copie d'emprunt d'identité a son type et son niveau ; SeCreateClientSecurity en suivi
statique et dynamique, le niveau d'un client qui emprunte, un niveau inconnu) ; le scénario `smoke` (un thread
emprunte sa propre identité, NtOpenThreadToken rend une copie d'emprunt d'identité à ce niveau, le retour à soi,
puis `STATUS_NO_TOKEN` ; un jeton primaire, un handle sans `TOKEN_IMPERSONATE` et un niveau inconnu refusés) ; le
scénario `console` sur les deux CPU. 4 mutations tuées : sans PEB rendu au créateur, sans emprunt (scénario
`console`), un retour à soi ignoré, un jeton primaire accepté (`smoke`). Sans test : le thread d'entrée d'un bureau
retrouvé par une seconde console (il n'y en a qu'une).

La suite : les polices de la console (étape 2).

## Étape 2 : les polices de la console

`consrv` crée la fenêtre de sa console avec la police de sa page de code : « VGA » pour la 437, « Terminal » en
repli (`concfg/font.c`). Il la vérifie d'abord par EnumFontFamiliesExW (IsValidConsoleFont2) : une police TrueType
doit être à pas fixe et FF_MODERN, sauf si elle est dans la liste `Console\TrueTypeFont` de la ruche SOFTWARE (Lucida
Console seulement). Tout donnait Tahoma, et NtGdiGetFontFamilyInfo manquait.

- **La ruche SOFTWARE** de ReactOS épinglé est sur le disque de démarrage et montée en `\REGISTRY\MACHINE\SOFTWARE`
  (`userland::mount_software_hive`, réécrite par NtFlushKey comme SYSTEM) : `FontSubstitutes` (34 substituts : « MS
  Shell Dlg » donne Tahoma, « Terminal » Lucida Console, « Courier » Courier New…), `Console\TrueTypeFont`.
- **Les polices du disque** : `win32k::font` tient une table de polices installées (plus l'énumération fermée de
  Tahoma, Tahoma gras et Marlett) ; le noyau installe chaque `.ttf` de `\SystemRoot\Fonts` (IntLoadSystemFonts ; Io sait
  lister un répertoire : `Volume::list`, `File::list`). Pour chacune : sa famille, son style et son nom complet (table
  `name`, `glyph::Names`), sa graisse, son italique, son pas et sa famille, son jeu de caractères (le premier de ses
  pages de code, comme ReactOS). `xtask` met sur le disque, en plus des polices du cadre, VGA (`UniVGA16.ttf`, famille
  « VGA » : sa table `post` la dit proportionnelle, son PANOSE à chasse fixe, ce qui suffit à FillTM), Lucida Console
  et Courier New.
- **La correspondance d'un LOGFONT** (TextIntRealizeFont) : son nom à travers les substituts (SubstituteFontRecurse,
  10 fois au plus), puis la police de cette famille la plus proche de sa graisse et de son italique ; sans elle, une
  police à pas fixe (Courier New d'abord) si le LOGFONT en demande une, sinon Tahoma. ReactOS pèse chaque écart
  (GetFontPenalty) ; ici, le nom décide.
- **L'énumération** (NtGdiGetFontFamilyInfo, `fontobj::family_info`, FONTFAMILYINFO dans `abi::gdi`) : les polices
  de ce nom (famille ou nom complet) et de ce jeu de caractères, puis celles des substituts de ce nom, sous le nom du
  substitut ; le LOGFONT et le NEWTEXTMETRIC de la hauteur par défaut, `lfPitchAndFamily` comme FontFamilyFillInfo
  (FIXED_PITCH pour VGA), TRUETYPE_FONTTYPE, la FONTSIGNATURE et l'écriture de la dernière page de code.
  `gdi32` rappelle le service quand son tampon est trop petit : le compte écrit est celui de toutes les polices.

**La sonde va au bout.** `consrv` crée la console ; `THREADS1.EXE` démarre, ses 8 threads comptent 16000 sans jamais
être deux dans la section critique, WriteConsoleW écrit ses 17 caractères, et il se termine avec 0x600D, que
`CONSOLE1.EXE` lit.

Mais les threads n'attendent jamais la section critique (« contended: no ») : Sleep(0) ne cède pas le processeur.
`ke::dispatcher::ke_delay_execution_thread` le dit (un intervalle nul revient aussitôt) ; XP donne le reste du quantum
à un thread prêt de même priorité. Le critère du M5 (8 threads synchronisés) attend ce correctif de Ke, pour que le
test exerce vraiment l'attente (la création de l'événement de la section critique, l'attente, le réveil).

En passant, toujours tolérés : l'assertion des icônes de `consrv` ; NtUserSetWindowLong, NtUserSetTimer,
NtUserShowWindowAsync (la fenêtre console n'est pas montrée), NtUserDestroyWindow, NtGdiCreateCompatibleDC,
NtGdiExtGetObjectW, NtGdiCreateBitmap, NtGdiCreatePatternBrushInternal, NtAddAtom manquent (0 rendu) ; `comctl32`
ne trouve pas son manifeste (contextes d'activation) ; NtQueryInformationThread(ThreadAmILastThread) et
NtSetInformationThread(ThreadQuerySetWin32StartAddress) manquent.

Ce qui manque : les polices bitmap (`.fon` : « Terminal » n'existe que par son substitut), les collections, les
polices privées (AddFontResource), le jeu de caractères d'un substitut (`Nom,jeu`, ignoré), les pénalités de
GetFontPenalty, le gras et l'italique synthétiques.

Tests : hôte (`glyph` : noms, italique, pages de code des polices épinglées, VGA à pas fixe et FF_MODERN ; `io` : un
répertoire liste ses noms ; `win32k` : une police par famille, graisse et italique, réinstallée à son rang, son pas et
son jeu de caractères, les substituts suivis et arrêtés sur une boucle ; la correspondance d'un LOGFONT ; l'énumération
par nom et par substitut) ; 10 mutations, toutes tuées (8 sur l'hôte ; une énumération vide et sans ruche SOFTWARE,
dans le scénario) ; le scénario `console` sur les deux CPU, qui va au bout.

La suite : Sleep(0) qui cède le processeur (étape 3).

## Étape 3 : Sleep(0) cède le processeur, le critère des 8 threads

Sleep(0) passe par NtDelayExecution avec un intervalle nul. Ke revenait aussitôt
(`ke::dispatcher::ke_delay_execution_thread` : « un intervalle nul ou déjà échu retourne aussitôt, sans céder le
processeur »), alors que XP donne le reste du quantum à un thread prêt de même priorité, et revient aussitôt s'il n'y
en a pas (le comportement que documente Sleep). Les 8 threads de `THREADS1.EXE`, qui appellent Sleep(0) en tenant la
section critique, ne laissaient donc jamais un autre thread la demander.

- `ke::sched::Scheduler::yield_to_equal` : s'il y a un thread prêt de la priorité du thread courant, celui-ci passe en
  queue de sa file avec un quantum neuf, et le premier de la file s'exécute ; sinon rien ne change. Un thread de
  priorité plus basse n'a pas le processeur.
- `ke::dispatcher::Platform::yield_execution` (le noyau : la commutation de `ke::sched` ; les tests hôte : le
  simulateur) ; KeDelayExecutionThread d'un intervalle nul l'appelle, après l'attente sans objet qui livre d'abord un
  APC utilisateur à une attente alertable (STATUS_USER_APC, sans céder). Un intervalle déjà échu revient toujours
  aussitôt.

La sonde : « contended: yes ». Les threads attendent la section critique (son événement est créé, attendu, signalé),
le compteur reste juste (16000, jamais deux threads dedans), et `THREADS1.EXE` se termine avec 0x600D : **le critère
« 8 threads synchronisés par des sections critiques » du M5 est coché** (scénario `console`).

Pas encore : NtYieldExecution (SwitchToThread), qui cède aussi à un thread de priorité plus basse ; la décroissance
de priorité d'un thread qui cède (le sien garde sa priorité et reçoit un quantum neuf).

Tests : hôte (`ke::sched` : céder seulement à un thread prêt de même priorité, dans l'ordre de la file, avec un quantum
neuf ; le dispatcher : un intervalle nul cède, une échéance passée non, un APC utilisateur d'abord) ; 2 mutations
(ne pas céder ; ne céder à personne), tuées sur l'hôte et dans le scénario `console`, qui exige « contended: yes ».

La suite : la fenêtre console montrée (NtUserShowWindowAsync) et son texte peint, les icônes de `consrv`, puis
l'entrée au clavier pour `cmd.exe` (le critère de `cmd.exe` interactif).
