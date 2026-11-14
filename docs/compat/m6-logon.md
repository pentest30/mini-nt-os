# M6 — le logon, de NtCreateToken à `userinit`

Premier critère de sortie du M6 ([05](../05-feuille-de-route.md#m6--win32k-avec-le-spike-s3-en-premier)) : « `winlogon`
(ouverture de session automatique), `userinit` et `explorer` affichent le bureau, la barre des tâches et le menu
Démarrer ». L'étape 27 du M5 ([`m5-csrss.md`](m5-csrss.md)) menait le second démarrage du scénario `logon` jusqu'à
NtCreateToken : `msgina` ouvre la session d'`Administrator` par LsaLogonUser, `msv1_0` valide le compte, et `lsasrv`
fait le jeton de la session. Ce document suit la suite, jusqu'à `userinit.exe` qui cherche le shell.

La spécification suivie est ReactOS 0.4.16 (le comportement de ses DLL et services, et `ntoskrnl/se`, `ntoskrnl/config`,
`ntoskrnl/ex/locale.c`, `ntoskrnl/ps/security.c` comme description) ; aucun code n'en est porté.

## Ce que le logon demandait, dans l'ordre

Chaque ligne est un arrêt du scénario `logon`, sa cause, et ce qui l'a levé.

1. **NtCreateToken** (`se::Token::create`, SepCreateToken ; `sys::security::nt_create_token`). `lsasrv` fait le
   jeton primaire de l'utilisateur : son SID et ses groupes, ses privilèges, son propriétaire par défaut (l'utilisateur,
   ou un groupe qui porte `SE_GROUP_OWNER` : sinon `STATUS_INVALID_OWNER`), son groupe principal (l'utilisateur ou un de
   ses groupes : sinon `STATUS_INVALID_PRIMARY_GROUP`), sa DACL par défaut, sa source, sa session d'ouverture (que le
   moniteur de références doit connaître : `STATUS_NO_SUCH_LOGON_SESSION`), sous `SeCreateTokenPrivilege`. Tout est
   capturé (`se::capture_sid`, `se::capture_acl`, partagés avec la capture des descripteurs). Un jeton d'emprunt
   d'identité prend son niveau de la qualité de service des attributs. LsaLogonUser réussit.
2. **FileEaInformation** (NtQueryInformationFile, classe 7). `userenv` fait le profil d'`Administrator` en copiant
   celui de `Default User` (CopyDirectory) ; CopyFileW demande la taille des attributs étendus avant de copier, et la
   classe manquait (erreur 87, profil refusé). Ni la FAT ni NPFS n'en ont : 0.
3. **NtLoadKey** (`cm::load_hive`, `sys::registry::nt_load_key`). `userenv` monte le `NTUSER.DAT` du profil en
   `\REGISTRY\USER\<SID>` par RegLoadKeyW, qui donne la clé relativement au handle de `HKEY_USERS` (le SID seul) :
   la ruche est lue par Io, montée sous une clé virtuelle ouverte, et NtFlushKey la réécrit dans ce fichier.
   `SeRestorePrivilege`, que `userenv` active.
4. **NtUnloadKey** (`cm::unload_hive`). `userenv` charge la ruche pour la préparer, la décharge, puis la recharge
   pour la session : sans le déchargement, le second chargement trouvait le nom pris (erreur 183). La ruche est
   réécrite si elle a changé, puis démontée ; les clés encore ouvertes la gardent.
5. **NtDuplicateToken** (`se::Token::duplicate_as`). ImpersonateLoggedOnUser fait une copie d'emprunt d'identité du
   jeton de l'utilisateur, que `winlogon` emprunte pour préparer sa session. `EffectiveOnly` ne garde que les groupes
   et privilèges actifs. Un `DesiredAccess` nul donne à la copie les droits du handle copié : c'est ce que
   DuplicateTokenEx demande pour la copie primaire de CreateProcessAsUser (sans cela, le handle n'avait aucun droit, et
   l'assignation du jeton était refusée, `STATUS_ACCESS_DENIED`).
6. **Les paramètres régionaux de l'utilisateur**. SetDefaultLanguage de `winlogon` lit
   `HKCU\Control Panel\International\Locale` et le redonne par NtSetDefaultLocale(UserProfile). La ruche DEFAULT du
   LiveCD a la clé, vide (c'est l'installation de ReactOS qui l'écrit) : la couche Mino pose `Locale` = `00000409`
   (`tools/mkhive/mino.inf`), qui passe dans `NTUSER.DAT` de `Default User`, puis dans chaque profil. NtSetDefaultLocale
   écrit maintenant la valeur de l'utilisateur dans son profil (RtlOpenCurrentUser : la ruche du SID du jeton effectif,
   `.DEFAULT` sans elle), et `ex::locale` sépare les paramètres de l'utilisateur de ceux du système (ceux du système
   tant que rien ne les fixe) ; NtQueryDefaultLocale répond selon `UserProfile`. Sans la valeur, `winlogon` fermait la
   session sans un mot (ses avertissements ne sont pas compilés dans la version publiée). `winsrv` dit alors « We are
   logged on ».
7. **ProcessAccessToken** (NtSetInformationProcess, classe 9 ; `sys::security::assign_primary_token`,
   `ps::EProcess::set_primary_token`). `msgina` lance `userinit.exe` par CreateProcessAsUserW : le processus est créé
   suspendu, puis reçoit le jeton primaire de l'utilisateur (`TOKEN_ASSIGN_PRIMARY`, un jeton primaire,
   `SeAssignPrimaryTokenPrivilege` actif).

`userinit.exe` (sur le disque depuis cette étape) tourne alors sous le jeton de l'utilisateur : il se connecte à
`csrss` et à win32k, charge la disposition de clavier, applique les paramètres de l'utilisateur
(UpdatePerUserSystemParameters), puis cherche le shell de `Winlogon\Shell`, `C:\WINDOWS\explorer.exe`, qui n'est pas
sur le disque : « Failed to start default shell », puis la boîte « Userinit failed to start the shell! ». **C'est là
que le logon s'arrête aujourd'hui.**

## Vu en chemin, pas fait

- Le thread de `userinit` n'a pas de bureau de démarrage : « no startup desktop for thread … of userinit.exe
  (STATUS_NOT_IMPLEMENTED) » (`win32k::startup`) ; il prend celui de son processus ensuite. À diagnostiquer avant
  `explorer`, qui doit s'ouvrir sur `WinSta0\Default`.
- NtDeleteKey (le nettoyage de `winlogon` à la fermeture d'une session : `Volatile Environment`), FileStreamInformation
  (classe 22, que CopyFileW demande sans en dépendre), NtUserSetThreadState, NtUserUpdatePerUserSystemParameters
  (rend 0), NtUserSystemParametersInfo (classes 0x0E, 0x14, 0x5A), NtUserCallOneParam (0x31), NtUserCallHwnd.
- La parenté des jetons (`ParentTokenId`, SeIsTokenChild, SeIsTokenSibling) n'est pas suivie : un jeton tiré de celui
  de l'appelant demande donc aussi `SeAssignPrimaryTokenPrivilege` ; `winlogon` l'a actif.
- NtUnloadKey démonte une ruche dont des clés sont ouvertes (NT refuse : `STATUS_CANNOT_DELETE`).
- NtLoadKey refuse un fichier désigné relativement à un répertoire ouvert (`STATUS_NOT_IMPLEMENTED`) : sa réécriture
  demande son nom entier.

## Le shell : `explorer.exe`

`explorer.exe` est sur le disque des scénarios qui le demandent (`shell = explorer`, ici `logon`), dans
`C:\WINDOWS` (`SHELL_FILES`, `xtask/src/userland.rs` : la fermeture de ses imports vient avec, `browseui` et
`shdocvw` compris). Les autres disques ne le prennent pas : avec ces trois fichiers, la copie du disque de
l'installateur ne tenait plus sur sa cible (`installer-finish` : « copy failed: c0000185 »). `userinit` le lance
sous le jeton de l'utilisateur.

**Le premier lancement a mis au jour un bogue du noyau.** `explorer` mourait (`c0000096`, une instruction privilégiée à
l'adresse `0x006E0057`) dans la création de sa barre des tâches. Ses registres sauvés portaient les mots successifs de
« Shell_TrayWnd » en UTF-16 : EBX « l_ », EDI « Tr », EBP « ay », et l'adresse de retour « Wn ». NtUserGetAtomName
prend une UNICODE_STRING (`pustrName`, useratom.c), que `user32` pose sur sa pile quand une classe est donnée par
son atome (ClassNameToVersion, VersionRegisterClass, autour de CreateWindowEx et de RegisterClass) ; Mino la prenait
pour le tampon et y écrivait le nom entier, au-delà de ses 8 octets. Le même motif (« SHELLDLL_DefView » sur la pile)
faisait planter la boîte Enregistrer sous du Bloc-notes avant la PR 127. NtUserGetAtomName suit maintenant
useratom.c :

- le nom vient de la table de USER comme RtlQueryAtomInAtomTable le rend (`win32k::atom::query_name`) : 255
  caractères au plus (IntGetAtomName), « #n » pour un atome entier (NtQueryInformationAtom aussi, qui rendait les
  chiffres sans « # ») ;
- la UNICODE_STRING est lue, son tampon sondé sur `MaximumLength` ; le nom y est tronqué pour laisser la place du nul
  (`win32k::atom::copied_name_units`), rien sans cette place ; le service rend le nombre de caractères copiés ;
- 0 pour un thread sans bureau (IntGetAtomName) ; 0 et la dernière erreur pour un atome inconnu ou une adresse fautive.

**La correction a montré deux autres écarts, dans la boîte Enregistrer sous du Bloc-notes.** Tant que la pile de
`user32` était écrasée, la création de la vue de dossier (CDefView, « SHELLDLL_DefView ») échouait sans bruit et la
boîte n'avait pas de liste ; `notepad-save` passait ainsi. La vue créée, deux écarts du noyau l'ont arrêtée :

- **SendMessage vers une fenêtre qui n'existe pas rendait une valeur au hasard.** CDefView compte les colonnes de
  l'en-tête de sa liste (`Header_GetItemCount(ListView_GetHeader(...))`) alors que la liste n'a pas encore d'en-tête :
  SendMessageW(NULL, HDM_GETITEMCOUNT). `user32` (SendMessageW, SendMessageA) passe au noyau l'adresse d'une variable
  `Result` qu'il n'initialise pas et la rend telle quelle. ReactOS (NtUserMessageCall, FNID_SENDMESSAGE) y écrit
  toujours la valeur de co_IntDoSendMessage, 0 pour une fenêtre inconnue (`ERROR_INVALID_WINDOW_HANDLE`), et rend
  TRUE ; Mino rendait FALSE sans l'écrire. CDefView prenait donc des colonnes pour existantes, les modifiait
  (LVM_SETCOLUMN) au lieu de les insérer, et l'assertion `MapFolderColumnToListColumn(0)` (CDefView.cpp:1178)
  arrêtait le Bloc-notes. NtUserMessageCall(FNID_SENDMESSAGE) suit maintenant ReactOS (`sys::message`,
  `send_message_result`) : TRUE et 0 si l'envoi échoue, avec son erreur ; FALSE seulement si `ResultInfo` est fautif.
- **Une fenêtre déjà active était réactivée, et perdait le focus.** comdlg32 redimensionne sa boîte (ArrangeCtrlPositions :
  SetWindowPos sans SWP_NOACTIVATE). Mino ne tenait une fenêtre pour déjà active que si elle avait aussi le focus ;
  celui de la boîte était sur le champ du nom : WM_NCACTIVATE, WM_ACTIVATE, puis le focus à la boîte elle-même, que
  DefDlgProc rendait à son premier contrôle, la liste « Enregistrer dans ». Les touches tapées après Alt+N y
  choisissaient « Poste de travail », et le champ ne gardait que la dernière lettre : « Path does not exist ».
  ReactOS (co_IntSetActiveWindow) ne fait rien pour une fenêtre déjà active ; après WM_ACTIVATE, il ne donne le focus
  à la fenêtre que s'il n'est pas déjà dans l'une de ses filles (IntGetNonChildAncestor). `win32k::input::activate`
  fait de même (`focus_is_in`).

**Le thread du bureau : MsgWaitForMultipleObjects.** CDesktopThread::Initialize attend son thread du bureau et
l'événement que celui-ci signale une fois le bureau créé, par MsgWaitForMultipleObjects (`desktop.cpp`). `user32`
(RealMsgWaitForMultipleObjectsEx) y ajoute l'événement de la file du thread, qu'il demande par
NtUserCallOneParam(ONEPARAM_ROUTINE_GETINPUTEVENT, 0x27 ; IntMsqSetWakeMask), puis efface le masque de réveil
(NOPARAM_ROUTINE_MSQCLEARWAKEMASK, 0x03). Mino n'avait ni l'un ni l'autre : WAIT_FAILED tout de suite, E_FAIL
(`desktop.cpp:193`), et Initialize remettait le plateau à NULL avant que le thread du bureau ne s'en serve
(l'assertion d'ATL, atlcomcli.h:208, `p != 0`). Comme InitThreadCallback, chaque thread GUI reçoit maintenant à sa
conversion un handle (EVENT_ALL_ACCESS) sur l'événement de sa file (`hEventQueueClient`,
`win32k::gui::ThreadInfo::queue_event_handle`), fermé à sa fin s'il le désigne encore ; IntMsqSetWakeMask
(`win32k::queue::input_event`) rend ce handle et signale l'événement si la file a déjà changé pour le masque demandé
(ou, MWMO_INPUTAVAILABLE, si l'un de ses bits est levé). La file de Mino n'a pas de masque de réveil (son événement
est signalé à chaque message) : NOPARAM_ROUTINE_MSQCLEARWAKEMASK n'a rien à défaire. ReactOS y remet aussi
`fsWakeBits` à zéro (« very hacky ») ; Mino ne le fait pas, ses bits de réveil suivent ce que tient la file.

**La fenêtre du shell : NtUserSetShellWindowEx.** Le thread du bureau crée alors le bureau d'`explorer` (« Progman »,
sa vue de dossier sur le Bureau de l'utilisateur et de All Users) et déclare sa fenêtre celle du shell
(`win32k::shell`, comme `window.c`) : une fois par station (ShellWindow, ShellListView), dans le `DESKTOPINFO` du
bureau (`hShellWindow`, `spwndShell`, `spwndBkGnd`, `ppiShellProcess`, que `user32` lit pour GetShellWindow), et
la fenêtre du shell passe au bas de l'ordre Z (`WNDS2_BOTTOMMOST`), que SetWindowPos ne lui fait plus quitter
(UserGetShellWindow dans co_WinPosSetWindowPos). Détruite, elle quitte la station et le `DESKTOPINFO`. Pas encore :
le raccourci Ctrl+Échap (SC_TASKLIST), faute de RegisterHotKey.

**Ce qu'une fenêtre découvre en changeant seulement de rang.** Le bureau d'`explorer`, d'abord au-dessus de tout,
avait recouvert la barre des tâches ; passé au fond, il ne la découvrait pas : SetWindowPos tenait pour découvert
l'ancien rectangle moins le nouveau, vide quand seul l'ordre Z change. Comme co_WinPosSetWindowPos
(co_VIS_WindowLayoutChanged de VisBefore moins VisAfter), `win32k::winpos::set_window_pos` compare maintenant ce qu'on
voyait de la fenêtre avant et après, ses sœurs au-dessus déduites (`paint::visible_region`) : la barre des tâches
se repeint.

**Où `explorer` va maintenant.** Sa barre des tâches (vide : ni bouton Démarrer ni horloge) au-dessus de son bureau,
sans assertion. Le bureau n'a encore ni fond (NtUserPaintDesktop : on voit celui de la fenêtre du bureau de win32k)
ni icônes (NtUserGetIconInfo ; CDesktopFolder.cpp:977 et CDefView.cpp:2744 pour les détails des éléments). En
chemin : BeginDeferWindowPos (ERROR_CALL_NOT_IMPLEMENTED), NtUserSystemParametersInfo (classes 0x2B, 0x2F, 0x30,
0x100A), les fenêtres message seul (HWND_MESSAGE), NtGdiGetDIBitsInternal, NtGdiAlphaBlend, NtUserRemoveProp,
NtUserSetWindowRgn, NtUserFindWindowEx, NtUserCallOneParam (0x1E BEGINDEFERWNDPOS, 0x28 GETKEYBOARDLAYOUT), le
fond du bureau repeint à la demande. Les threads de `userinit` et d'`explorer` n'ont pas de bureau de démarrage :
`msgina` leur donne un chemin sans station, que win32k ne résout pas encore (la station du processus,
IntResolveDesktop).

## La suite

Le bureau d'`explorer` : son fond (NtUserPaintDesktop : la couleur COLOR_BACKGROUND et le papier peint) et ses
icônes (NtUserGetIconInfo, les détails des éléments) ; la station par défaut d'un chemin de bureau, puis ce qu'il demande pour la barre (le bouton Démarrer, crochets, `SetWindowsHookEx`,
presse-papiers, notifications, `NtNotifyChangeKey`) et le bureau du critère.

## Tests

Hôte : `se` (un jeton créé tel qu'on l'a donné, le propriétaire et le groupe principal refusés, un jeton d'emprunt
d'identité créé, la copie « effective only »), `cm` (une ruche montée sous une clé virtuelle ouverte, refusée sous une
clé de ruche, déchargée puis rechargée), `ex` (les paramètres de l'utilisateur suivent ceux du système jusqu'à être
fixés). Scénario `logon` : les marqueurs du profil chargé (`IncrementRefCount(S-1-5-21-…)`), de la session ouverte
(« We are logged on »), de `userinit` (son thread converti), d'`explorer` (son thread converti, `desktop.cpp:193`, sa
barre des tâches à l'écran : deux pixels) ; chaque échec traversé est interdit (NtCreateToken, LsaLogonUser, le
profil, RegLoadKeyW, ImpersonateLoggedOnUser, l'assignation du jeton, CreateProcessAsUserW, « Failed to start default
shell »), et la fin d'`explorer` (`(explorer.exe) ended`). Neuf mutations (chacun des sept services ou classes
retiré, la valeur `Locale` de la couche, les droits d'une copie à `DesiredAccess` nul) font échouer le scénario ;
l'ancien NtUserGetAtomName aussi (`explorer` meurt). Hôte : `win32k::atom` (« #n » d'un atome entier, la copie bornée
par `MaximumLength` avec son nul). Scénario `send-messages` : SendMessageW(NULL) rend 0 et
`ERROR_INVALID_WINDOW_HANDLE`, la pile salie d'un motif avant l'appel (l'ancien service rend ce motif, 0x5EEDBEEF).
Scénario `activate-app`, étapes 4 et 5 : SetWindowPos d'une fenêtre active dont une fille a le focus ne lui envoie
pas WM_ACTIVATE et laisse le focus à la fille ; une fenêtre dont WM_ACTIVATE donne le focus à sa fille le lui laisse
(l'ancien `activate` échoue aux deux). `notepad-save` va de nouveau au bout, la vue de dossier créée. Scénario
`msg-wait` (`msgwait1.c`) : MsgWaitForMultipleObjects expire sur une file vide, se réveille pour un message posté
par un autre thread, attend un thread et un événement comme `explorer`, puis encore après WaitMessage ; sans
GETINPUTEVENT, chaque attente rend WAIT_FAILED. Scénario `zorder` (`zorder1.c`) : deux fenêtres qui se
chevauchent, celle du dessus envoyée au fond sans bouger ; la capture montre la première repeinte dans le
chevauchement (l'ancien calcul y laisse la seconde). Hôte : `win32k::winsta` (une station prend un seul shell,
jusqu'à la destruction de sa fenêtre). Scénario `logon` : `Documents and Settings\Administrator\Desktop` parcouru,
`desktop.cpp:193` et `atlcomcli.h` interdits, la barre des tâches visible au-dessus du bureau (ses deux pixels, que
le bureau recouvrait sans SetShellWindowEx).

Les apitests de `ntdll` (scénario `rostests`) restent à 43 sur 84, le plancher, mais pas les mêmes : NtDuplicateToken
(un `NewTokenHandle` nul : `STATUS_ACCESS_VIOLATION`, la poignée écrite d'abord, comme ProbeForWriteHandle) et
NtOpenThreadToken passent ; NtAccessCheck et NtAccessCheckByTypeResultList, qui passaient en se sautant faute de
NtDuplicateToken (GetToken), vont maintenant jusqu'à NtAccessCheck, pas encore là (SeAccessCheck, ADR-011).
NtSetDefaultLocale de l'utilisateur rend `STATUS_OBJECT_NAME_NOT_FOUND` pour un LCID que `Nls\Locale` ne connaît
pas, comme l'apitest l'attend d'XP (ExpValidateNlsLocaleId : la valeur introuvable) ; un groupe de langues absent
reste `STATUS_INVALID_PARAMETER`.
