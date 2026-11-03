# M6 : les fenêtres, avec le vrai `user32`

Observations du début du M6 ([05](../05-feuille-de-route.md#m6--win32k-avec-le-spike-s3-en-premier)) : ce que fait un
programme Win32 de test, lié au `user32` de ReactOS 0.4.16, quand il enregistre des classes et crée des fenêtres sur
le win32k de Mino. À mettre à jour à chaque étape.

## Le banc d'essai : `GUI1.EXE` à la place de `winlogon.exe`

`winlogon` s'arrête avant sa première fenêtre (son serveur RPC demande les tubes nommés, puis viennent `services`,
`lsass` et `msgina` : [`m5-csrss.md`](m5-csrss.md)). Le scénario `gui` donne donc à `smss` un autre programme à lancer
comme commande initiale : `tests/native/gui1.c`, compilé par MinGW (sous-système WINDOWS 5.1, sans runtime C, entrée
`GuiStartup`), lié à `ntdll`, `kernel32` et `user32` par des bibliothèques d'importation tirées de
`tests/native/*.def`. La clé `initial-command = GUI1.EXE` du scénario le met sur le disque à la place de
`WINDOWS\SYSTEM32\WINLOGON.EXE` (`xtask`, `put_initial_command`). `smss` le lance comme il lancerait `winlogon`,
`csrss` en fait un processus CSR, et son `user32` se connecte à `csrss` et à win32k comme celui de `winlogon` (dont
le rappel ClientThreadSetup).

Comme `winlogon`, le programme s'inscrit comme processus de logon (RegisterLogonProcess), crée `WinSta0` et le bureau
`Default`, s'y place et y passe (SwitchDesktop : le fond du bureau est peint). Chaque étape, et chaque message que
reçoit sa procédure de fenêtre, va au port de débogage (`DbgPrint`), où le scénario les cherche ; il se termine avec
un statut qui dit où il s'est arrêté.

## Étape 1 : les classes de fenêtres

`RegisterClassExW` de `user32` enregistre d'abord ses contrôles du système (RegisterSystemControls : Button, ListBox,
Edit, Static, Ghost… avec leur FNID et `CS_GLOBALCLASS`), puis la classe demandée, par NtUserRegisterClassExWOW.
Pour chacun, `LoadCursorW` cherche un curseur partagé (NtUserFindExistingCursorIcon) puis en crée un (NtGdiOpenDCW) :
ces services manquent, la classe n'a pas de curseur, et l'enregistrement continue.

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::atom` | la table des atomes de USER (gAtomTable), aux règles de RtlAddAtomToAtomTable : atome entier (de 1 à `0xBFFF`, ou `#` et des chiffres) sans entrée ; nom en chaîne de 255 caractères au plus, atome à partir de `0xC000`, le même sans tenir compte de la casse, compte de références, place réutilisée |
| `win32k::class` | les classes privées et publiques de chaque processus (les plus récentes d'abord) ; à son premier enregistrement, les classes du système à procédure du serveur (bureau, menus, sélecteur de tâches, barres de défilement, titres d'icônes, fenêtres de messages) ; deux atomes par classe (nom et version) ; une procédure du client qui est celle d'une classe à procédure du serveur donne cette procédure (`CSF_SERVERSIDEPROC`) ; la recherche de CreateWindowEx (privée de l'instance, publique, puis celles de `user32`) ; le `CLS` dans le tas de chaque bureau où la classe aura une fenêtre |
| NtUserRegisterClassExWOW (`sys::class`) | les refus de ReactOS (drapeau autre que `CSF_ANSIPROC` : `ERROR_INVALID_FLAGS` ; taille de `WNDCLASSEXW`, longueurs impaires, octets de plus négatifs ou qui débordent, instance nulle, nom vide qui n'est pas un atome : `ERROR_INVALID_PARAMETER`) ; une classe privée de la même instance, ou publique, du même nom : `ERROR_CLASS_ALREADY_EXISTS` ; rend l'atome du nom |
| NtUserGetClassInfo (`sys::class`) | le `WNDCLASSEXW` de la classe que CreateWindowEx trouverait (instance nulle : celle de `user32`), procédure vue par le client (ANSI ou non), `CS_GLOBALCLASS` ôté d'une classe à FNID ; rend l'atome du nom ; sans classe : `ERROR_CLASS_DOES_NOT_EXIST` |

Le programme enregistre sa classe (atome `0xC00A`, après celles des contrôles), la retrouve telle qu'il l'a donnée
(`GetClassInfoExW`), retrouve la classe Button de `user32` (globale, mais sans `CS_GLOBALCLASS` puisqu'elle a un
FNID), ne trouve pas une classe jamais enregistrée (1411) et ne peut pas enregistrer la sienne deux fois (1410). Il
s'arrêtait ensuite à NtUserCreateWindowEx (étape 2).

Écarts : ni objets curseur et icône (les handles sont gardés, `spicn` et `spcur` restent nuls), ni pinceaux (un
pinceau du système vaut sa couleur plus un, comme pour la classe du bureau) ; le nom de menu reste dans le client
(les pointeurs de `CLSMENUNAME`) ; le compte des fenêtres d'une classe n'est pas tenu dans le `CLS` ; pas de
`atomSysClass` dans le `SERVERINFO` ; ni désenregistrement (NtUserUnregisterClass), ni procédures d'appel (une
classe Unicode demandée en ANSI rend sa procédure, journalisé une fois).

Tests : hôte (`win32k::atom` : casse, atomes entiers, longueurs, références et réutilisation ; `win32k::class` :
recherche par nom et par atome, instance, classes globales, celles de `user32` en dernier, refus d'un double,
atomes rendus, classes du système une fois, procédure du serveur reprise) ; le scénario `gui`, sur les deux CPU.

## Étape 2 : NtUserCreateWindowEx, et les messages de la création

`CreateWindowExW` de `user32` cherche d'abord la classe (`GetClassInfoExW`, pour son menu), puis appelle
NtUserCreateWindowEx. Comme `co_UserCreateWindowEx` de ReactOS (`window.c`, `message.c`, `callback.c`, comme
spécification), win32k (`win32k::window::create_window`) :

1. trouve la classe par le nom de sa version (`ERROR_CANNOT_FIND_WND_CLASS`), le parent (la fenêtre du bureau, ou
   celle que donne une fenêtre fille ; une fenêtre fille sans parent : `ERROR_TLW_WITH_WSCHILD`) et le propriétaire
   (d'une fenêtre qui n'est pas fille : la fenêtre de premier niveau du parent donné) ;
2. corrige la place (IntFixWindowCoordinates : `CW_USEDEFAULT` d'une fenêtre qui n'est pas recouvrante vaut 0 ; une
   recouvrante, sans moniteur, prend 0, 0, 800 × 600, comme ReactOS sans moniteur) ; une fenêtre fille se place dans
   la zone cliente de son parent ;
3. crée le `WND` dans le tas du bureau (octets de plus de la classe compris), son handle (`TYPE_WINDOW`, le
   `THREADINFO` du thread), le `CLS` de la classe sur ce bureau, le nom dans le tas ; corrige les styles
   (`WS_VISIBLE` ôté, `WS_CLIPSIBLINGS` pour une fenêtre qui n'est pas fille, `WS_CAPTION` pour une recouvrante,
   `WS_EX_WINDOWEDGE` d'après le cadre, `WNDS_SENDSIZEMOVEMSGS` pour une recouvrante) ; les `WNDS2_*` de
   compatibilité d'après la version qu'attend le module ; la procédure de la classe (celle d'un contrôle, dans le jeu
   de caractères de la fenêtre) ;
4. envoie WM_NCCREATE (refusé : pas de fenêtre), lie la fenêtre parmi les enfants de son parent (en haut de l'ordre
   Z, une fille en bas), envoie WM_NCCALCSIZE (la zone cliente, ramenée dans la fenêtre), WM_CREATE (-1 : pas de
   fenêtre), puis WM_SIZE et WM_MOVE à une fenêtre qui n'attend pas d'être montrée, et WM_PARENTNOTIFY au parent
   d'une fenêtre fille (sauf `WS_EX_NOPARENTNOTIFY`) ;
5. donne la fenêtre à son thread (elle vit autant que lui) ; rend son handle, l'erreur Win32 remise à 0.

Un message envoyé à une fenêtre du thread courant dont la procédure est dans le client va à `user32` par
KeUserModeCallback (USER32_CALLBACK_WINDOWPROC, `WINDOWPROC_CALLBACK_ARGUMENTS` suivi du `lParam` emballé, repris
pour un message qui y écrit) ; pendant le rappel, le `CLIENTINFO` du thread désigne la fenêtre (`CallbackWnd` : son
handle, son `WND` dans la vue du processus). Le `CREATESTRUCT` de WM_NCCREATE et WM_CREATE est emballé comme
PackParam : ses chaînes à la suite, leurs positions à la place des pointeurs, `A` et l'atome ou `S` et le nom de la
classe ; `user32` le déballe (MsgiKMToUMMessage). NtUserDefSetText (DefWindowProc sur WM_NCCREATE et WM_SETTEXT)
change le nom, à sa place s'il y tient ; un texte ANSI garde son ASCII (le reste devient `?`, journalisé).

Le programme crée une fenêtre `WS_POPUP` de 400 × 300 en (100, 50) : sa procédure reçoit WM_NCCREATE et WM_CREATE
avec le `CREATESTRUCT` donné (paramètre, nom, classe, place, style), et, pendant WM_CREATE, son `CLIENTINFO` désigne
la fenêtre et son `WND` (dont le premier mot est le handle) ; elle reçoit, dans l'ordre, `0081 0083 0001 0005 0003`.
`user32` lit lui-même dans son `WND` son nom (`GetWindowTextW`, par WM_GETTEXT à DefWindowProc), son style corrigé
(`84000000`) et son rectangle ; `SetWindowTextW` change le nom (plus long : un bloc neuf ; plus court : à sa place).
Une fenêtre fille (`WS_CHILD`, identifiant 7, en (10, 20) dans la fenêtre) reçoit les mêmes messages, et son parent
WM_PARENTNOTIFY (WM_CREATE, 7, la fille) ; `GetParent` et `GetWindow(GW_CHILD)` suivent les liens des `WND`, et la
fille est en (110, 70). Une fille sans parent (1406), une fenêtre d'une classe inconnue (1407) et une fenêtre dont la
procédure refuse WM_NCCREATE ne sont pas créées. Le programme va au bout (statut `0x600D`).

Ce qui manque, journalisé une fois : la partie noyau de DefWindowProc et WM_GETMINMAXINFO (étape 3), montrer une
fenêtre créée visible (ShowWindow, SetWindowPos), les menus (une fenêtre
qui n'est pas fille ne peut pas en recevoir : `ERROR_INVALID_MENU_HANDLE`), les fenêtres de messages (`HWND_MESSAGE`),
les messages envoyés à un autre thread, DestroyWindow (les fenêtres d'un thread vivent autant que lui ; une création
qui échoue ne reçoit ni WM_DESTROY ni WM_NCDESTROY), les crochets (`WH_CBT`), une fenêtre créée réduite ou agrandie.

Tests : hôte (`win32k::window` : `CREATESTRUCT` emballé, styles d'une fenêtre neuve, place par défaut, compatibilité,
zone cliente ramenée dans la fenêtre) ; le scénario `gui`, sur les deux CPU.

Correction (étape 3) : NtUserCreateWindowEx lisait le bit `bAnsi` des `LARGE_STRING` de la classe et de sa version.
`user32` n'y pose que `MaximumLength` : le bit est ce qui restait sur sa pile, et une classe pouvait ne pas être
trouvée (1407), selon les appels précédents. Comme ProbeAndCaptureLargeString, la capture l'ignore maintenant (le nom
de la fenêtre aussi : CreateWindowExA le convertit en Unicode sans ôter le bit) ; seul NtUserDefSetText le lit.

## Étape 3 : les métriques du système et DefWindowProc du noyau

`user32` lit lui-même les métriques du système (`GetSystemMetrics`) et les couleurs système (`GetSysColor`) dans le
`SERVERINFO` de la section partagée, `aiSysMet` (en `0x5CC`) et `argbSystem` (en `0x7BC`) : les positions viennent du
`user32` épinglé. Pour les messages qu'il ne traite pas lui-même (WM_NCCALCSIZE, WM_NCPAINT, WM_SETCURSOR,
WM_SYSCOMMAND…), son DefWindowProc appelle NtUserMessageCall avec `FNID_DEFWINDOWPROC`. Comme ReactOS (`metric.c`,
`stockobj.c`, `defwnd.c`, `nonclient.c`, `winpos.c`, `message.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::metrics` | InitMetrics avec les valeurs par défaut de ReactOS sans profil d'utilisateur (titre de 19 + 1, bordure de 1, barres de défilement de 16, menus de 18…) et le mode de l'écran (640 × 480 sans affichage) ; les 31 couleurs système de ReactOS ; écrites dans le `SERVERINFO` quand `csrss` initialise win32k (InitVideo), gardées pour les calculs du noyau (UserGetSystemMetrics) |
| `win32k::defwnd` | IntDefWindowProc : WM_NCCALCSIZE (NC_HandleNCCalcSize : bordures d'après UserHasWindowEdge et UserGetWindowBorders, titre ou petit titre, bord client, barres de défilement, à gauche aussi ; avec des rectangles valides, `WVR_VALIDRECTS` et les `WVR_*REDRAW` de la classe ; les `WNDS_HAS*` gardés dans le `WND`) ; WM_DEVICECHANGE rend TRUE, un message au-delà de WM_USER 0 ; les valeurs par défaut de WM_GETMINMAXINFO (co_WinPosGetMinMaxInfo : IntGetWindowBorders, taille et place agrandies, suivi entre SM_CXMINTRACK et SM_CXMAXTRACK) |
| NtUserMessageCall (`sys::message`) | `FNID_DEFWINDOWPROC` : la fenêtre (`hWnd` nul permis ; inconnue : FALSE, `ERROR_INVALID_WINDOW_HANDLE`), le résultat dans `ResultInfo`, TRUE ; une structure illisible ou un `ResultInfo` où l'on ne peut écrire : FALSE (ReactOS n'a pas de garde autour de ce traitement) ; les autres types : FALSE et `ERROR_CALL_NOT_IMPLEMENTED`, journalisés une fois chacun |
| `win32k::window::create_window` | WM_GETMINMAXINFO avant WM_NCCREATE, à une fenêtre recouvrante ou à cadre épais ; sa taille est ramenée entre le suivi minimal et maximal que laisse la procédure (le minimum l'emporte) |

Le programme lit l'écran (1280 × 800), le titre (20), le cadre (4), la largeur minimale (112) et trois couleurs
(fond du bureau `a56e3a`, fenêtre `ffffff`, boutons `c8d0d4`). Une fenêtre `WS_OVERLAPPEDWINDOW` (`CW_USEDEFAULT`)
reçoit `0024 0081 0083 0001` (pas encore WM_SIZE ni WM_MOVE : elle attend d'être montrée) ; WM_GETMINMAXINFO lui
donne 1288 × 808 en (−4, −4) agrandie, un suivi de 112 × 28 à 1292 × 812 ; elle est en 0, 0, 800 × 600 (ReactOS
sans moniteur), sa zone cliente fait 792 × 572 (4 de bordure, 20 de titre) et son `WND` a `WNDS_HASCAPTION` pendant
WM_CREATE. DefWindowProcW de WM_NCCALCSIZE avec des rectangles valides rend `0x400` et la zone cliente du premier.
Des fenêtres `WS_POPUP | WS_CAPTION | WS_THICKFRAME` créées trop petites, trop grandes, ou avec un minimum que leur
procédure relève (300 × 200), ont la taille permise ; elles sont créées avec des uns sur la pile, que `user32` laisse
dans le bit `bAnsi` du nom de la classe.

Ce qui manque, journalisé une fois : les autres messages de DefWindowProc (peinture du cadre, WM_NCHITTEST,
WM_SETCURSOR, WM_SYSCOMMAND, WM_CLOSE, les touches… : ils attendent les contextes de périphérique, le
positionnement et l'entrée), le texte ANSI de DefWindowProcA, les autres types de NtUserMessageCall (SendMessage et
ses variantes, la barre de défilement, le bureau, les menus) ; ni moniteur (place par défaut d'une fenêtre
recouvrante, valeurs de WM_GETMINMAXINFO non adaptées à la zone de travail), ni profil d'utilisateur pour les
métriques (`HKCU\Control Panel\Desktop\WindowMetrics`), ni SystemParametersInfo, ni menus (`WNDS_HASMENU`).

Tests : hôte (`win32k::metrics` : les métriques d'un écran 1280 × 800, le fond du bureau ; `win32k::defwnd` :
bords en relief, zone cliente d'une fenêtre recouvrante, bordure fine, bord client, barres de défilement, titre
d'outil, fenêtre réduite, WM_GETMINMAXINFO de cadres divers) ; le scénario `gui`, sur les deux CPU.
