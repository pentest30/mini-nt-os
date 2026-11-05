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
ses variantes, la barre de défilement, le bureau, les menus) ; ni moniteur (étape 4), ni profil d'utilisateur pour
les métriques (`HKCU\Control Panel\Desktop\WindowMetrics`), ni SystemParametersInfo, ni menus (`WNDS_HASMENU`).

Tests : hôte (`win32k::metrics` : les métriques d'un écran 1280 × 800, le fond du bureau ; `win32k::defwnd` :
bords en relief, zone cliente d'une fenêtre recouvrante, bordure fine, bord client, barres de défilement, titre
d'outil, fenêtre réduite, WM_GETMINMAXINFO de cadres divers) ; le scénario `gui`, sur les deux CPU.

## Étape 4 : le moniteur, et SetWindowPos

Comme ReactOS (`monitor.c`, `window.c`, `winpos.c`, `defwnd.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::monitor` | un moniteur principal, de la taille de l'écran, attaché avec les métriques quand il y a un affichage (co_IntInitializeDesktopGraphics) : handle USER (`TYPE_MONITOR`), rectangle et zone de travail, le compte des fenêtres placées en cascade (`cWndStack`) ; le moniteur d'un rectangle (`MONITOR_DEFAULTTONULL`, `…TOPRIMARY`, `…TONEAREST`) |
| NtUserMonitorFromWindow, NtUserMonitorFromRect, NtUserMonitorFromPoint, NtUserGetMonitorInfo (`sys::monitor`) | `dwFlags` inconnu : `ERROR_INVALID_FLAGS` ; un rectangle vide compte pour son coin ; `MONITORINFO` ou `MONITORINFOEXW` (nom `\\.\DISPLAY1`), une autre taille : `ERROR_INVALID_PARAMETER` ; un moniteur inconnu : `ERROR_INVALID_MONITOR_HANDLE` |
| `win32k::window::fix_coordinates` | IntFixWindowCoordinates sur un moniteur : `CW_USEDEFAULT` donne à une fenêtre recouvrante la place du `STARTUPINFO` (`STARTF_USEPOSITION`) ou la suivante d'une cascade (un bouton de titre et un cadre plus loin, recommencée au-delà du quart de la zone de travail), et sa taille (`STARTF_USESIZE`) ou les trois quarts de la zone ; `CW_USEDEFAULT` sur 16 bits vaut -32768 (corrigé : 32768 l'était aussi) |
| `win32k::window::min_max_info` | co_WinPosGetMinMaxInfo, pour la création et SetWindowPos : valeurs par défaut, WM_GETMINMAXINFO, puis ce que la procédure a laissé s'adapte à la zone de travail (`WNDS_MAXIMIZESTOMONITOR`) |
| `win32k::winpos` | co_WinPosSetWindowPos : WM_WINDOWPOSCHANGING (la procédure peut changer la demande), les nouveaux rectangles, WinPosFixupFlags (ce qui ne change pas, une fenêtre de premier niveau qui s'active monte en haut), WM_NCCALCSIZE avec des rectangles valides, l'ordre Z, les enfants déplacés avec la zone cliente, `WS_VISIBLE` (`SWP_SHOWWINDOW`, `SWP_HIDEWINDOW`), WM_CHILDACTIVATE à une fenêtre fille qui s'active, WM_WINDOWPOSCHANGED (sauf pour une fenêtre invisible dont seul le rang change) |
| `win32k::window::link` | IntLinkHwnd : en haut sous les fenêtres au premier plan, en bas, au premier plan (`HWND_TOPMOST`, `WS_EX_TOPMOST`), hors du premier plan (`HWND_NOTOPMOST`), après une sœur |
| `win32k::defwnd` | WM_WINDOWPOSCHANGING : la taille demandée ramenée dans les limites de WM_GETMINMAXINFO ; WM_WINDOWPOSCHANGED : WM_MOVE (zone cliente dans celle du parent d'une fenêtre fille, sinon à l'écran) et WM_SIZE si elle a bougé ou changé |
| NtUserSetWindowPos, NtUserMoveWindow (`sys::window`) | une fenêtre, ou une sœur `hWndInsertAfter`, qui n'existe pas : `ERROR_INVALID_WINDOW_HANDLE` ; la fenêtre du bureau : FALSE ; coordonnées sur 16 bits, tailles de 0 à 32767 ; MoveWindow : sans ordre Z ni activation |

Le `WINDOWPOS` de WM_WINDOWPOSCHANGED donne la place dans la zone cliente du parent, comme le dit l'API (ReactOS y met
des coordonnées d'écran, les mêmes pour une fenêtre de premier niveau).

Le programme trouve le moniteur de sa fenêtre (0, 0, 1280 × 800, zone de travail identique, principal,
`\\.\DISPLAY1`), aucun loin de l'écran sauf le plus proche, et `ERROR_INVALID_FLAGS`. Sa fenêtre recouvrante
(`CW_USEDEFAULT`) est en 0, 0, 960 × 600 (zone cliente 952 × 572, `WNDS_MAXIMIZESTOMONITOR`), la suivante en 23, 23.
SetWindowPos la déplace en (50, 60) en 400 × 300 : `0046 0024 0083 0047 0003 0005`, le `WINDOWPOS` final (drapeaux
`0x1c`), WM_MOVE (54, 84), WM_SIZE 392 × 272 ; trop petite, elle prend 112 × 28 ; déplacée seulement,
`0046 0047 0003` ; MoveWindow la place en (100, 100), 300 × 200. Une fenêtre déplacée emmène sa fille ; la fille
déplacée reçoit `0046 0022 0047 0003` et WM_MOVE (20, 30) dans son parent. Deux fenêtres cachées changent de rang
(en haut, en bas, après l'autre, au premier plan puis hors de lui ; une seule reçoit `0046`), sont montrées et
cachées (`IsWindowVisible`). SetWindowPos d'une fenêtre inconnue, ou après elle : FALSE, 1400.

Correction : la numérotation des services de win32k. `tools/syscall-gen` suivait `w32ksvc32.h` sans `DBG` ; les
binaires publiés de ReactOS sont construits avec : cinq services de plus avant `NtGdiMakeObjectXferable`, et les 26
derniers numéros décalés (MonitorFromWindow de `user32` tombait sur `NtGdiDdDDICreateAllocation`). Les 1770 stubs
de `ntdll`, `user32` et `gdi32` s'accordent maintenant avec les tables, et `syscall-gen --check` (`cargo xtask lint`)
les vérifie quand l'espace utilisateur a été téléchargé.

Ce qui manque, journalisé une fois : les régions visibles (une fenêtre est visible avant si elle et ses parents le
sont et qu'elle n'est pas vide), repeindre ce qui a bougé et la copie des bits valides, l'activation et le premier
plan (aucune fenêtre n'y est ; une fenêtre de premier niveau qui s'active monte seulement en haut), garder les
fenêtres possédées au-dessus de leur propriétaire (WinPosDoOwnedPopups), `SWP_ASYNCWINDOWPOS` (fait tout de suite),
plusieurs moniteurs et la zone de travail réduite, DeferWindowPos, une fenêtre réduite ou agrandie.

Tests : hôte (`win32k::monitor` : le moniteur d'un rectangle, la cascade ; `win32k::window` : places par défaut sans
moniteur et sur un moniteur, `STARTUPINFO`, `CW_USEDEFAULT` sur 16 bits ; `win32k::defwnd` : limites de
WM_WINDOWPOSCHANGING, adaptation à la zone de travail ; `win32k::winpos` : drapeaux corrigés, rang déjà tenu,
activation, nouveaux rectangles ; `syscall-gen` : les stubs trouvés et vérifiés, les stubs du moniteur qui demandent
`DBG`) ; le scénario `gui`, sur les deux CPU.

## Étape 5 : ShowWindow

`ShowWindow` de `user32` appelle directement NtUserShowWindow. Comme co_WinPosShowWindow de ReactOS (`winpos.c`,
`window.c`, `main.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::winpos::show_window` | la commande du `STARTUPINFO` du processus (`STARTF_USESHOWWINDOW`, lu de ses paramètres au premier besoin) pour sa première fenêtre recouvrante à titre et sans propriétaire, et pour `SW_SHOWDEFAULT`, une seule fois ; les drapeaux de SetWindowPos de la commande (`show_command`) ; WM_SHOWWINDOW si la visibilité change (ou `SW_SHOWNA`) ; SetWindowPos (en haut, ou au premier plan) si ses parents sont visibles, sinon `WS_VISIBLE` seul ; puis WM_SIZE et WM_MOVE qui attendaient (`WNDS_SENDSIZEMOVEMSGS`, co_WinPosSendSizeMove) ; rend si elle était visible |
| `win32k::window::create_window` | une fenêtre créée avec `WS_VISIBLE` est montrée à la fin de sa création, avec `SW_SHOW` ou, pour une fenêtre recouvrante placée par défaut, la commande passée en `y` (IntFixWindowCoordinates) |
| NtUserShowWindow (`sys::window`) | une fenêtre qui n'existe pas : `ERROR_INVALID_WINDOW_HANDLE` ; la fenêtre du bureau : FALSE ; une commande au-delà de `SW_MAX` : `ERROR_INVALID_PARAMETER` |

Le programme montre une fenêtre recouvrante (`SW_SHOWNORMAL`) : `0018 0046 0047 0005 0003` (WM_SHOWWINDOW, SetWindowPos,
puis WM_SIZE 952 × 572 et WM_MOVE en (50, 70) qu'elle attendait), elle était cachée et devient visible ; `SW_SHOW`
d'une fenêtre visible ne fait rien et rend TRUE ; `SW_HIDE` la cache (`0018 0046 0047`), puis ne fait rien. La fille
d'une fenêtre cachée reçoit WM_SHOWWINDOW et `WS_VISIBLE`, sans être visible. Une commande de 12 : 87 ; une fenêtre
inconnue : 1400. Une fenêtre recouvrante créée visible avec `SW_SHOWNOACTIVATE` en `y` reçoit
`0024 0081 0083 0001 0018 0046 0047 0005 0003` (drapeaux de son `WINDOWPOS` : `0x1857`, sans activation ni ordre Z), une
fenêtre contextuelle créée visible `0081 0083 0001 0005 0003 0018 0046 0047`.

Les fenêtres montrées n'étaient pas encore peintes à cette étape : l'écran restait le fond du bureau (étape 6).

Ce qui manque, journalisé une fois : réduire et agrandir (co_WinPosMinMaximize : les commandes qui le demandent, ou
montrer une fenêtre réduite ou agrandie, ne font rien et rendent FALSE ; le placement des fenêtres, WINDOWPLACEMENT),
la fenêtre active, le premier plan et le focus (à cacher la fenêtre active, une autre devrait l'être), les fenêtres
possédées montrées et cachées avec leur propriétaire, ShowWindowAsync, la peinture.

Tests : hôte (`win32k::winpos` : les commandes et leurs drapeaux, le `STARTUPINFO` pour la première fenêtre
recouvrante seulement, une fois ; `win32k::window` : la commande en `y`) ; le scénario `gui`, sur les deux CPU.

## Étape 6 : peindre le cadre des fenêtres

Dans ReactOS, le cadre d'une fenêtre se dessine dans le noyau : `user32` passe WM_NCPAINT à NtUserMessageCall, et
DefWindowProc (NC_DoNCPaint) dessine avec GDI sans repasser par le mode utilisateur. Le fond de la zone cliente, lui,
passe par `user32` et `gdi32` (WM_ERASEBKGND : `GetClipBox`, `FillRect`, donc SelectObject et PatBlt sur un HDC du
client) : il attend la table des handles GDI partagée et les attributs des contextes de périphérique. Comme ReactOS
(`painting.c`, `vis.c`, `nonclient.c`, `draw.c`, `winpos.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::gdi::region` | des régions, unions de rectangles disjoints : coupe à un rectangle, retrait d'un rectangle, intersection |
| `win32k::gdi::draw` | des opérations de dessin (remplissage, dégradé horizontal), faites sur une surface, décalées à l'origine d'une fenêtre et coupées à une région ; DrawEdge (bords en relief et creux, normaux ou doux, milieu, ajustement) |
| `win32k::nonclient` | NC_DoNCPaint en opérations : bord en relief (ou statique), cadre épais (`COLOR_INACTIVEBORDER`) et fin, barre de titre en dégradé (SPI_GETGRADIENTCAPTIONS, vrai par défaut : `UPM_DEFAULT`), boutons fermer, réduire et agrandir (DrawFrameControl : relief doux et face), trait sous le titre, bord client creux ; ce qu'il ne dessine pas encore |
| `win32k::paint` | VIS_ComputeVisibleRegion (coupée aux zones clientes des parents, sans les sœurs visibles au-dessus) ; IntInvalidateWindows (cadre et fond à repeindre, avec les enfants visibles) ; co_IntPaintWindows et UserSyncAndPaintWindows (WM_NCPAINT aussitôt) ; DefWindowProc de WM_NCPAINT (le cadre, dans la région visible) ; ce qu'une fenêtre découvre : le fond du bureau s'y repeint, ses sœurs sont invalidées |
| `win32k::winpos::set_window_pos` | après le déplacement : la fenêtre visible est invalidée entière (pas de copie des bits valides), ce qu'elle découvre est exposé ; une fenêtre montrée, déplacée, redimensionnée ou dont le cadre change se repeint aussitôt (WM_NCPAINT avant WM_WINDOWPOSCHANGED) |

Une fenêtre montrée reçoit maintenant `0018 0046 0085 0047 0005 0003` (WM_NCPAINT entre WM_WINDOWPOSCHANGING et
WM_WINDOWPOSCHANGED). Sur la capture de l'écran, les fenêtres « Pending » (0, 0, 200 × 100) et « Visible » (69, 69,
960 × 600) ont leur cadre : bord en relief, titre en dégradé de `808080` vers `C0C0C0` (inactives : il n'y a pas
encore de fenêtre active), trait sous le titre, boutons ; « Pending », repeinte sous « Visible » (`SWP_FRAMECHANGED` :
`0046 0083 0085 0047`), est coupée par elle. Là où était « Shown » avant d'être cachée, le bureau est repeint. La
fille encadrée d'une fenêtre à `WS_CLIPCHILDREN` est coupée à la zone cliente de son parent. « Cover », montrée puis
cachée dans « Visible », y laisse son cadre : le bureau ne repeint pas par-dessus « Visible », qui n'est pas encore
repeinte. Les zones clientes ne sont pas effacées : on voit au travers ce qui était dessous.

Ce qui manque, journalisé une fois : WM_ERASEBKGND et WM_PAINT des fenêtres du client (contextes de périphérique),
le texte du titre et les symboles des boutons (polices, ADR-013), l'icône du titre, les barres de défilement, la
fenêtre active (tout cadre est dessiné inactif), une sœur découverte ne se repeint qu'à sa prochaine invalidation (pas
encore de WM_PAINT tiré de la file des messages), les fenêtres d'un autre thread, une partie seulement du cadre
(WM_NCPAINT avec une région), les régions de fenêtre, `WS_EX_TRANSPARENT`. Le dégradé interpole chaque composante
en ligne (le moteur de ReactOS, absent des sources épinglées, peut arrondir autrement) ; le bureau, sans thread à lui,
se repeint dans le thread qui le découvre.

Tests : hôte (`gdi::region` : bandes, intersection ; `gdi::draw` : bords en relief, creux, doux, milieu, un bord
intérieur seul, dégradés, origine et coupe ; `nonclient` : cadre d'une fenêtre recouvrante, boutons, titre actif et
inactif, cadres sans titre, bords statique et client, fenêtre d'outil, couleurs de chaque partie sur une palette
codée) ; le scénario `gui`, sur les deux CPU, avec seize pixels de la capture de l'écran.

## Étape 7 : effacer la zone cliente (la table des handles GDI, les DC, PatBlt en lot)

Le fond de la zone cliente s'efface en mode utilisateur : win32k envoie WM_ERASEBKGND avec un HDC qu'il prête,
`user32` (DefWindowProc) lit le pinceau de la classe (`GetClassLongPtrW(GCL_HBRBACKGROUND)`), demande la boîte de
découpage (`GetClipBox` : NtGdiGetAppClipBox) et la remplit (`FillRect` : `GetSysColorBrush` pour une couleur du
système plus un, `SelectObject`, `PatBlt`, `SelectObject`). `gdi32` ne fait presque rien par le noyau : il vérifie
chaque handle dans la table des handles GDI que win32k lui montre en lecture seule (`PEB.GdiSharedHandleTable`),
change le pinceau du DC dans les attributs du DC (`DC_ATTR`, dans la mémoire du processus, trouvés par l'entrée de la
table) et met PatBlt en lot dans le TEB (`GdiTebBatch`), que win32k exécute au retour du rappel (KeUserModeCallback,
`BatchFlushRoutine`) ou au service suivant du thread chez lui. Comme ReactOS (`gdiobj.c`, `stockobj.c`, `dclife.c`,
`dcattr.c`, `dcobjs.c`, `bitblt.c`, `cliprgn.c`, `gdibatch.c`, `windc.c`, `painting.c`, comme spécification ; les
décalages lus dans `gdi32` et `user32` épinglés) :

| Partie | Ce qu'elle fait |
|---|---|
| `abi::gdi` | l'entrée de la table (`GDI_TABLE_ENTRY`, 16 octets), `DEVCAPS`, `DC_ATTR` (0x1D0 octets), `GDI_TEB_BATCH` (dans le TEB en 0x1D4), `GDIBSPATBLT` (0x40 octets), les types de handles, les bits de `ulDirty_`, les ROP ; `SERVERINFO.ahbrSystem` (0x838) dans `abi::user` |
| `win32k::gdi::handles` | la table : une section du fichier d'échange (les entrées, puis les capacités de l'écran), projetée en lecture seule (`SEC_NO_CHANGE`) dans chaque processus GUI ; handle = `FullUnique << 16 \| index`, dix entrées réservées ; propriétaire (PID, public ou personne) et attributs de chaque objet ; objets de stock |
| `win32k::gdi::brush` | les pinceaux pleins et nul ; ceux de stock (WHITE_BRUSH à NULL_BRUSH) et des 31 couleurs du système, publics, ces derniers dans `ahbrSystem` |
| `win32k::gdi::dc` | les DC de l'écran : région visible, origine, pinceau ; pris par un processus, ils reçoivent des attributs neufs dans des blocs de 64 Kio de sa mémoire (GdiPoolAllocate), rendus au repos ; DC_vUpdateFillBrush (`DC_BRUSH_DIRTY`), PatBlt (tout ROP3 sans source, étendues négatives), GetClipBox (complexité de la région) |
| `win32k::gdi::batch` | les appels en lot du TEB : PatBlt exécuté avec le pinceau qu'il apporte, les autres sautés (journalisés une fois) ; le lot vidé |
| `win32k::dce` | le cache des DC de fenêtres (UserGetDCEx : `DCX_USESTYLE`, coupe aux enfants et aux sœurs, `DCX_INTERSECTRGN` et `DCX_EXCLUDERGN`, origine de la zone cliente ou de la fenêtre ; UserReleaseDC) |
| `win32k::paint` | co_IntPaintWindows : après WM_NCPAINT, WM_ERASEBKGND avec un DC du cache coupé à la région à mettre à jour ; une fenêtre qui rend 0 garde son fond à effacer |
| `sys::gdi` | NtGdiPatBlt, NtGdiGetAppClipBox, NtGdiFlush ; `sys::dispatch` exécute le lot avant chaque service de win32k, Ps après chaque rappel (`ps::callback::set_gdi_batch_flush`) |
| `win32k::gdi::dib` | PatBlt d'un pinceau plein par un ROP3 sans source quelconque (PATCOPY, PATINVERT, DSTINVERT, BLACKNESS…) |

Une fenêtre montrée reçoit maintenant `0018 0046 0085 0014 0047 0005 0003` (WM_ERASEBKGND après WM_NCPAINT). Le DC
de WM_ERASEBKGND de « Visible » donne `GetClipBox` 2 (une région simple : toute la zone cliente, 952 × 572) ; celui
de « Pending », repeinte sous « Visible », 3 (un L : une région complexe, de 192 × 72) ; rendu, il ne sert plus
(`GetClipBox` 0, `PatBlt` FALSE et `ERROR_INVALID_HANDLE` par NtGdiPatBlt, `gdi32` n'y trouvant plus d'attributs).
`GetSysColorBrush(COLOR_WINDOW)` est un pinceau de stock que `GetObjectType` reconnaît par la table seule. Sur la
capture, les zones clientes sont blanches (`COLOR_WINDOW + 1`) et coupées comme les cadres : le titre de « Visible »
reste au-dessus de la zone cliente de « Pending » ; « Clipper » (`WS_CLIPCHILDREN`), effacée de nouveau
(`SWP_FRAMECHANGED`), laisse le bord de sa fille. « Cover », d'une autre classe (`COLOR_HIGHLIGHT + 1`), trace 24
traits noirs (un PatBlt chacun : plus qu'un lot n'en tient, `gdi32` appelle NtGdiFlush au vingt et unième) puis un
trait du pinceau propre du DC, blanc.

La région à mettre à jour d'une fenêtre reste un rectangle (celui qui tient ce qui a été invalidé). Une région du
noyau n'est pas normalisée en bandes : la complexité de GetClipBox se tire de son aire (un seul rectangle exactement
quand ses rectangles disjoints remplissent leur boîte), ce qui donne le résultat de ReactOS. Un appel en lot plus court
que son enregistrement finit le lot (ReactOS lirait les octets suivants). Les attributs d'un DC repris sont toujours
neufs (IntGdiCleanDC ; `DCX_NORESETATTRS` n'est pas suivi).

Ce qui manque, journalisé une fois : WM_PAINT des fenêtres du client (tiré de la file, BeginPaint, EndPaint : la
région à mettre à jour reste, effacée), NtUserGetDCEx et NtUserReleaseDC, les DC d'une fenêtre ou d'une classe
(`CS_OWNDC`, `CS_CLASSDC` : un DC du cache), le DC du parent (`CS_PARENTDC`), les autres appels en lot (PolyPatBlt,
TextOut, SelectClipRgn, suppression d'objets…), et sans journal : les DC en mémoire, les pinceaux et autres objets
créés par un client (CreateSolidBrush, NtGdiGetStockObject), les stylos (`hpen` nul), les transformations (matrices à
zéro, `MM_TEXT`), les capacités de l'écran (`DevCaps` à zéro), la suppression des objets et les objets d'un processus
rendus à sa fin, les DC dont la fenêtre bouge pendant qu'ils sont pris.

Tests : hôte (`abi::gdi` : appel en lot relu, attributs d'un DC neuf ; `gdi::handles` : types, reprises, bit de stock,
propriétaires, table pleine, ce que vérifie GdiValidateHandle ; `gdi::dc` : ROP avec source, rectangle de PatBlt,
DC_vUpdateFillBrush, boîte de découpage, blocs d'attributs ; `gdi::batch` : appels suivis, lot coupé ; `gdi::dib` :
les ROP3 sans source ; `dce` : `DCX_USESTYLE`) ; l'auto-test du noyau (scénario `smoke` : la table en lecture seule
dans le PEB, WHITE_BRUSH et le pinceau de `COLOR_WINDOW` publics) ; le scénario `gui`, sur les deux CPU, avec 32 pixels
de la capture de l'écran.

## Étape 8 : WM_PAINT, BeginPaint et EndPaint

Une fenêtre peinte jusqu'ici l'était aussitôt (cadre et fond, étape 7), mais jamais validée : sa région à mettre à
jour restait. WM_PAINT n'est pas posté dans la file : comme dans ReactOS (`painting.c`, `message.c`, `msgqueue.c`,
`defwnd.c`, comme spécification), un compte des fenêtres à peindre de chaque thread (`cPaintsReady`, `QS_PAINT` tant
qu'il n'est pas nul) dit à PeekMessage et GetMessage, une fois les messages postés et WM_QUIT sortis, de chercher la
première fenêtre du thread qui a quelque chose à peindre (IntFindWindowToRepaint : dans l'ordre Z, un parent avant
ses enfants) et de lui donner WM_PAINT, tant qu'elle n'est pas validée. `user32` passe WM_PAINT par
NtUserDispatchMessage, qui appelle la procédure ; DefWindowProc (NtUserMessageCall) fait BeginPaint et EndPaint.

| Partie | Ce qu'elle fait |
|---|---|
| `abi::user` | `PAINTSTRUCT` (64 octets), `QS_PAINT`, `WNDS_INTERNALPAINT`, `WNDS_UPDATEDIRTY`, `WNDS_PAINTNOTPROCESSED`, `WNDS2_WMPAINTSENT`, `WNDS2_STARTPAINT`, WM_PAINTICON, WM_TIMER |
| `win32k::queue` | le compte des fenêtres à peindre et `QS_PAINT` (MsqIncPaintCountQueue, MsqDecPaintCountQueue) ; PeekMessage cherche WM_PAINT quand il n'y a plus de message posté ; WaitMessage revient aussi pour `QS_PAINT` |
| `win32k::window` | chaque changement d'une fenêtre compte pour son thread si elle se met à avoir quelque chose à peindre (visible, région à mettre à jour ou `WNDS_INTERNALPAINT`) ou cesse de l'avoir ; IntDispatchMessage : WM_PAINT à la procédure, puis cadre et fond repeints si elle n'a pas appelé BeginPaint |
| `win32k::paint` | IntGetPaintMessage (filtre : la fenêtre ou l'un de ses parents, l'intervalle ; pas les messages du seul thread), IntFindWindowToRepaint, IntBeginPaint (cadre, DC du cache coupé à la région à mettre à jour, région validée, `rcPaint` par GetClipBox, WM_ERASEBKGND, cadre des enfants), IntEndPaint, DefWindowProc de WM_PAINT |
| `win32k::dce` | `DCX_INTERSECTRGN` sans région : un DC qui ne peint rien (DceUpdateVisRgn) |
| `win32k::gui` | le `THREADINFO` d'une fenêtre, par l'adresse du serveur de son thread (`pti`) |
| `sys` | NtUserBeginPaint, NtUserEndPaint, NtUserDispatchMessage |

Dans `gui`, une boucle de messages (PeekMessage, DispatchMessage) suit les fenêtres créées : `GetQueueStatus(QS_PAINT)`
vaut `00200020` avant, 0 après ; WM_PAINT va six fois, dans l'ordre Z, à « Popup », « Striped », « Clipper », sa fille
« Framed » (dont le cadre et le fond, invalidés avec ceux de son parent, se repeignent dans BeginPaint), « Visible »
(découverte par « Cover » : son cadre et son fond se repeignent, et les restes de « Cover » disparaissent de la
capture), puis « Pending ». Le popup se peint lui-même entre BeginPaint et EndPaint (un carré noir) : `rcPaint` est sa
zone cliente, `fErase` 0 (son fond déjà effacé) ; le DC rendu par EndPaint, PatBlt le refuse. PeekMessage ne donne
WM_PAINT qu'au filtre qui le demande : la fenêtre ou un de ses parents (une autre fenêtre : rien tant que le popup, au
premier plan, est à peindre), pas les messages du seul thread, pas un intervalle au-delà de WM_PAINT.

Un écart avec ReactOS : le compte des fenêtres à peindre est tenu à chaque changement d'une fenêtre (`window::change`),
y compris quand elle se cache ou se montre ; il reste exact, et IntGetPaintMessage n'a pas à le remettre à zéro quand
il ne trouve plus de fenêtre (ReactOS le fait, avec un message d'erreur, une fenêtre cachée gardant sa région).

Ce qui manque : InvalidateRect, ValidateRect, RedrawWindow, UpdateWindow, GetUpdateRect et GetUpdateRgn (les régions
à mettre à jour ne viennent que du noyau), WM_SYNCPAINT, WM_TIMER et les procédures de minuterie de DispatchMessage
(journalisé une fois), le curseur caché pendant BeginPaint, le dessin de l'icône d'une fenêtre réduite. Sans test (des
mutations qui les retirent survivent) : une procédure qui ne fait pas BeginPaint pour WM_PAINT (son cadre et son fond
repeints par IntDispatchMessage ; elle reçoit WM_PAINT de nouveau, comme dans ReactOS), le cadre des enfants repeint
par BeginPaint (aucun enfant de `gui` n'a son seul cadre à repeindre), le DC de BeginPaint coupé à la région à mettre
à jour (elle couvre toujours toute la zone cliente), WM_PAINT réservé aux fenêtres du thread (`gui` n'a qu'un thread
GUI).

Tests : hôte (`queue` : compte et `QS_PAINT` ; `paint` : fenêtre à peindre, filtre de WM_PAINT ; `dce` : coupe d'un
DC ; `gui` : thread d'une adresse du serveur ; `abi::user` : `PAINTSTRUCT`) ; le scénario `gui`, sur les deux CPU, avec
les fenêtres peintes par la boucle de messages et 36 pixels de la capture.

## Étape 9 : InvalidateRect, ValidateRect, RedrawWindow, UpdateWindow, GetUpdateRect

Le client demande lui-même à repeindre : `user32` passe InvalidateRect, ValidateRect et RedrawWindow à
NtUserInvalidateRect, NtUserValidateRect et NtUserRedrawWindow, UpdateWindow à NtUserCallHwndLock
(`HWNDLOCK_ROUTINE_UPDATEWINDOW`, 0x5E), GetUpdateRect à NtUserGetUpdateRect ; il lit d'abord lui-même `WND.hrgnUpdate`
(0x68) et l'enfant (`spwndChild`, 0x38) pour ne pas appeler le noyau sans rien à faire. Comme ReactOS (`painting.c`,
`simplecall.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::gdi::region` | l'union d'une région et d'un rectangle (ses rectangles restent disjoints), son rectangle englobant |
| `win32k::window` | la région à mettre à jour devient une région (dans la zone cliente, depuis son coin) ; `WND.hrgnUpdate` vaut `HRGN_WINDOW` tant qu'elle n'est pas vide, faute d'objets région de GDI (`user32` ne fait que le comparer à NULL) |
| `win32k::paint` | IntInvalidateWindows (`RDW_INVALIDATE`, `RDW_FRAME`, `RDW_ERASE`, `RDW_INTERNALPAINT` ; `RDW_VALIDATE`, `RDW_NOFRAME`, `RDW_NOERASE`, `RDW_NOINTERNALPAINT` ; les enfants visibles, sauf `RDW_NOCHILDREN` ou ceux d'un parent à `WS_CLIPCHILDREN` sans `RDW_ALLCHILDREN` ; `WNDS_UPDATEDIRTY` pour une fenêtre d'un autre thread), co_UserRedrawWindow (le rectangle ou la fenêtre, puis `RDW_UPDATENOW` ou `RDW_ERASENOW` ; rien pour une fenêtre qu'on ne voit pas), co_IntUpdateWindows (WM_PAINT envoyé aussitôt, puis aux enfants ; IntValidateParents), co_UserGetUpdateRect (le rectangle englobant, coupé à la zone cliente et aux parents ; `bErase` : cadre et fond d'abord) ; l'invalidation d'une fenêtre montrée ou déplacée y passe aussi |
| `sys::window` | NtUserRedrawWindow (drapeaux vérifiés : `ERROR_INVALID_FLAGS`), NtUserInvalidateRect, NtUserValidateRect (hWnd nul : tout le bureau), NtUserGetUpdateRect, NtUserCallHwndLock (`UPDATEWINDOW` ; les autres routines journalisées) |

Dans `gui`, après la boucle de messages : deux rectangles disjoints invalidés dans « Visible » donnent un rectangle
englobant de 10, 10 à 120, 60 ; validés l'un après l'autre, il ne reste rien (une région, non un rectangle) et
`QS_PAINT` s'éteint. UpdateWindow du popup invalidé et à effacer lui envoie WM_PAINT aussitôt (`000f 0014`) : son
premier carré disparaît, le second est dessiné 12 pixels plus loin. RedrawWindow(`RDW_ERASENOW`) d'un coin de 5 × 5
pixels l'efface aussitôt (`0014`, visible sur la capture) sans le valider (GetUpdateRect : 12, 0, 17, 5 ; `QS_PAINT`) ;
GetUpdateRect(`TRUE`) l'efface de nouveau ; ValidateRect le valide. `RDW_UPDATENOW` avec `RDW_FRAME` : WM_PAINT, où
BeginPaint repeint le cadre et efface (`000f 0085 0014`). `RDW_INTERNALPAINT` : pas de région, mais `QS_PAINT` et
WM_PAINT, puis plus rien. « Clipper » (`WS_CLIPCHILDREN`) n'invalide sa fille qu'avec `RDW_ALLCHILDREN`, et
UpdateWindow les peint l'un puis l'autre (`000f 0014 000f 0085 0014` : la fille invalidée avec son cadre). Une
fenêtre jamais montrée n'est pas invalidée ; un drapeau inconnu est refusé (1004). InvalidateRect sans effacer :
WM_PAINT n'efface pas (`000f`) ; un fond à effacer, validé, ne l'est plus. Un parent sans `WS_CLIPCHILDREN`
invalide sa fille ; UpdateWindow de la fille valide sa part dans la région du parent (il lui reste 0, 20, 192, 72) ;
sa procédure ne faisant pas BeginPaint, son cadre et son fond sont repeints quand même (`000f 0085 0014`), et elle
reste à peindre.

Ce qui manque : InvalidateRgn, ValidateRgn, GetUpdateRgn et RedrawWindow avec une région (pas encore d'objets région
de GDI : `ERROR_NOT_ENOUGH_MEMORY`, journalisé une fois ; faits à l'étape 10), le fond du bureau repeint à la demande (RedrawWindow,
InvalidateRect de NULL : journalisé une fois ; ses fenêtres le sont), WM_SYNCPAINT et `WNDS_SYNCPAINTPENDING`, la
région de fenêtre (SetWindowRgn), le passage en coordonnées logiques d'une fenêtre `CS_OWNDC` dans GetUpdateRect.
Sans test : la validation refusée d'une fenêtre invalidée par un autre thread (`WNDS_UPDATEDIRTY` : `gui` n'a qu'un
thread GUI). Mutation équivalente : ôter l'effacement oublié quand la validation vide la région (BeginPaint n'efface
pas une région vide, et le cadre et le fond repeints aussitôt oublient eux-mêmes un fond sans région).

Tests : hôte (`gdi::region` : union disjointe, rectangle englobant ; `window` : région à mettre à jour ;
`paint` : région de l'écran dans la zone cliente) ; le scénario `gui`, sur les deux CPU, avec 42 pixels de la capture.

## Étape 10 : GetDC et ReleaseDC, les régions de GDI, InvalidateRgn, ValidateRgn, GetUpdateRgn

Le client prend lui-même un DC pour peindre hors de WM_PAINT, et se sert de régions. `user32` passe GetDC, GetDCEx et
GetWindowDC à NtUserGetDC, NtUserGetDCEx et NtUserGetWindowDC, ReleaseDC à NtUserCallOneParam
(`ONEPARAM_ROUTINE_RELEASEDC`, 0x39 : `user32!ReleaseDC` le pousse), ValidateRgn à NtUserCallHwndParamLock
(`TWOPARAM_ROUTINE_VALIDATERGN`, 0x65), InvalidateRgn et GetUpdateRgn à NtUserInvalidateRgn et NtUserGetUpdateRgn.
`gdi32` crée une région par NtGdiCreateRectRgn, puis la tient lui-même tant qu'elle est vide ou rectangulaire : il en
lit et en écrit les attributs (`RGN_ATTR`, dans la mémoire du processus, nommés par l'entrée de la table des handles),
en les marquant `ATTR_RGN_DIRTY` (SetRectRgn, CombineRgn de deux rectangles quand le résultat en est un) ; pour le
reste, il appelle NtGdiCombineRgn et NtGdiGetRgnBox. DeleteObject d'une région et SelectClipRgn (`RGN_COPY` d'un
rectangle ou d'aucune région) vont dans le lot du TEB ; DeleteDC appelle NtGdiDeleteObjectApp. Comme ReactOS
(`region.c`, `cliprgn.c`, `gdiobj.c`, `gdibatch.c`, `windc.c`, `painting.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `abi::gdi` | `RGN_ATTR` et ses drapeaux (`ATTR_RGN_VALID`, `ATTR_RGN_DIRTY`), `RGN_AND` … `RGN_COPY`, les appels en lot `GDIBSEXTSELCLPRGN` (24 octets, `GDIBS_NORECT`) et `GDIBSOBJECT` (8 octets) |
| `abi::user` | `ONEPARAM_ROUTINE_RELEASEDC`, `TWOPARAM_ROUTINE_VALIDATERGN`, `DCX_NOCLIPCHILDREN` |
| `win32k::gdi::region` | IntGdiCombineRgn (`RGN_AND`, `RGN_OR`, `RGN_XOR`, `RGN_DIFF`, `RGN_COPY`), REGION_Complexity (une région est un rectangle quand ses morceaux remplissent le rectangle qui les tient), REGION_SetRectRgn (coins dans n'importe quel ordre), un déplacement qui ne dépasse pas les entiers |
| `win32k::gdi::handles` | une entrée rendue (ENTRY_vPushFreeEntry) perd type, propriétaire et attributs et compte une reprise de plus ; les entrées rendues sont reprises les premières (la dernière d'abord) ; GreDeleteObject (ni de stock, ni publique, au processus) |
| `win32k::gdi::rgnobj` | les régions d'un client : leurs attributs pris dans des blocs de sa mémoire (`pPoolRgnAttr`), repris avant chaque usage (REGION_vSyncRegion) et réécrits après (REGION_UnlockRgn) ; NtGdiCreateRectRgn ; la suppression rend les attributs |
| `win32k::gdi::dc` | la région de découpage d'un DC (`dclevel.prgnClip`, depuis son origine) et là où il peint (`prgnRao`) ; IntGdiExtSelectClipRgn et IntSelectClipRgn (sans région de découpage, un mode la combine au rectangle qui tient la région visible ; `RGN_AND` la prend telle quelle), IntGdiExtSelectClipRect (le SelectClipRgn en lot) ; `VisRectRegion` des attributs écrit à la prise du DC (`gdi32` en tire ce que rend un SelectClipRgn en lot) ; GetClipBox et PatBlt sur `prgnRao` |
| `win32k::gdi::batch` | SelectClipRgn et DeleteObject (d'une région ou d'un objet) en lot |
| `win32k::dce` | les règles des `DCX_*` de UserGetDCEx au complet (sans fenêtre : tout l'écran, du cache ; une fenêtre qui n'est pas un enfant coupe toujours ses sœurs ; `DCX_NOCLIPCHILDREN` ; le DC du parent seulement pour qui ne coupe ni sœurs ni enfants) ; la région d'un client donnée à GetDCEx, à l'écran, au DC jusqu'à sa remise où elle est supprimée sauf `DCX_KEEPCLIPRGN` ; `HRGN_WINDOW` ; seul le processus qui a pris un DC le rend |
| `win32k::paint` | co_UserRedrawWindow avec une région (dans la zone cliente, elle l'emporte sur le rectangle), co_UserGetUpdateRgn (la région à mettre à jour coupée à la zone cliente et aux parents, dans la zone cliente) |
| `sys::gdi` | NtGdiCreateRectRgn, NtGdiCombineRgn, NtGdiGetRgnBox, NtGdiDeleteObjectApp, NtGdiExtSelectClipRgn |
| `sys::window` | NtUserGetDC, NtUserGetDCEx, NtUserGetWindowDC, NtUserInvalidateRgn, NtUserGetUpdateRgn, NtUserCallHwndParamLock (`VALIDATERGN` ; les autres routines journalisées), NtUserRedrawWindow avec une région |
| `sys::message` | `ONEPARAM_ROUTINE_RELEASEDC` |

Dans `gui`, après les tests de l'étape 9, un popup « Regions » de 200 × 150 pixels en 1050, 600 :

- Régions : une région créée aux coins inversés tient de 0, 0 à 100, 100 (GetRgnBox, lu par `gdi32` dans ses
  attributs) ; avec une autre de 50, 50 à 150, 150, `RGN_OR` (dans le noyau) donne une région complexe de 0, 0 à
  150, 150, `RGN_AND` (dans `gdi32`) le rectangle commun, `RGN_DIFF` (dans le noyau) un L ; SetRectRgn (dans `gdi32`)
  puis `RGN_OR` : le noyau reprend le rectangle changé (10, 10 à 150, 150) ; sans seconde région, CombineRgn rend
  ERROR (6). DeleteObject, en lot : GetObjectType et GetRgnBox ne trouvent plus rien, et la région suivante reprend
  l'entrée, avec un compte de reprises de plus.
- DC : GetDC donne la zone cliente (GetClipBox 0, 0, 200, 150), où PatBlt noircit le coin ; ReleaseDC le rend une
  fois (1, puis 0 ; PatBlt le refuse ensuite) ; DeleteDC aussi (1, puis ReleaseDC 0 et DeleteDC 0 avec l'erreur 6).
  GetWindowDC de « Plain » : toute la fenêtre (200 × 100), dont le coin du cadre noircit ; GetDC(NULL) : tout l'écran
  (1280 × 800), sur le bureau. GetDCEx(`DCX_INTERSECTRGN`) d'une région de l'écran : GetClipBox 50, 50, 70, 70, seul ce
  carré noircit, et la région est supprimée à la remise ; avec `DCX_EXCLUDERGN | DCX_KEEPCLIPRGN`, un DC complexe, et
  la région reste.
- Découpage : SelectClipRgn d'un carré (en lot ; 2, d'après `VisRectRegion`) puis GetClipBox (120, 0, 140, 20) ;
  PatBlt de toute la zone cliente ne noircit que le carré ; ExtSelectClipRgn(`RGN_OR`) d'un autre (dans le noyau) rend
  3 ; SelectClipRgn d'une région hors de la fenêtre rend 1, d'aucune région 2 (GetClipBox : toute la zone cliente).
- Région à mettre à jour : deux InvalidateRgn, GetUpdateRgn rend 3 (10, 10 à 60, 60) ; ValidateRgn de l'une, 2 (l'autre
  seule) ; ValidateRgn(NULL), 1 (rien). InvalidateRgn(NULL) : 0 (1400). InvalidateRgn sans effacer, puis UpdateWindow :
  WM_PAINT seul. RedrawWindow(`RDW_ERASENOW`) d'une région de 10, 10 à 30, 30 efface aussitôt ce carré (`0014`, et le
  coin noir coupé sur la capture) sans le valider (GetUpdateRgn : 2). « Plain » validé puis invalidé dans sa seule
  barre de titre (`RDW_FRAME`) : `user32`, qui voit `WNDS_SENDNCPAINT`, demande au noyau, qui vide la région donnée
  (GetUpdateRgn : 1).

Écarts avec ReactOS : sans `DCX_CACHE`, une fenêtre sans DC à elle a un DC du cache, comme dans XP (`DCX_CACHE` ne fait
que passer outre `CS_OWNDC` et `CS_CLASSDC`) et Wine (ReactOS rend NULL) ; seul le processus qui a pris un DC le rend
(ReactOS ne vérifie pas, et rendrait les attributs au mauvais processus) ; `VisRectRegion` est écrit à la prise du DC
(ReactOS l'écrit au premier dessin, CLIPPING_UpdateGCRegion). `WND.hrgnUpdate` reste `HRGN_WINDOW` tant que la région à
mettre à jour n'est pas vide : `user32` ne fait que le comparer à NULL.

Ce qui manque : NtGdiSetRectRgn (`gdi32` change lui-même une région qui a ses attributs), les autres formes de région
(ellipses, polygones, ExtCreateRegion), OffsetRgn, EqualRgn, PtInRegion, RectInRegion, GetRegionData, GetClipRgn,
ExcludeClipRect, IntersectClipRect, OffsetClipRgn, SetMetaRgn, `DCX_INTERSECTUPDATE` (journalisé une fois), les DC
d'une fenêtre ou d'une classe (`CS_OWNDC`, `CS_CLASSDC` : un DC du cache, journalisé une fois), les régions et les DC
d'un processus rendus à sa fin, le cache de handles du PEB. Sans test : NtGdiDeleteObjectApp d'un autre objet qu'un DC
(`gdi32` met en lot la suppression d'une région), le refus de rendre le DC d'un autre processus (`gui` n'a qu'un
processus GUI), le libre des attributs d'une région supprimée (une fuite n'a pas d'effet visible). Les 27 mutations
des autres parties sont tuées ; un `|` dans un marqueur `expect` en fait deux marqueurs au choix (`xtask`) : le
message de `DCX_EXCLUDERGN, DCX_KEEPCLIPRGN` n'en a plus.

Tests : hôte (`abi::gdi` : appels en lot et attributs relus ; `gdi::region` : CombineRgn, complexité, coins,
déplacement ; `gdi::handles` : entrée rendue puis reprise ; `gdi::rgnobj` : attributs repris et réécrits ;
`gdi::dc` : région de découpage, modes, rectangle en lot, `VisRectRegion`, place des attributs d'une région ;
`gdi::batch` : appels lus ; `dce` : règles des `DCX_*`) ; le scénario `gui`, sur les deux CPU, avec 57 pixels de la
capture.
