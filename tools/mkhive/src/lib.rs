//! `mkhive` (ADR-012, ADR-023) : les ruches du disque de Mino. Aujourd'hui,
//! la couche Mino ([`MINO_LAYER`], `mino.inf`) appliquée par `xtask` aux
//! ruches de la version épinglée de ReactOS ; plus tard, les ruches de base
//! générées des `.inf` de ReactOS (`hivesys`, `hivesft`, `hivedef`…), sous la
//! même couche.
//!
//! Une couche est un `.inf` dans la syntaxe de celles de ReactOS
//! (`boot/bootdata/livecd.inf`, comme spécification) : une section
//! `[DelReg]`, appliquée d'abord, puis `[AddReg]`. Chaque ligne nomme une
//! racine (`HKLM`, `HKCU`, `HKU`, `HKCR`), une clé, et au besoin une valeur,
//! ses drapeaux et ses données. Ce qui est lu ([`parse`]) :
//!
//! - commentaires `;`, continuation par `\` en fin de ligne, champs séparés
//!   par des virgules, guillemets (`""` pour un guillemet) ;
//! - les types de `[AddReg]` : chaîne (`0x00000000`), binaire
//!   (`0x00000001`), `REG_MULTI_SZ` (`0x00010000`), `REG_EXPAND_SZ`
//!   (`0x00020000`), `REG_DWORD` (`0x00010001`), `REG_NONE` (`0x00020001`) ;
//!   les modificateurs « ne pas écraser » (`0x2`), « supprimer la valeur »
//!   (`0x4`), « ajouter à la liste » (`0x8`, une `REG_MULTI_SZ`) et « la clé
//!   seule » (`0x10`). Un autre drapeau est une erreur.
//!
//! Où va une ligne ([`apply`]) : `HKLM\SYSTEM`, `SOFTWARE`, `SAM`,
//! `SECURITY` dans la ruche de ce nom ; `HKCU` et `HKU\.DEFAULT` dans la
//! ruche `DEFAULT` ; `HKCR` dans `SOFTWARE\Classes`. Dans SYSTEM,
//! `CurrentControlSet` est le jeu que nomme `Select\Current`, comme le fait
//! le `mkhive` de ReactOS (il n'y a pas encore de lien).

use std::collections::BTreeMap;

use regf::builder::{KeyNode, ValueNode};

/// La couche Mino des ruches (ADR-023).
pub const MINO_LAYER: &str = include_str!("../mino.inf");

/// Les ruches qu'une couche peut changer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hive {
    System,
    Software,
    Sam,
    Security,
    Default,
}

impl Hive {
    /// Toutes, dans l'ordre.
    pub const ALL: [Hive; 5] = [Hive::System, Hive::Software, Hive::Sam, Hive::Security, Hive::Default];

    /// Son nom de fichier dans `system32\config`, en minuscules comme dans la
    /// version épinglée.
    pub fn file_name(self) -> &'static str {
        match self {
            Hive::System => "system",
            Hive::Software => "software",
            Hive::Sam => "sam",
            Hive::Security => "security",
            Hive::Default => "default",
        }
    }
}

const REG_NONE: u32 = 0;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;

const FLG_NOCLOBBER: u32 = 0x2;
const FLG_DELVAL: u32 = 0x4;
const FLG_APPEND: u32 = 0x8;
const FLG_KEYONLY: u32 = 0x10;
/// Les bits du type : `0x00000001` (binaire) et le mot haut.
const TYPE_MASK: u32 = 0xFFFF_0001;

/// Ce que fait une ligne de `[AddReg]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Créer la clé, sans valeur.
    Key,
    /// Poser la valeur (sauf si elle existe et `keep_existing`).
    Set { name: String, data_type: u32, data: Vec<u8>, keep_existing: bool },
    /// Ajouter des chaînes à une `REG_MULTI_SZ`, celles qui n'y sont pas.
    Append { name: String, strings: Vec<String> },
    /// Supprimer une valeur.
    DeleteValue { name: String },
    /// Supprimer la clé et tout ce qu'elle contient.
    DeleteKey,
}

/// Une ligne, rapportée à sa ruche.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub hive: Hive,
    /// Le chemin de la clé dans la ruche, `\` entre les noms.
    pub path: String,
    pub action: Action,
    /// Où elle est dans le `.inf` (numéro de ligne), pour les erreurs.
    pub line: usize,
}

/// Une couche lue : ses suppressions, puis ses ajouts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layer {
    pub delete: Vec<Entry>,
    pub add: Vec<Entry>,
}

impl Layer {
    /// Les ruches que la couche change.
    pub fn hives(&self) -> Vec<Hive> {
        let mut hives: Vec<Hive> = self.delete.iter().chain(&self.add).map(|entry| entry.hive).collect();
        hives.sort();
        hives.dedup();
        hives
    }
}

/// Lit une couche (`.inf`) : ses sections `[DelReg]` et `[AddReg]` ; les
/// autres sont ignorées.
///
/// # Errors
/// La ligne et ce qui ne va pas : une racine, un drapeau ou une donnée
/// inconnus, des guillemets non fermés.
pub fn parse(text: &str) -> Result<Layer, String> {
    let mut layer = Layer::default();
    let mut section = String::new();
    for (number, line) in logical_lines(text) {
        let at = |why: String| format!("line {number}: {why}");
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix('[') {
            let name = name.strip_suffix(']').ok_or_else(|| at("a section without `]`".into()))?;
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        if section != "addreg" && section != "delreg" {
            continue;
        }
        let fields = fields(&line).map_err(at)?;
        if fields.iter().all(|f| f.is_empty()) {
            continue;
        }
        let (hive, path) =
            route(fields.first().map(String::as_str).unwrap_or(""), fields.get(1).map(String::as_str)).map_err(at)?;
        let value_name = fields.get(2).cloned();
        let action = if section == "delreg" {
            match value_name {
                Some(name) => Action::DeleteValue { name },
                None => Action::DeleteKey,
            }
        } else {
            add_action(value_name, fields.get(3).map(String::as_str), &fields[fields.len().min(4)..]).map_err(at)?
        };
        let entry = Entry { hive, path, action, line: number };
        if section == "delreg" {
            layer.delete.push(entry);
        } else {
            layer.add.push(entry);
        }
    }
    Ok(layer)
}

/// Les lignes logiques : sans commentaire, les continuations (`\` final)
/// jointes, avec le numéro de leur première ligne.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut lines = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = strip_comment(raw);
        let (start, mut joined) = pending.take().unwrap_or((index + 1, String::new()));
        let trimmed = line.trim_end();
        if let Some(head) = trimmed.strip_suffix('\\') {
            joined.push_str(head);
            pending = Some((start, joined));
            continue;
        }
        joined.push_str(trimmed);
        lines.push((start, joined));
    }
    if let Some(last) = pending {
        lines.push(last);
    }
    lines
}

/// La ligne sans son commentaire (`;` hors des guillemets).
fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (at, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => return &line[..at],
            _ => {}
        }
    }
    line
}

/// Les champs d'une ligne : séparés par des virgules hors des guillemets,
/// sans les blancs autour ni les guillemets ; `""` dans des guillemets est
/// un guillemet.
fn fields(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(core::mem::take(&mut field)),
            _ if !quoted && c.is_whitespace() => {}
            _ => field.push(c),
        }
    }
    if quoted {
        return Err("a quote is not closed".into());
    }
    fields.push(field);
    Ok(fields)
}

/// La ruche et le chemin d'une racine et d'une clé.
fn route(root: &str, key: Option<&str>) -> Result<(Hive, String), String> {
    let key = key.unwrap_or("").trim_matches('\\');
    let (first, rest) = key.split_once('\\').unwrap_or((key, ""));
    match root.to_ascii_uppercase().as_str() {
        "HKLM" => {
            let hive = match first.to_ascii_uppercase().as_str() {
                "SYSTEM" => Hive::System,
                "SOFTWARE" => Hive::Software,
                "SAM" => Hive::Sam,
                "SECURITY" => Hive::Security,
                _ => return Err(format!("HKLM\\{first}: not a hive of the disk")),
            };
            Ok((hive, rest.to_string()))
        }
        "HKCU" => Ok((Hive::Default, key.to_string())),
        "HKU" if first.eq_ignore_ascii_case(".DEFAULT") => Ok((Hive::Default, rest.to_string())),
        "HKCR" => Ok((Hive::Software, if key.is_empty() { "Classes".into() } else { format!("Classes\\{key}") })),
        _ => Err(format!("`{root}\\{key}`: an unknown root")),
    }
}

/// L'action d'une ligne de `[AddReg]` : nom de valeur, drapeaux, données.
fn add_action(name: Option<String>, flags: Option<&str>, data: &[String]) -> Result<Action, String> {
    let flags = match flags {
        None | Some("") => 0,
        Some(text) => number(text)?,
    };
    let modifiers = flags & !TYPE_MASK;
    if modifiers & !(FLG_NOCLOBBER | FLG_DELVAL | FLG_APPEND | FLG_KEYONLY) != 0 {
        return Err(format!("flags {flags:#010x}: not read here"));
    }
    if modifiers & FLG_KEYONLY != 0 || (name.is_none() && data.is_empty()) {
        return Ok(Action::Key);
    }
    let name = name.unwrap_or_default();
    if modifiers & FLG_DELVAL != 0 {
        return Ok(Action::DeleteValue { name });
    }
    let data_type = match flags & TYPE_MASK {
        0x0000_0000 => REG_SZ,
        0x0000_0001 => REG_BINARY,
        0x0001_0000 => REG_MULTI_SZ,
        0x0002_0000 => REG_EXPAND_SZ,
        0x0001_0001 => REG_DWORD,
        0x0002_0001 => REG_NONE,
        other => return Err(format!("type flags {other:#010x}: not read here")),
    };
    if modifiers & FLG_APPEND != 0 {
        if data_type != REG_MULTI_SZ {
            return Err("append (0x8) is for a REG_MULTI_SZ".into());
        }
        return Ok(Action::Append { name, strings: data.to_vec() });
    }
    let data = match data_type {
        REG_SZ | REG_EXPAND_SZ => utf16z(data.first().map(String::as_str).unwrap_or("")),
        REG_MULTI_SZ => multi_sz(data),
        REG_DWORD => number(data.first().map(String::as_str).unwrap_or("0"))?.to_le_bytes().to_vec(),
        _ => data
            .iter()
            .map(|byte| u8::from_str_radix(byte.trim_start_matches("0x"), 16))
            .collect::<Result<_, _>>()
            .map_err(|_| "binary data: hexadecimal bytes".to_string())?,
    };
    Ok(Action::Set { name, data_type, data, keep_existing: modifiers & FLG_NOCLOBBER != 0 })
}

/// Un nombre : hexadécimal (`0x…`) ou décimal.
fn number(text: &str) -> Result<u32, String> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| format!("`{text}`: not a number"))
}

/// Une chaîne en UTF-16, terminée par un zéro.
fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// Les chaînes d'une `REG_MULTI_SZ`, chacune terminée, puis un zéro.
fn multi_sz(strings: &[String]) -> Vec<u8> {
    let mut data: Vec<u8> = strings.iter().flat_map(|s| utf16z(s)).collect();
    data.extend([0, 0]);
    data
}

/// Les chaînes d'une `REG_MULTI_SZ`.
fn strings_of(data: &[u8]) -> Vec<String> {
    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units).split('\0').filter(|s| !s.is_empty()).map(String::from).collect()
}

/// Applique `layer` aux ruches `hives` (leur arbre, [`KeyNode::read`]) :
/// `[DelReg]` d'abord, puis `[AddReg]`, dans l'ordre des lignes.
///
/// # Errors
/// Une ligne pour une ruche absente de `hives`.
pub fn apply(layer: &Layer, hives: &mut BTreeMap<Hive, KeyNode>) -> Result<(), String> {
    // The current control set as the base hive names it, before any line.
    let current = hives.get(&Hive::System).map(current_control_set).unwrap_or(1);
    for entry in layer.delete.iter().chain(&layer.add) {
        let root =
            hives.get_mut(&entry.hive).ok_or_else(|| format!("line {}: no {:?} hive", entry.line, entry.hive))?;
        let path = control_set_path(current, entry.hive, &entry.path);
        match &entry.action {
            Action::DeleteKey => {
                remove_key(root, &path);
            }
            Action::DeleteValue { name } => {
                if let Some(key) = find_key(root, &path) {
                    key.values.retain(|value| !value.name.eq_ignore_ascii_case(name));
                }
            }
            Action::Key => {
                root.key_mut(&path);
            }
            Action::Set { name, data_type, data, keep_existing } => {
                let key = root.key_mut(&path);
                let exists = key.values.iter().any(|value| value.name.eq_ignore_ascii_case(name));
                if !(*keep_existing && exists) {
                    key.set_value(name, *data_type, data.clone());
                }
            }
            Action::Append { name, strings } => {
                let key = root.key_mut(&path);
                let mut current = key
                    .values
                    .iter()
                    .find(|value| value.name.eq_ignore_ascii_case(name))
                    .map(|value| strings_of(&value.data))
                    .unwrap_or_default();
                for string in strings {
                    if !current.iter().any(|s| s.eq_ignore_ascii_case(string)) {
                        current.push(string.clone());
                    }
                }
                key.set_value(name, REG_MULTI_SZ, multi_sz(&current));
            }
        }
    }
    Ok(())
}

/// Le jeu de contrôle courant d'une ruche SYSTEM (`Select\Current`, 1 sans
/// lui).
fn current_control_set(system: &KeyNode) -> u32 {
    value(system, "Select", "Current")
        .and_then(|value| value.data.get(..4).map(|d| u32::from_le_bytes([d[0], d[1], d[2], d[3]])))
        .unwrap_or(1)
}

/// Dans SYSTEM, `CurrentControlSet` devient le jeu `current`.
fn control_set_path(current: u32, hive: Hive, path: &str) -> String {
    let (first, rest) = path.split_once('\\').unwrap_or((path, ""));
    if hive != Hive::System || !first.eq_ignore_ascii_case("CurrentControlSet") {
        return path.to_string();
    }
    let set = format!("ControlSet{current:03}");
    if rest.is_empty() {
        set
    } else {
        format!("{set}\\{rest}")
    }
}

/// La clé à `path`, si elle existe (sans casse).
fn find_key<'a>(root: &'a mut KeyNode, path: &str) -> Option<&'a mut KeyNode> {
    let mut key = root;
    for part in path.split('\\').filter(|p| !p.is_empty()) {
        key = key.subkeys.iter_mut().find(|sub| sub.name.eq_ignore_ascii_case(part))?;
    }
    Some(key)
}

/// Retire la clé à `path` et ce qu'elle contient ; rien si elle n'existe
/// pas. La racine ne se retire pas.
fn remove_key(root: &mut KeyNode, path: &str) {
    let path = path.trim_matches('\\');
    let (parent, name) = path.rsplit_once('\\').unwrap_or(("", path));
    if name.is_empty() {
        return;
    }
    if let Some(parent) = find_key(root, parent) {
        parent.subkeys.retain(|sub| !sub.name.eq_ignore_ascii_case(name));
    }
}

/// Une ruche du disque changée par `layer` : lue, changée, réécrite, avec
/// `file_name` dans son en-tête.
///
/// # Errors
/// Une ruche illisible, ou celles d'[`apply`].
pub fn layered(hive: Hive, file: &[u8], layer: &Layer, file_name: &str) -> Result<Vec<u8>, String> {
    let parsed = regf::Hive::parse(file).map_err(|e| format!("{hive:?} hive: {e:?}"))?;
    let root = parsed.root().map_err(|e| format!("{hive:?} hive: {e:?}"))?;
    let tree = KeyNode::read(&root).map_err(|e| format!("{hive:?} hive: {e:?}"))?;
    let mut hives = BTreeMap::from([(hive, tree)]);
    let only_this = Layer {
        delete: layer.delete.iter().filter(|e| e.hive == hive).cloned().collect(),
        add: layer.add.iter().filter(|e| e.hive == hive).cloned().collect(),
    };
    apply(&only_this, &mut hives)?;
    Ok(regf::builder::build(&hives[&hive], file_name))
}

/// Une valeur d'un arbre, pour les tests et les outils.
pub fn value<'a>(root: &'a KeyNode, path: &str, name: &str) -> Option<&'a ValueNode> {
    let mut key = root;
    for part in path.split('\\').filter(|p| !p.is_empty()) {
        key = key.subkeys.iter().find(|sub| sub.name.eq_ignore_ascii_case(part))?;
    }
    key.values.iter().find(|value| value.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests;
