//! Loading the module graph of one compilation (JDD 0004, "Modules, context and
//! foundation").
//!
//! An import names a module by a dotted path (JDD 0016, "Modules and imports"), which
//! the loader turns into the canonical label of JDD 0004 that the lock and the digests
//! keep: `jlv.std.deploy` is `@jlv//std:deploy.jlv`, a plugin alias `host` alone is
//! `@host//:plugin.jlv`, a library path `labels.lib.text` is `@labels//lib:text.jlv`,
//! and any other path names a module of the importing package, so `lib.app` is
//! `//lib:app.jlv` in the project and `@p//lib:app.jlv` inside the package `p`. An
//! import resolves to a registry library or to a captured source module; anything else
//! is `module_not_locked`. The source modules form a finite DAG, and a cycle reports
//! its path before evaluation. Diagnostics show dotted paths.

use std::collections::BTreeMap;
use std::sync::Arc;

use jlv_core::{Diagnostic, SourceId, Span};
use jlv_lang::codes;
use jlv_syntax::Syntax;
use jlv_syntax::view::Module;

use crate::Request;

/// What an import names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// A source module, by index into [`Loaded::modules`].
    Source(usize),
    /// A registry library, by label.
    Library(Arc<str>),
}

/// One parsed source module and its resolved imports.
#[derive(Debug)]
pub(crate) struct Unit {
    /// The canonical label.
    pub key: Arc<str>,
    /// The module's source.
    pub text: Arc<str>,
    /// Its tokens and tree.
    pub syntax: Syntax,
    /// Each import of the tree and what it names, in order.
    pub targets: Vec<Target>,
}

impl Unit {
    /// The module's views.
    pub fn module(&self) -> Module<'_> {
        self.syntax.source(&self.text).module()
    }
}

/// The source modules, dependencies before their importers.
#[derive(Debug)]
pub(crate) struct Loaded {
    /// The modules in initialization order.
    pub modules: Vec<Unit>,
    /// The entry module's index.
    pub entry: usize,
}

/// Parses the entry module and every source module it reaches.
pub(crate) fn load(request: Request<'_>) -> Result<Loaded, Diagnostic> {
    let mut loader =
        Loader { request, order: Vec::new(), state: BTreeMap::new(), parsed: BTreeMap::new() };
    unambiguous(request)?;
    let entry_key: Arc<str> = request.entry.module.clone();
    if request.closure.file(&entry_key).is_none() {
        let message = format!("The entry module `{entry_key}` is not in the source closure.");
        let hint = "Name an entry `source` that exists in the project.";
        return Err(Diagnostic::unplaced(codes::problem(
            codes::MODULE_NOT_LOCKED,
            &message,
            hint,
        )));
    }
    loader.visit(&entry_key)?;
    let index: BTreeMap<Arc<str>, usize> =
        loader.order.iter().enumerate().map(|(i, k)| (k.clone(), i)).collect();
    let mut modules = Vec::with_capacity(loader.order.len());
    for key in &loader.order {
        // Every visited key was parsed before it entered the order.
        let Some((_, text, syntax, labels)) = loader.parsed.remove(key) else { continue };
        let targets = labels
            .into_iter()
            .map(|resolved| match resolved {
                Resolved::Source(k) => Target::Source(index[&k]),
                Resolved::Library(l) => Target::Library(l),
            })
            .collect();
        modules.push(Unit { key: key.clone(), text, syntax, targets });
    }
    let entry = index[&entry_key];
    Ok(Loaded { modules, entry })
}

/// A resolved import before module indices are known.
#[derive(Debug, Clone)]
enum Resolved {
    Source(Arc<str>),
    Library(Arc<str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Visit {
    Active,
    Done,
}

type Parsed = (SourceId, Arc<str>, Syntax, Vec<Resolved>);

/// A module whose imports are being visited: the frame of the depth-first search,
/// which replaces a recursive call per import (JDD 0013).
struct Open {
    key: Arc<str>,
    id: SourceId,
    text: Arc<str>,
    syntax: Syntax,
    /// Each import's dotted path as written, and where.
    labels: Vec<(Arc<str>, Span)>,
    resolved: Vec<Resolved>,
    /// The next import to visit.
    next: usize,
}

struct Loader<'a> {
    request: Request<'a>,
    order: Vec<Arc<str>>,
    state: BTreeMap<Arc<str>, Visit>,
    parsed: BTreeMap<Arc<str>, Parsed>,
}

impl Loader<'_> {
    /// Depth-first visit that appends a module after everything it imports. The
    /// stack holds the open modules and `path` the imports that lead from the entry to
    /// the top one, so a long chain of imports needs no native stack.
    fn visit(&mut self, entry: &Arc<str>) -> Result<(), Diagnostic> {
        let mut path: Vec<(Arc<str>, Span)> = Vec::new();
        let mut stack: Vec<Open> = self.enter(entry, &path)?.into_iter().collect();
        while let Some(top) = stack.last_mut() {
            let Some((label, span)) = top.labels.get(top.next).cloned() else {
                if let Some(done) = stack.pop() {
                    self.finish(done)?;
                }
                path.pop();
                continue;
            };
            let target = self.resolve(&top.key, &label, span)?;
            top.next += 1;
            top.resolved.push(target.clone());
            if let Resolved::Source(dependency) = target {
                path.push((top.key.clone(), span));
                match self.enter(&dependency, &path)? {
                    Some(open) => stack.push(open),
                    None => {
                        path.pop();
                    }
                }
            }
        }
        Ok(())
    }

    /// Starts visiting `key`, reached by `path`: `None` when it is already done, and a
    /// cycle when it is still open.
    fn enter(
        &mut self,
        key: &Arc<str>,
        path: &[(Arc<str>, Span)],
    ) -> Result<Option<Open>, Diagnostic> {
        match self.state.get(key) {
            Some(Visit::Done) => return Ok(None),
            Some(Visit::Active) => return Err(cycle(key, path)),
            None => {}
        }
        self.state.insert(key.clone(), Visit::Active);
        // Refused as soon as the closure holds one module too many, before parsing it.
        if self.state.len() > self.request.limits.modules {
            return Err(too_many(self.request.limits.modules));
        }
        let closure = self.request.closure;
        let Some(file) = closure.file(key) else { return Err(not_locked(key, path)) };
        if file.text.len() > self.request.limits.module_bytes {
            return Err(too_large(key, self.request.limits.module_bytes));
        }
        let syntax = Syntax::parse(file.id, &file.text, self.request.limits)?;
        let imports = syntax.source(&file.text).module().imports();
        let labels: Vec<(Arc<str>, Span)> =
            imports.iter().map(|i| (Arc::from(i.dotted()), i.path_span)).collect();
        let resolved = Vec::with_capacity(labels.len());
        let text = file.text.clone();
        Ok(Some(Open { key: key.clone(), id: file.id, text, syntax, labels, resolved, next: 0 }))
    }

    /// Ends the visit of a module whose imports are all visited.
    fn finish(&mut self, open: Open) -> Result<(), Diagnostic> {
        self.state.insert(open.key.clone(), Visit::Done);
        self.order.push(open.key.clone());
        self.parsed.insert(open.key, (open.id, open.text, open.syntax, open.resolved));
        Ok(())
    }

    fn resolve(&self, importer: &str, written: &str, span: Span) -> Result<Resolved, Diagnostic> {
        let label = label_of(self.request, importer, written)
            .map_err(|(message, hint)| invalid_path(&message, &hint, span))?;
        if self.request.registry.library(&label).is_some() {
            return Ok(Resolved::Library(label));
        }
        if self.request.closure.file(&label).is_some() {
            return Ok(Resolved::Source(label));
        }
        let message = format!("The module `{written}` is not in the locked closure.");
        let hint = self.missing_hint(importer, written, &label);
        Err(Diagnostic::at(codes::problem(codes::MODULE_NOT_LOCKED, &message, &hint), span))
    }

    /// Why `written`, resolved to `label`, names no module, and what to write instead.
    fn missing_hint(&self, importer: &str, written: &str, label: &str) -> String {
        if let Some(path) = written.strip_suffix(".jlv") {
            return format!("Leave out `.jlv`: write `from {path}`.");
        }
        if written.starts_with("jlv.std.") {
            let modules: Vec<String> = self
                .request
                .registry
                .labels()
                .filter(|l| l.starts_with("@jlv//std:"))
                .map(dotted)
                .collect();
            let suggestion = gd_report::suggest(
                written,
                modules.iter().map(String::as_str).collect::<Vec<_>>(),
            );
            let listed = modules.join("`, `");
            return match suggestion {
                Some(s) => format!("Did you mean `{s}`? The standard library has `{listed}`."),
                None => format!("The standard library has `{listed}`."),
            };
        }
        if package_of(label) == package_of(importer) {
            let file = label.split_once("//").map_or(label, |(_, f)| f).replacen(':', "/", 1);
            let file = file.trim_start_matches('/');
            let root = written.split('.').next().unwrap_or(written);
            return match package_of(importer) {
                Some(alias) => {
                    format!("Create `{file}` in the library `{alias}`, or correct the path.")
                }
                // A first segment that is no folder of the project is more likely a library
                // that `jlv.toml` does not name yet.
                None if !has_root(self.request, importer, root) => format!(
                    "Create `{file}` in the project, or add the library `{root}` to jlv.toml \
                     and run `jlvd lock update`."
                ),
                None => format!("Create `{file}` in the project, or correct the path."),
            };
        }
        "Add the package to jlv.toml and run `jlvd lock update`, or correct the path.".into()
    }
}

/// What the first segment of a dotted path names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Root {
    /// The standard library, `jlv`.
    Standard,
    /// A plugin's facade, by its alias alone.
    Plugin,
    /// A library package, by its alias and then a module path.
    Library,
    /// Anything else: a module of the importing package.
    Own,
}

/// What `segment` names, from the registry and the captured closure.
fn root_of(request: Request<'_>, segment: &str) -> Root {
    if segment == "jlv" {
        return Root::Standard;
    }
    if request.registry.library(&format!("@{segment}//:plugin.jlv")).is_some() {
        return Root::Plugin;
    }
    let prefix = format!("@{segment}//");
    if request.closure.files.iter().any(|f| f.label.starts_with(&prefix)) {
        return Root::Library;
    }
    Root::Own
}

/// Whether the package of the module `importer` has a directory or a module named
/// `segment` at its root.
fn has_root(request: Request<'_>, importer: &str, segment: &str) -> bool {
    let package = package_of(importer).map_or_else(String::new, |p| format!("@{p}"));
    let (directory, module) = (format!("{package}//{segment}/"), format!("{package}//{segment}:"));
    let file = format!("{package}//:{segment}.jlv");
    request.closure.files.iter().any(|f| {
        f.label.starts_with(&directory) || f.label.starts_with(&module) || *f.label == *file
    })
}

/// The canonical label of the dotted path `written` imported by the module
/// `importer`, or the message and hint of its refusal.
fn label_of(
    request: Request<'_>,
    importer: &str,
    written: &str,
) -> Result<Arc<str>, (String, String)> {
    let segments: Vec<&str> = written.split('.').collect();
    if let Some(plugin) = package_of(importer).filter(|p| is_plugin(request, p)) {
        return plugin_import(request, importer, plugin, &segments);
    }
    // A package's own root comes first, so a library's paths never depend on the
    // aliases of the project that uses it; in the project, `unambiguous` refuses a root
    // that an alias could also mean.
    let root = if segments[0] != "jlv" && has_root(request, importer, segments[0]) {
        Root::Own
    } else {
        root_of(request, segments[0])
    };
    match root {
        Root::Plugin if segments.len() == 1 => Ok(Arc::from(format!("@{written}//:plugin.jlv"))),
        // A plugin's modules are below its `lib/` (JDD 0017, "Part 4").
        Root::Plugin if segments.len() > 2 && segments[1] == "lib" => {
            Ok(Arc::from(format!("@{}//{}", segments[0], module_label(&segments[1..]))))
        }
        Root::Plugin => Err((
            format!(
                "`{written}` names no module: below a plugin's alias, a path names one of its \
                 `lib` modules."
            ),
            format!(
                "Write `from {}` for its facade, or `from {}.lib.NAME` for a module it ships.",
                segments[0], segments[0]
            ),
        )),
        Root::Standard if segments.len() == 1 => Err((
            format!("`{written}` is a package; an import names one of its modules."),
            "Name a module of the standard library, such as `jlv.std.deploy`.".to_string(),
        )),
        Root::Library if segments.len() == 1 => Err((
            format!("`{written}` is a package; an import names one of its modules."),
            format!("Name a module of the package, such as `{written}.lib.name`."),
        )),
        Root::Library | Root::Standard => {
            Ok(Arc::from(format!("@{}//{}", segments[0], module_label(&segments[1..]))))
        }
        Root::Own => own(importer, &segments),
    }
}

/// The `DIR:FILE.jlv` part of a label for the module path `path`.
fn module_label(path: &[&str]) -> String {
    let (file, dirs) = path.split_last().unwrap_or((&"", &[]));
    format!("{}:{file}.jlv", dirs.join("/"))
}

/// The label of a module of the importer's own package, by its path from the root.
fn own(importer: &str, segments: &[&str]) -> Result<Arc<str>, (String, String)> {
    canonical(importer, &format!("//{}", module_label(segments))).map_err(|message| {
        let hint = "Name the module by its path from the package root, such as `lib.app`.";
        (message, hint.to_string())
    })
}

/// Whether `alias` is a plugin's alias, whose facade the registry holds.
fn is_plugin(request: Request<'_>, alias: &str) -> bool {
    request.registry.library(&format!("@{alias}//:plugin.jlv")).is_some()
}

/// The label of `segments` imported by a module of the plugin `plugin` (JDD 0017,
/// "Part 4"): its own modules by path, its facade as `plugin`, or the standard library;
/// any other import is refused, since the aliases of the project that locks the plugin
/// are not the plugin's to know.
fn plugin_import(
    request: Request<'_>,
    importer: &str,
    plugin: &str,
    segments: &[&str],
) -> Result<Arc<str>, (String, String)> {
    match segments {
        ["plugin"] => Ok(Arc::from(format!("@{plugin}//:plugin.jlv"))),
        ["jlv"] => Err((
            "`jlv` is a package; an import names one of its modules.".to_string(),
            "Name a module of the standard library, such as `jlv.std.operations`.".to_string(),
        )),
        ["jlv", rest @ ..] => Ok(Arc::from(format!("@jlv//{}", module_label(rest)))),
        [first, ..]
            if has_root(request, importer, first) || root_of(request, first) == Root::Own =>
        {
            own(importer, segments)
        }
        _ => Err((
            format!(
                "A module of the plugin `{plugin}` imports `{}`, which is not its own.",
                segments.join(".")
            ),
            "A plugin's module imports only its own modules by their path, such as \
             `lib.common`, its facade as `plugin`, and the standard library."
                .to_string(),
        )),
    }
}

/// The dotted path that names the module `label` from outside its package, for
/// diagnostics: `@jlv//std:deploy.jlv` is `jlv.std.deploy`, `@host//:plugin.jlv` is
/// `host` and `//lib:app.jlv` is `lib.app`.
pub(crate) fn dotted(label: &str) -> String {
    let (alias, rest) = match label.strip_prefix('@').and_then(|r| r.split_once("//")) {
        Some((alias, rest)) => (Some(alias), rest),
        None => (None, label.trim_start_matches("//")),
    };
    if let Some(alias) = alias
        && rest == ":plugin.jlv"
    {
        return alias.to_string();
    }
    let (dir, file) = rest.split_once(':').unwrap_or(("", rest));
    let file = file.strip_suffix(".jlv").unwrap_or(file);
    let parts = alias.into_iter().chain(dir.split('/').filter(|d| !d.is_empty()));
    parts.chain([file]).collect::<Vec<_>>().join(".")
}

/// Refuses a project whose root directory or root module is named like a package
/// alias, since a dotted path beginning with that name could mean either.
fn unambiguous(request: Request<'_>) -> Result<(), Diagnostic> {
    for file in &request.closure.files {
        let Some(body) = file.label.strip_prefix("//") else { continue };
        let (dir, module) = body.split_once(':').unwrap_or(("", body));
        let name = match dir.split('/').next() {
            Some(first) if !first.is_empty() => first,
            _ => module.strip_suffix(".jlv").unwrap_or(module),
        };
        let package = match root_of(request, name) {
            Root::Own => continue,
            Root::Standard => "the standard library `jlv`".to_string(),
            Root::Plugin => format!("the plugin alias `{name}` of jlv.toml"),
            Root::Library => format!("the library alias `{name}` of jlv.toml"),
        };
        let what = if dir.is_empty() { "module" } else { "directory" };
        let message = format!(
            "The project's {what} `{name}` has the name of {package}, so a path that \
             begins `{name}.` could mean either; this module is in it."
        );
        let hint =
            format!("Rename the {what} `{name}`, or give the package another alias in jlv.toml.");
        let problem = codes::problem(codes::AMBIGUOUS_IMPORT, &message, &hint);
        return Err(Diagnostic::at(problem, Span::new(file.id, 0, 0)));
    }
    Ok(())
}

fn invalid_path(message: &str, hint: &str, span: Span) -> Diagnostic {
    Diagnostic::at(codes::problem(codes::INVALID_SOURCE, message, hint), span)
}

/// The canonical label of `label` as written in the module `importer`.
pub(crate) fn canonical(importer: &str, label: &str) -> Result<Arc<str>, String> {
    let (alias, rest) = match label.strip_prefix('@') {
        Some(rest) => {
            let end =
                rest.find("//").ok_or_else(|| format!("`{label}` has no `//` after its alias"))?;
            (Some(&rest[..end]), &rest[end..])
        }
        None => (None, label),
    };
    let Some(body) = rest.strip_prefix("//") else {
        return Err(format!("`{label}` does not start with `//` or `@name//`"));
    };
    let (dir, file) =
        body.split_once(':').ok_or_else(|| format!("`{label}` has no `:` before its file"))?;
    let valid_part = |p: &str| {
        !p.is_empty()
            && p != "."
            && p != ".."
            && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
    };
    if let Some(alias) = alias
        && !(valid_part(alias)
            && alias.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    {
        return Err(format!("`{alias}` is not a valid package alias"));
    }
    if !(dir.is_empty() || dir.split('/').all(valid_part)) {
        return Err(format!(
            "`{label}` has an empty, `.` or `..` component, or a character outside [A-Za-z0-9_.-]"
        ));
    }
    if !valid_part(file) || !file.ends_with(".jlv") || file.contains('/') {
        return Err(format!("`{label}` must name one `.jlv` file after its `:`"));
    }
    let scope = alias.map(str::to_string).or_else(|| package_of(importer).map(str::to_string));
    Ok(match scope {
        Some(scope) => Arc::from(format!("@{scope}//{dir}:{file}")),
        None => Arc::from(format!("//{dir}:{file}")),
    })
}

/// The package alias of a module label, or `None` for a project module.
fn package_of(label: &str) -> Option<&str> {
    let rest = label.strip_prefix('@')?;
    rest.find("//").map(|end| &rest[..end])
}

fn cycle(key: &str, path: &[(Arc<str>, Span)]) -> Diagnostic {
    let start = path.iter().position(|(k, _)| &**k == key).unwrap_or(0);
    let mut names: Vec<String> = path[start..].iter().map(|(k, _)| dotted(k)).collect();
    names.push(dotted(key));
    let (message, hint) = if names.len() == 2 {
        let message = format!("The module `{}` imports itself.", names[0]);
        (message, "Remove the import; a module sees its own definitions without one.")
    } else {
        let message = format!("The modules import each other: {}.", names.join(" -> "));
        (message, "Move the shared definitions into a module that both import.")
    };
    let span = path.last().map(|(_, s)| *s).unwrap_or_default();
    Diagnostic::at(codes::problem(codes::MODULE_CYCLE, &message, hint), span)
}

fn not_locked(key: &str, path: &[(Arc<str>, Span)]) -> Diagnostic {
    let message = format!("The module `{}` is not in the source closure.", dotted(key));
    let hint = "Check the path, or add the module to the project.";
    let span = path.last().map(|(_, s)| *s).unwrap_or_default();
    Diagnostic::at(codes::problem(codes::MODULE_NOT_LOCKED, &message, hint), span)
}

fn too_large(key: &str, limit: usize) -> Diagnostic {
    let message = format!("The module `{}` is larger than {limit} bytes.", dotted(key));
    let hint = "Split the module, or raise `[limits] module_bytes` in jlv.toml.";
    Diagnostic::unplaced(codes::problem(codes::BUDGET_EXHAUSTED, &message, hint))
}

fn too_many(limit: usize) -> Diagnostic {
    let message = format!("The closure has more than {limit} modules.");
    let hint = "Reduce the number of modules the entry reaches.";
    Diagnostic::unplaced(codes::problem(codes::BUDGET_EXHAUSTED, &message, hint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_read_as_dotted_paths() {
        assert_eq!(dotted("@jlv//std:deploy.jlv"), "jlv.std.deploy");
        assert_eq!(dotted("@host//:plugin.jlv"), "host");
        assert_eq!(dotted("//lib:app.jlv"), "lib.app");
        assert_eq!(dotted("//:deploy.jlv"), "deploy");
        assert_eq!(dotted("@labels//lib/x:text.jlv"), "labels.lib.x.text");
    }

    #[test]
    fn labels_are_canonical_within_their_package() {
        assert_eq!(&*canonical("//:deploy.jlv", "//lib:labels.jlv").unwrap(), "//lib:labels.jlv");
        assert_eq!(
            &*canonical("@labels//lib:a.jlv", "//lib:b.jlv").unwrap(),
            "@labels//lib:b.jlv"
        );
        assert_eq!(
            &*canonical("//:deploy.jlv", "@incus//:plugin.jlv").unwrap(),
            "@incus//:plugin.jlv"
        );
        assert!(canonical("//:a.jlv", "//../x:y.jlv").is_err());
        assert!(canonical("//:a.jlv", "//a//b:y.jlv").is_err());
        assert!(canonical("//:a.jlv", "//a\\b:y.jlv").is_err());
        assert!(canonical("//:a.jlv", "lib/labels.jlv").is_err());
        assert!(canonical("//:a.jlv", "//lib:labels.txt").is_err());
    }
}
