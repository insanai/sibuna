//! Drill-downs from the security overview into the Events page
//! (`security_investigation.zig`): a module, source address, category or path row opens
//! the incidents behind it with the summary's frozen node and period.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::security::Module;

use super::model::Model;
use crate::error::UiError;
use crate::json::parse_integer;
use crate::pages::events::Investigation;

/// Parses an index of an action name.
fn index(part: Option<&str>) -> Result<usize, UiError> {
    part.and_then(parse_integer).ok_or(UiError::InvalidRequest)
}

/// Returns the drill-down that the action `name` asks for, `None` when `name` is not a
/// drill-down (`security-module-M`, `security-source-M-R`, `security-category-I`,
/// `security-path-I`).
///
/// # Errors
///
/// [`UiError::InvalidRequest`] for a malformed name, an index beyond the rows, a row that
/// is absent or a view that is not loaded.
pub fn selection(model: &Model, name: &str) -> Result<Option<Investigation>, UiError> {
    let Some(rest) = name.strip_prefix("security-") else { return Ok(None) };
    let mut parts = rest.split('-');
    let kind = parts.next().unwrap_or_default();
    if !matches!(kind, "source" | "module" | "category" | "path") {
        return Ok(None);
    }
    let position = index(parts.next())?;
    let mut picked = Investigation {
        node: model.request.node,
        from: model.request.from,
        until: model.request.until,
        hours: u32::from(model.hours),
        ..Investigation::default()
    };
    if kind == "source" || kind == "module" {
        let module = Module::ALL.get(position).copied();
        let Some(module) = module.filter(|_| model.loaded[0]) else {
            return Err(UiError::InvalidRequest);
        };
        picked.module = Some(module);
        if kind == "source" {
            let rank = index(parts.next())?;
            let sources = &model.modules[position].sources;
            let row = sources.get(rank).and_then(Option::as_ref);
            picked.ip = Text::new(row.ok_or(UiError::InvalidRequest)?.label.as_str())?;
        }
        if parts.next().is_some() {
            return Err(UiError::InvalidRequest);
        }
        return Ok(Some(picked));
    }
    let category = kind == "category";
    if parts.next().is_some() || !model.loaded[if category { 1 } else { 2 }] {
        return Err(UiError::InvalidRequest);
    }
    let rows = if category { &model.categories } else { &model.paths };
    let row = rows.get(position).and_then(Option::as_ref).ok_or(UiError::InvalidRequest)?;
    if category {
        picked.category = Text::new(row.label.as_str())?;
    } else {
        picked.path = Text::new(row.label.as_str())?;
    }
    Ok(Some(picked))
}
