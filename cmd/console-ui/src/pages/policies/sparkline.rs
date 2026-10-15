//! The counter sparkline of the rule hit panels (`counter_sparkline.zig`). Missing
//! observations break the line; the tables beside it keep the exact counts.
//!
//! The traffic tiles of the dashboard use the same drawing; this copy keeps the policies
//! page independent of the dashboard module.

use std::fmt::{self, Write as _};

use crate::format;
use crate::render::Html;

/// Projects counts into the 240 by 48 drawing.
struct Projection {
    maximum: u64,
    length: usize,
}

impl Projection {
    /// Returns the point of `value` at `index`.
    fn point(&self, index: usize, value: u64) -> (f64, f64) {
        let x = if self.length == 1 {
            120.0
        } else {
            4.0 + index as f64 * 232.0 / (self.length - 1) as f64
        };
        (x, 44.0 - value as f64 * 40.0 / self.maximum as f64)
    }
}

/// Writes one coordinate with two decimals, as Zig's `{d:.2}`.
fn coordinate(out: &mut Html<'_>, value: f64) -> fmt::Result {
    format::decimal(out, value, 2)
}

/// Draws `values` (oldest first, `None` for no observation) as a labelled line. Nothing
/// is drawn for an empty series.
pub fn render(out: &mut Html<'_>, values: &[Option<u64>], label: &str) -> fmt::Result {
    if values.is_empty() {
        return Ok(());
    }
    let maximum = values.iter().flatten().copied().fold(1, u64::max);
    let projection = Projection { maximum, length: values.len() };
    out.write_str(
        "<svg viewBox=\"0 0 240 48\" width=\"240\" height=\"48\" class=\"max-w-full \
         text-primary\" role=\"img\" aria-label=\"",
    )?;
    out.escaped(label)?;
    out.write_str("\"><path fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" d=\"")?;
    let mut pen = false;
    for (index, value) in values.iter().enumerate() {
        let Some(count) = value else {
            pen = false;
            continue;
        };
        let (x, y) = projection.point(index, *count);
        out.write_str(if pen { "L" } else { "M" })?;
        coordinate(out, x)?;
        out.write_str(" ")?;
        coordinate(out, y)?;
        out.write_str(" ")?;
        pen = true;
    }
    out.write_str("\"/>")?;
    for (index, value) in values.iter().enumerate() {
        let Some(count) = value else { continue };
        let (x, y) = projection.point(index, *count);
        out.write_str("<circle cx=\"")?;
        coordinate(out, x)?;
        out.write_str("\" cy=\"")?;
        coordinate(out, y)?;
        out.write_str("\" r=\"2\" fill=\"currentColor\"/>")?;
    }
    out.write_str("</svg>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaps_break_the_line_and_a_single_point_is_centred() {
        let mut text = String::new();
        render(&mut Html::new(&mut text, 4096), &[Some(2), None, Some(1)], "x").unwrap();
        assert!(text.contains("d=\"M4.00 4.00 M236.00 24.00 \""));
        assert_eq!(text.matches("<circle").count(), 2);
        let mut text = String::new();
        render(&mut Html::new(&mut text, 4096), &[Some(0)], "x").unwrap();
        assert!(text.contains("d=\"M120.00 44.00 \""));
        let mut text = String::new();
        render(&mut Html::new(&mut text, 4096), &[], "x").unwrap();
        assert!(text.is_empty());
    }
}
