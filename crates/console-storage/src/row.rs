//! Reading result rows into typed values, and binding unsigned values as SQL integers.
//!
//! Every subsystem decodes its rows with [`Fields`], one call per column in `SELECT` order,
//! so a stored value that the Rust types cannot represent becomes
//! [`StorageError::InvalidRow`] naming the table and the column, never a panic.

use sibuna_storage::{Cell, Row, StorageError};

use crate::error::ConsoleStorageError;

/// The largest value a SQL integer column holds.
pub const MAX_INTEGER: u64 = i64::MAX as u64;

/// Returns `value` as a SQL integer. Fails with [`ConsoleStorageError::InvalidInput`] above
/// [`MAX_INTEGER`], which no console quantity reaches legitimately.
pub fn int(value: u64) -> Result<i64, ConsoleStorageError> {
    i64::try_from(value).map_err(|_| ConsoleStorageError::InvalidInput("a value exceeds 2^63-1"))
}

/// Returns `value` as an optional SQL integer; fails as [`int`].
pub fn optional_int(value: Option<u64>) -> Result<Option<i64>, ConsoleStorageError> {
    value.map(int).transpose()
}

/// Returns `now + seconds`. Fails with [`ConsoleStorageError::InvalidInput`] when the sum
/// passes [`MAX_INTEGER`], so the result always binds with [`int`].
pub fn deadline(now: u64, seconds: u64) -> Result<u64, ConsoleStorageError> {
    now.checked_add(seconds)
        .filter(|value| *value <= MAX_INTEGER)
        .ok_or(ConsoleStorageError::InvalidInput("a deadline exceeds 2^63-1"))
}

/// Returns `text`, or `None` when it is empty: the protocol carries an absent client
/// address as the empty string, the schema as `NULL`.
pub fn non_empty(text: &str) -> Option<&str> {
    (!text.is_empty()).then_some(text)
}

/// Returns the single row of `rows`, or `None` when there is none.
pub fn first(rows: Vec<Row>) -> Option<Row> {
    rows.into_iter().next()
}

/// Reads the cells of one row of `table` from left to right. It owns the row and moves text
/// and bytes out of it without copying.
#[derive(Debug)]
pub struct Fields {
    cells: std::vec::IntoIter<Cell>,
    table: &'static str,
}

impl Fields {
    /// Starts reading `row`, a row of `table`.
    pub fn new(row: Row, table: &'static str) -> Fields {
        Fields { cells: row.into_iter(), table }
    }

    /// Returns the error for a stored value of `column` that the Rust types cannot hold.
    pub fn invalid(&self, column: &'static str) -> ConsoleStorageError {
        ConsoleStorageError::Storage(StorageError::InvalidRow { table: self.table, column })
    }

    fn take(&mut self, column: &'static str) -> Result<Cell, ConsoleStorageError> {
        self.cells.next().ok_or_else(|| self.invalid(column))
    }

    /// Takes an integer of type `T`; fails when it is NULL, not an integer or out of range.
    pub fn integer<T: TryFrom<i64>>(
        &mut self,
        column: &'static str,
    ) -> Result<T, ConsoleStorageError> {
        self.optional_integer(column)?.ok_or_else(|| self.invalid(column))
    }

    /// Takes an optional integer: NULL gives `None`; otherwise as [`Fields::integer`].
    pub fn optional_integer<T: TryFrom<i64>>(
        &mut self,
        column: &'static str,
    ) -> Result<Option<T>, ConsoleStorageError> {
        match self.take(column)? {
            Cell::Null => Ok(None),
            Cell::Int(value) => T::try_from(value).map(Some).map_err(|_| self.invalid(column)),
            _ => Err(self.invalid(column)),
        }
    }

    /// Takes a flag: 0 or 1 on SQLite, a boolean (decoded as 0 or 1) on PostgreSQL.
    pub fn flag(&mut self, column: &'static str) -> Result<bool, ConsoleStorageError> {
        match self.integer::<i64>(column)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(self.invalid(column)),
        }
    }

    /// Takes text; fails when it is NULL or not text.
    pub fn text(&mut self, column: &'static str) -> Result<String, ConsoleStorageError> {
        self.optional_text(column)?.ok_or_else(|| self.invalid(column))
    }

    /// Takes optional text: NULL gives `None`.
    pub fn optional_text(
        &mut self,
        column: &'static str,
    ) -> Result<Option<String>, ConsoleStorageError> {
        match self.take(column)? {
            Cell::Null => Ok(None),
            Cell::Text(text) => Ok(Some(text)),
            _ => Err(self.invalid(column)),
        }
    }

    /// Takes a byte string; fails when it is NULL or not bytes.
    pub fn bytes(&mut self, column: &'static str) -> Result<Vec<u8>, ConsoleStorageError> {
        self.optional_bytes(column)?.ok_or_else(|| self.invalid(column))
    }

    /// Takes an optional byte string: NULL gives `None`.
    pub fn optional_bytes(
        &mut self,
        column: &'static str,
    ) -> Result<Option<Vec<u8>>, ConsoleStorageError> {
        match self.take(column)? {
            Cell::Null => Ok(None),
            Cell::Bytes(bytes) => Ok(Some(bytes)),
            _ => Err(self.invalid(column)),
        }
    }

    /// Takes a byte string of exactly `N` bytes (a digest, a boot identifier).
    pub fn array<const N: usize>(
        &mut self,
        column: &'static str,
    ) -> Result<[u8; N], ConsoleStorageError> {
        self.optional_array(column)?.ok_or_else(|| self.invalid(column))
    }

    /// Takes an optional byte string of exactly `N` bytes.
    pub fn optional_array<const N: usize>(
        &mut self,
        column: &'static str,
    ) -> Result<Option<[u8; N]>, ConsoleStorageError> {
        match self.optional_bytes(column)? {
            None => Ok(None),
            Some(bytes) => <[u8; N]>::try_from(bytes).map(Some).map_err(|_| self.invalid(column)),
        }
    }

    /// Takes the name of an enumerated value and returns `parse(name)`; fails when the cell
    /// is not text or `parse` returns `None`.
    pub fn parsed<T>(
        &mut self,
        column: &'static str,
        parse: fn(&str) -> Option<T>,
    ) -> Result<T, ConsoleStorageError> {
        self.optional_parsed(column, parse)?.ok_or_else(|| self.invalid(column))
    }

    /// As [`Fields::parsed`], but NULL gives `None`.
    pub fn optional_parsed<T>(
        &mut self,
        column: &'static str,
        parse: fn(&str) -> Option<T>,
    ) -> Result<Option<T>, ConsoleStorageError> {
        match self.optional_text(column)? {
            None => Ok(None),
            Some(text) => parse(&text).map(Some).ok_or_else(|| self.invalid(column)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_decode_in_order_and_name_the_bad_column() {
        let row = vec![
            Cell::Int(7),
            Cell::Null,
            Cell::Int(1),
            Cell::Bytes(vec![1; 4]),
            Cell::Text("admin".into()),
        ];
        let mut fields = Fields::new(row, "console_users");
        assert_eq!(fields.integer::<u64>("id").unwrap(), 7);
        assert_eq!(fields.optional_integer::<u64>("last_login_at").unwrap(), None);
        assert!(fields.flag("disabled").unwrap());
        assert_eq!(fields.array::<4>("digest").unwrap(), [1; 4]);
        assert_eq!(fields.text("role").unwrap(), "admin");
        let error = fields.text("missing").unwrap_err();
        assert!(matches!(
            error,
            ConsoleStorageError::Storage(StorageError::InvalidRow { column: "missing", .. })
        ));
        let mut fields = Fields::new(vec![Cell::Int(2), Cell::Bytes(vec![0; 3])], "t");
        assert!(fields.flag("flag").is_err());
        assert!(fields.array::<4>("digest").is_err());
    }

    #[test]
    fn unsigned_values_bind_only_below_2_pow_63() {
        assert_eq!(int(5).unwrap(), 5);
        assert!(int(MAX_INTEGER + 1).is_err());
        assert_eq!(deadline(10, 600).unwrap(), 610);
        assert!(deadline(MAX_INTEGER, 1).is_err());
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty("::1"), Some("::1"));
    }
}
