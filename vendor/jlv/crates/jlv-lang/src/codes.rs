//! The stable diagnostic classes of JDD 0004, "Limits and diagnostics".
//!
//! The class is the problem's code, so tools and fixtures compare codes, never
//! English text. [`problem`] builds a problem of one class with its title, message and
//! a hint that says how to fix it.

use jlv_core::Problem;

/// Source that is not valid JLV.
pub const INVALID_SOURCE: &str = "invalid_source";
/// A reserved or excluded form, such as `loop` or `match`.
pub const UNSUPPORTED_SYNTAX: &str = "unsupported_syntax";
/// A name with no binding in scope.
pub const UNBOUND_NAME: &str = "unbound_name";
/// A binding read before it has a value.
pub const UNINITIALIZED_BINDING: &str = "uninitialized_binding";
/// A value of the wrong type.
pub const TYPE_MISMATCH: &str = "type_mismatch";
/// A call with missing, unknown or duplicate arguments.
pub const ARGUMENT_ERROR: &str = "argument_error";
/// Integer arithmetic outside the signed 64-bit range.
pub const INTEGER_OVERFLOW: &str = "integer_overflow";
/// Division or remainder by zero.
pub const DIVISION_BY_ZERO: &str = "division_by_zero";
/// A negative, out-of-range index or a missing map key.
pub const INDEX_ERROR: &str = "index_error";
/// A repeated key in a record or map.
pub const DUPLICATE_KEY: &str = "duplicate_key";
/// Two declarations of one resource address.
pub const DUPLICATE_ADDRESS: &str = "duplicate_address";
/// An import that the lock does not account for.
pub const MODULE_NOT_LOCKED: &str = "module_not_locked";
/// A project directory or module whose name is also a package alias, so that a
/// dotted import path could name either (JDD 0016).
pub const AMBIGUOUS_IMPORT: &str = "ambiguous_import";
/// Modules that import each other.
pub const MODULE_CYCLE: &str = "module_cycle";
/// A function that can reach itself through calls.
pub const RECURSIVE_CALL: &str = "recursive_call";
/// An evaluation, size or output budget that ran out.
pub const BUDGET_EXHAUSTED: &str = "budget_exhausted";
/// A provider output used where a known value is required.
pub const UNRESOLVED_REFERENCE: &str = "unresolved_reference";
/// Resources whose required state depends on itself.
pub const DEPENDENCY_CYCLE: &str = "dependency_cycle";
/// A target selection with zero or several matches where one is required.
pub const INVALID_TARGET_SET: &str = "invalid_target_set";
/// A `fail(...)` in source.
pub const USER_ERROR: &str = "user_error";
/// A failure outside the language's semantics, such as an exhausted process.
pub const OPERATIONAL_FAILURE: &str = "operational_failure";

/// The title of a class: its words in upper case.
pub fn title(code: &str) -> String {
    code.replace('_', " ").to_uppercase()
}

/// The consequence every language problem has: JLV preparation is all or nothing.
pub const CONSEQUENCE: &str = "Preparation stopped; no partial result was produced.";

/// A problem of class `code` with `message`, its consequence and how to fix it.
pub fn problem(code: &str, message: &str, hint: &str) -> Problem {
    Problem::new(code, &title(code), message).status(422).consequence(CONSEQUENCE).hint(hint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_come_from_the_class() {
        let p = problem(TYPE_MISMATCH, "An Int is not a Text.", "Convert it explicitly.");
        assert_eq!(p.title, "TYPE MISMATCH");
        assert_eq!(p.code, "type_mismatch");
    }
}
