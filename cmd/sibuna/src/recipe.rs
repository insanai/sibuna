//! What every engine starts from: the command-line settings, the startup policy file and
//! the daemon's pages. Startup builds the first engine from it; with storage, every rebuild
//! starts from it again.

use std::fmt;

use sibuna_core::Config;
use sibuna_policy::loader::Diagnostic;
use sibuna_policy::pages::{PageError, Pages};
use sibuna_policy::{Engine, LoadError};

/// What every engine starts from: the command-line settings and the startup policy file.
#[derive(Clone, Debug, Default)]
pub struct Recipe {
    /// The default challenge difficulty.
    pub default_difficulty: u32,
    /// Whether the semantic WAF runs before the file's `waf` key.
    pub waf: bool,
    /// The startup policy file's text, replayed on every rebuild.
    pub policy_file: Option<Vec<u8>>,
}

impl Recipe {
    /// Returns the recipe `config` implies, with `policy_file`.
    pub fn new(config: &Config, policy_file: Option<Vec<u8>>) -> Recipe {
        Recipe { default_difficulty: config.default_difficulty, waf: config.waf, policy_file }
    }

    /// Builds the engine of the recipe alone: defaults, the WAF switch, the policy file and
    /// the daemon's pages.
    ///
    /// Fails with [`BuildError::File`] (and the diagnostic) when the file is rejected.
    pub fn base_engine(&self, diagnostic: &mut Diagnostic) -> Result<Engine, BuildError> {
        let mut engine = Engine::new(self.default_difficulty);
        engine.pages = daemon_pages()?;
        engine.waf_enabled = self.waf;
        if let Some(text) = &self.policy_file {
            engine.apply_json(text, diagnostic).map_err(BuildError::File)?;
        }
        Ok(engine)
    }
}

/// The built-in pages with the daemon's interstitial as the challenge page.
pub fn daemon_pages() -> Result<Pages, BuildError> {
    Pages::defaults(&crate::assets::challenge_page().template).map_err(BuildError::Pages)
}

/// Why a snapshot could not become an engine.
#[derive(Clone, Debug, PartialEq)]
pub enum BuildError {
    /// The startup policy file was rejected (it was accepted at startup, so only a changed
    /// engine default could cause this).
    File(LoadError),
    /// The challenge page does not compile.
    Pages(PageError),
    /// The stored inspection override names an unknown mode.
    InvalidInspectionMode,
    /// A stored rule is invalid: its id and what is wrong.
    InvalidStoredPolicy {
        /// The row's id.
        id: String,
        /// The field or Zig error name at fault.
        problem: String,
    },
    /// Managed and file rules together exceed the engine's capacity.
    TooManyRules,
    /// A reputation row's address does not parse, or the trie is full.
    InvalidReputation(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::File(error) => write!(f, "the policy file is rejected: {}", error.name()),
            BuildError::Pages(error) => write!(f, "the challenge page does not compile: {error}"),
            BuildError::InvalidInspectionMode => f.write_str("invalid stored inspection mode"),
            BuildError::InvalidStoredPolicy { id, problem } => {
                write!(f, "stored policy {id:?} is invalid: {problem}")
            }
            BuildError::TooManyRules => f.write_str("too many rules"),
            BuildError::InvalidReputation(cidr) => write!(f, "invalid reputation entry {cidr:?}"),
        }
    }
}

impl std::error::Error for BuildError {}
