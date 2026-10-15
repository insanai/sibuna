//! Browser-local presentation preferences: theme and density.
//!
//! The bridge reports the saved preference and the system theme; the module validates the
//! values, resolves the system theme and tells the bridge what to apply and whether to
//! save it.

use sibuna_json::Value;

use crate::commands::{Commands, Field};
use crate::error::UiError;
use crate::json;

/// The theme preference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Theme {
    /// Follow the browser.
    #[default]
    System,
    /// Always light.
    Light,
    /// Always dark.
    Dark,
}

impl Theme {
    /// Returns the preference's name, as saved and shown.
    pub fn name(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    fn from_name(name: &str) -> Option<Theme> {
        [Theme::System, Theme::Light, Theme::Dark].into_iter().find(|theme| theme.name() == name)
    }
}

/// The spacing preference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Density {
    /// The default spacing.
    #[default]
    Comfortable,
    /// Tighter spacing.
    Compact,
}

impl Density {
    /// Returns the preference's name, as saved and shown.
    pub fn name(self) -> &'static str {
        match self {
            Density::Comfortable => "comfortable",
            Density::Compact => "compact",
        }
    }

    fn from_name(name: &str) -> Option<Density> {
        [Density::Comfortable, Density::Compact].into_iter().find(|item| item.name() == name)
    }
}

/// The appearance preferences and the browser's colour scheme.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Appearance {
    /// The theme preference.
    pub theme: Theme,
    /// The spacing preference.
    pub density: Density,
    /// The browser prefers a dark colour scheme.
    pub system_dark: bool,
}

impl Appearance {
    /// Returns true when the page is drawn dark.
    pub fn is_dark(self) -> bool {
        self.theme == Theme::Dark || (self.theme == Theme::System && self.system_dark)
    }

    /// Applies an environment event: the saved preferences when `load` is true (event 9;
    /// unknown values fall back to the defaults) and the system theme (events 9 and 10),
    /// then asks the bridge to apply the result without saving it.
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn environment(
        &mut self,
        value: &Value<'_>,
        load: bool,
        commands: &mut Commands,
    ) -> Result<(), UiError> {
        if load {
            self.theme = Theme::from_name(json::string(value, "theme")).unwrap_or_default();
            self.density = Density::from_name(json::string(value, "density")).unwrap_or_default();
        }
        if let Some(dark) = json::boolean(value, "system_dark") {
            self.system_dark = dark;
        }
        self.apply(false, commands)
    }

    /// Handles the `theme` (cycle system, light, dark) and `density` actions, asking the
    /// bridge to apply and save the result. Returns false for any other action.
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn action(&mut self, name: &str, commands: &mut Commands) -> Result<bool, UiError> {
        match name {
            "theme" => {
                self.theme = match self.theme {
                    Theme::System => Theme::Light,
                    Theme::Light => Theme::Dark,
                    Theme::Dark => Theme::System,
                }
            }
            "density" => {
                self.density = match self.density {
                    Density::Comfortable => Density::Compact,
                    Density::Compact => Density::Comfortable,
                }
            }
            _ => return Ok(false),
        }
        self.apply(true, commands)?;
        Ok(true)
    }

    fn apply(self, persist: bool, commands: &mut Commands) -> Result<(), UiError> {
        commands.emit_fields(&[
            ("op", Field::Text("appearance")),
            ("theme", Field::Text(if self.is_dark() { "dark" } else { "light" })),
            ("preference", Field::Text(self.theme.name())),
            ("density", Field::Text(self.density.name())),
            ("persist", Field::Bool(persist)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appearance_resolves_system_changes_and_validates_persisted_values() {
        let mut commands = Commands::default();
        commands.begin();
        let mut model = Appearance::default();
        let saved =
            sibuna_json::parse(br#"{"theme":"system","density":"compact","system_dark":true}"#)
                .unwrap();
        model.environment(&saved, true, &mut commands).unwrap();
        assert!(model.is_dark() && model.density == Density::Compact);
        assert!(model.action("theme", &mut commands).unwrap());
        assert!(!model.is_dark() && model.theme == Theme::Light);
        assert!(model.action("theme", &mut commands).unwrap());
        assert!(model.is_dark() && model.theme == Theme::Dark);
        assert!(model.action("theme", &mut commands).unwrap());
        assert!(model.is_dark() && model.theme == Theme::System);
        model.environment(&Value::Null, true, &mut commands).unwrap();
        assert!(model.theme == Theme::System && model.density == Density::Comfortable);
        assert!(!model.action("pause", &mut commands).unwrap());
        commands.end();
        assert!(commands.as_str().starts_with(
            "[{\"op\":\"appearance\",\"theme\":\"dark\",\"preference\":\"system\",\
             \"density\":\"compact\",\"persist\":false}"
        ));
    }
}
