//! The page interface: how a page module plugs into the state machine.
//!
//! A page module owns its state, renders its screen and handles the actions, replies,
//! timers and live views that concern it. The core calls every registered module through
//! the [`Page`] trait in registration order (see `pages/mod.rs`); every method has a
//! default that does nothing, so a module implements only what it needs. Panels that
//! several pages draw (the globe, the request timeline) are modules too: they have no
//! [`Page::screen`] and are drawn by the pages that call them through [`Pages::find`].

use std::any::Any;
use std::fmt;

use sibuna_console_protocol::Topic;
use sibuna_console_protocol::codec::Encode;
use sibuna_console_protocol::subscriptions::Args;
use sibuna_json::Value;

use crate::commands::{Commands, Json};
use crate::error::UiError;
use crate::live::Connection;
use crate::render::Html;
use crate::state::{Phase, State};

/// A function the core calls on each module in turn; see [`Pages::each`].
pub(crate) type Handler<'h> =
    dyn FnMut(&mut dyn Page, &mut Context<'_>) -> Result<bool, UiError> + 'h;

/// The message an expired session shows unless its page says more.
pub const SESSION_ENDED: &str = "Your session ended. Sign in to continue.";

/// Where a module draws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// The page of a phase, drawn inside the navigation shell when signed in.
    Phase(Phase),
    /// The wall display, drawn without the shell for a kiosk session.
    Kiosk,
    /// A panel below the password form of a signed-in account (the wall-display grant).
    AccountPanel,
}

/// A server reply the bridge delivered as a response event (kind 2).
#[derive(Clone, Copy, Debug)]
pub struct Reply<'e, 'a> {
    /// The request id the module chose when it sent the request.
    pub id: &'e str,
    /// The HTTP status, 0 when the request failed in the browser; `None` when the event
    /// has no integer status.
    pub status: Option<i64>,
    /// The decoded JSON body; `None` when the event has none.
    pub body: Option<&'e Value<'a>>,
    /// The whole event, for replies whose envelope matters (`browser_time`).
    pub envelope: &'e Value<'a>,
}

impl<'e, 'a> Reply<'e, 'a> {
    /// Returns the status and body when both are present, which ordinary replies need.
    pub fn complete(&self) -> Option<(i64, &'e Value<'a>)> {
        Some((self.status?, self.body?))
    }
}

/// Read access to everything a page draws from.
#[derive(Clone, Copy)]
pub struct View<'a> {
    /// The shared state.
    pub state: &'a State,
    /// Every registered module, for panels a page draws.
    pub pages: &'a Pages,
}

/// Write access for one handler: the shared state, the command list, the live
/// connection and every other module.
///
/// While a module's handler runs, that module is taken out of [`Context::pages`], so the
/// handler can reach every other module without aliasing itself.
pub struct Context<'a> {
    /// The shared state.
    pub state: &'a mut State,
    /// The commands of the current event.
    pub commands: &'a mut Commands,
    /// The other modules.
    pub pages: &'a mut Pages,
    /// The live connection.
    pub(crate) live: &'a mut Connection,
}

impl Context<'_> {
    /// Asks the bridge to `GET` `path`; the reply arrives as a response event `id`.
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn get(&mut self, id: &str, path: &str) -> Result<(), UiError> {
        self.commands.get(id, path)
    }

    /// Asks the bridge to `POST` the JSON `body` writes, with the session's CSRF token;
    /// the reply arrives as a response event `id`.
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn post(
        &mut self,
        id: &str,
        path: &str,
        body: &mut dyn FnMut(&mut Json<'_>) -> fmt::Result,
    ) -> Result<(), UiError> {
        self.commands.post(id, path, self.state.csrf.as_str(), body)
    }

    /// Posts an encodable wire value; see [`Context::post`].
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn post_value<T: Encode + ?Sized>(
        &mut self,
        id: &str,
        path: &str,
        body: &T,
    ) -> Result<(), UiError> {
        self.commands.post_value(id, path, self.state.csrf.as_str(), body)
    }

    /// Offers the action `name` to the other modules, as if the operator had chosen it;
    /// returns true if one handled it. A page uses it to open another page, for example
    /// with its navigation action.
    ///
    /// # Errors
    ///
    /// The handling module's error.
    pub fn action(&mut self, name: &str, fields: &Value<'_>) -> Result<bool, UiError> {
        self.each(&mut |page, cx| page.action(cx, name, fields))
    }

    /// Takes the module of type `T` out of [`Context::pages`], calls `handler` with it and
    /// a context over the other modules, and puts it back; returns the handler's result.
    /// Returns `None` when no module of type `T` is registered, or when it is the module
    /// whose handler is running. A page uses it to hand work to another page, as the
    /// security overview opens an investigation on the Events page.
    pub fn with_page<T: Page, R>(
        &mut self,
        handler: impl FnOnce(&mut T, &mut Context<'_>) -> R,
    ) -> Option<R> {
        let index = self.pages.position::<T>()?;
        let mut page = self.pages.take(index)?;
        let resets = self.pages.resets;
        let mut cx = Context {
            state: &mut *self.state,
            commands: &mut *self.commands,
            pages: &mut *self.pages,
            live: &mut *self.live,
        };
        let any: &mut dyn Any = page.as_mut();
        let result = any.downcast_mut::<T>().map(|typed| handler(typed, &mut cx));
        self.pages.restore(index, page, resets);
        result
    }

    /// Calls `handler` on each other module in order until one returns `Ok(true)` or an
    /// error; see [`Pages::each`].
    pub(crate) fn each(&mut self, handler: &mut Handler<'_>) -> Result<bool, UiError> {
        self.pages.each(self.state, self.commands, self.live, handler)
    }

    /// Calls `handler` on every other module in order, stopping at the first error.
    pub(crate) fn every(
        &mut self,
        handler: &mut dyn FnMut(&mut dyn Page, &mut Context<'_>) -> Result<(), UiError>,
    ) -> Result<(), UiError> {
        self.each(&mut |page, cx| handler(page, cx).map(|()| false)).map(|_| ())
    }

    /// Closes the live connection (if one is open or opening), marks the statistics
    /// stale and releases the statistics request guard, as navigation that stops live
    /// data must. Zig wrote this as the `disconnect` command.
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn disconnect(&mut self) -> Result<(), UiError> {
        self.live.stop(self.commands)?;
        self.state.stats_busy = false;
        self.state.stale = true;
        Ok(())
    }

    /// Ends the session: the shared state and every module return to their defaults, then
    /// the phase becomes `phase`; the appearance survives. The module whose handler calls
    /// this is reset when its handler returns.
    pub fn reset_session(&mut self, phase: Phase) {
        self.state.reset_to(phase);
        self.pages.reset_all();
    }

    /// Ends a session the server no longer accepts (a 401, or a 403 that refuses the
    /// session itself): the one session-expiry rule of every page. The bridge closes the
    /// live connection, aborts the geometry download and cancels every timer; the shared
    /// state and every module return to their defaults with the sign-in phase, keeping
    /// the appearance (theme and density); the operator reads `message`, usually
    /// [`SESSION_ENDED`].
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn end_session(&mut self, message: &str) -> Result<(), UiError> {
        self.commands.disconnect()?;
        *self.live = Connection::default();
        self.reset_session(Phase::Login);
        self.state.set_message(message);
        Ok(())
    }
}

/// A page or panel module. Every method has a default that does nothing except
/// [`Page::reset`], which each module must write so that sign-out erases its state.
///
/// Handlers return `Ok(true)` when they consumed the input: later modules and the core's
/// own handling are then skipped. An `Err` aborts the event's dispatch, and the operator
/// sees the generic "Could not complete the action" message.
pub trait Page: Any {
    /// Returns the screen this module draws, if it draws one.
    fn screen(&self) -> Option<Screen> {
        None
    }

    /// Returns true when the module's screen stays on although the session is signed out:
    /// the recovery codes that confirming two-factor authentication shows once, after the
    /// confirmation ended the session. The render then draws the module without the shell.
    fn shown_signed_out(&self) -> bool {
        false
    }

    /// Draws the module's screen into `out`. Only called when [`Page::screen`] matches
    /// the current screen and the session may see it.
    ///
    /// # Errors
    ///
    /// The sink's error: the page exceeded the render bound.
    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        let _ = (view, out);
        Ok(())
    }

    /// Handles the operator action `name` with the form `fields` (an object, or `null`
    /// for navigation).
    ///
    /// # Errors
    ///
    /// Any [`UiError`]; see the trait documentation.
    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let _ = (cx, name, fields);
        Ok(false)
    }

    /// Handles a server reply. Ids are chosen by the module that sent the request; a
    /// module claims replies by their id prefix.
    ///
    /// # Errors
    ///
    /// Any [`UiError`].
    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        let _ = (cx, reply);
        Ok(false)
    }

    /// Handles the browser timer `id`. Every timer reaches every module while the tab is
    /// visible, including the one-second `age` tick that only refreshes ages; return true
    /// to stop later modules.
    ///
    /// # Errors
    ///
    /// Any [`UiError`].
    fn timer(&mut self, cx: &mut Context<'_>, id: &str) -> Result<bool, UiError> {
        let _ = (cx, id);
        Ok(false)
    }

    /// The tab became visible again: refresh what the page shows.
    ///
    /// # Errors
    ///
    /// Any [`UiError`].
    fn resume(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let _ = cx;
        Ok(())
    }

    /// A live statistics snapshot was accepted into [`State::stats`] on the dashboard or
    /// the Nodes page; request the panels that follow it.
    ///
    /// # Errors
    ///
    /// Any [`UiError`].
    fn stats_received(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let _ = cx;
        Ok(())
    }

    /// Returns the subscription filter this module wants for `topic` in `state`, or
    /// `None`. The core subscribes `stats` itself; the first module that wants another
    /// topic decides its filter, and a topic nobody wants is unsubscribed.
    fn subscription(&self, state: &State, topic: Topic) -> Option<Args> {
        let _ = (state, topic);
        None
    }

    /// Takes a completed live view of `topic` (other than `stats`). For `events` and
    /// `audit` the core has already read the view's coverage into
    /// [`State::live`].
    ///
    /// # Errors
    ///
    /// An invalid view; the core then restarts the connection.
    fn publish(
        &mut self,
        cx: &mut Context<'_>,
        topic: Topic,
        view: &Value<'_>,
    ) -> Result<(), UiError> {
        let _ = (cx, topic, view);
        Ok(())
    }

    /// The live connection failed; views the module keeps from it are now stale.
    fn connection_lost(&mut self, state: &mut State) {
        let _ = state;
    }

    /// The phase changed from `from` during this event; erase one-time values the old
    /// page showed.
    fn left(&mut self, state: &mut State, from: Phase) {
        let _ = (state, from);
    }

    /// Runs at the end of every event, after dispatch and before rendering.
    ///
    /// # Errors
    ///
    /// Any [`UiError`]; the error is ignored after the module has had its chance to
    /// record a message.
    fn finish(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let _ = cx;
        Ok(())
    }

    /// Returns to the default state, dropping every retained value.
    fn reset(&mut self);

    /// Draws one animation frame into `out` (cleared by the caller) and returns its
    /// length, or 0 for no frame; the frame may advance shared view state (the globe's
    /// turn). Only the globe animates.
    fn frame(&mut self, state: &mut State, milliseconds: f64, out: &mut String) -> usize {
        let _ = (state, milliseconds, out);
        0
    }
}

/// The registered modules, in dispatch order.
#[derive(Default)]
pub struct Pages {
    /// A slot is `None` only while its module's handler runs.
    slots: Vec<Option<Box<dyn Page>>>,
    /// Counts session resets, so a module whose handler reset the session is reset too.
    resets: u64,
}

impl fmt::Debug for Pages {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pages({} modules)", self.slots.len())
    }
}

impl Pages {
    /// Returns a registry of `pages`, dispatched in the given order.
    pub fn new(pages: Vec<Box<dyn Page>>) -> Pages {
        Pages { slots: pages.into_iter().map(Some).collect(), resets: 0 }
    }

    /// Returns the number of registered modules.
    pub fn count(&self) -> usize {
        self.slots.len()
    }

    /// Returns the module of type `T`, if registered (and not the one whose handler is
    /// running).
    pub fn find<T: Page>(&self) -> Option<&T> {
        self.slots.iter().flatten().find_map(|page| {
            let page: &dyn Any = page.as_ref();
            page.downcast_ref::<T>()
        })
    }

    /// Returns the module of type `T` for changes, if registered (and not the one whose
    /// handler is running).
    pub fn find_mut<T: Page>(&mut self) -> Option<&mut T> {
        self.slots.iter_mut().flatten().find_map(|page| {
            let page: &mut dyn Any = page.as_mut();
            page.downcast_mut::<T>()
        })
    }

    /// Returns the slot of the module of type `T`, if it is present.
    fn position<T: Page>(&self) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_deref().is_some_and(|page| {
                let page: &dyn Any = page;
                page.is::<T>()
            })
        })
    }

    /// Takes the module in slot `index` out of the registry while its handler runs.
    fn take(&mut self, index: usize) -> Option<Box<dyn Page>> {
        self.slots.get_mut(index).and_then(Option::take)
    }

    /// Puts a module back into slot `index` after its handler ran; a module whose handler
    /// reset the session (the reset count moved past `resets`) is reset too.
    fn restore(&mut self, index: usize, mut page: Box<dyn Page>, resets: u64) {
        if self.resets != resets {
            page.reset();
        }
        if let Some(slot) = self.slots.get_mut(index) {
            *slot = Some(page);
        }
    }

    /// Returns the module that draws `screen`.
    pub(crate) fn screen(&self, screen: Screen) -> Option<&dyn Page> {
        self.slots.iter().flatten().map(Box::as_ref).find(|page| page.screen() == Some(screen))
    }

    /// Returns the first filter a module wants for `topic`.
    pub(crate) fn subscription(&self, state: &State, topic: Topic) -> Option<Args> {
        self.slots.iter().flatten().find_map(|page| page.subscription(state, topic))
    }

    /// Resets every module present.
    pub(crate) fn reset_all(&mut self) {
        self.resets += 1;
        for page in self.slots.iter_mut().flatten() {
            page.reset();
        }
    }

    /// Calls `handler` on each module in order, with the module taken out of the
    /// registry, until one returns `Ok(true)` or an error.
    pub(crate) fn each(
        &mut self,
        state: &mut State,
        commands: &mut Commands,
        live: &mut Connection,
        handler: &mut Handler<'_>,
    ) -> Result<bool, UiError> {
        for index in 0..self.slots.len() {
            let Some(mut page) = self.take(index) else { continue };
            let resets = self.resets;
            let mut cx = Context {
                state: &mut *state,
                commands: &mut *commands,
                pages: &mut *self,
                live: &mut *live,
            };
            let result = handler(page.as_mut(), &mut cx);
            self.restore(index, page, resets);
            if !matches!(result, Ok(false)) {
                return result;
            }
        }
        Ok(false)
    }

    /// Calls `left` on every module after a phase change from `from`.
    pub(crate) fn left(&mut self, state: &mut State, from: Phase) {
        for page in self.slots.iter_mut().flatten() {
            page.left(state, from);
        }
    }

    /// Tells every module that the live connection failed.
    pub(crate) fn connection_lost(&mut self, state: &mut State) {
        for page in self.slots.iter_mut().flatten() {
            page.connection_lost(state);
        }
    }

    /// Asks the modules for an animation frame; the first non-empty one wins.
    pub(crate) fn frame(
        &mut self,
        state: &mut State,
        milliseconds: f64,
        out: &mut String,
    ) -> usize {
        for page in self.slots.iter_mut().flatten() {
            let length = page.frame(state, milliseconds, out);
            if length != 0 {
                return length;
            }
        }
        0
    }
}
