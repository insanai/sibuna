//! The security overview's retained views (`security_overview_state.zig`): one frozen
//! query range, the three storage views read under it and the live feed of the newest
//! incident summaries.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::security::{Findings, Page, Rank, Request, View};
use sibuna_json::Value;

use crate::error::UiError;
use crate::pages::events::wire::{self, counter, number, or, required, text};

/// The storage views of one query, in [`View`] order: modules, categories, paths.
pub const VIEWS: usize = 3;
/// The periods the operator may choose, in hours.
pub const PERIODS: [u16; 4] = [1, 24, 168, 720];
/// The summaries the live feed shows.
pub const FEED_ROWS: usize = 8;
/// The most rows a live `events` view carries.
const LIVE_ROWS: usize = 64;

/// One live incident summary of the feed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedRow {
    /// The incident id.
    pub id: u64,
    /// The recording node.
    pub node: u32,
    /// The incident time, in Unix seconds.
    pub time: u64,
    /// The client address.
    pub ip: Text<48>,
    /// The request path, redacted by the server.
    pub path: Text<128>,
    /// The finding category.
    pub category: Text<32>,
    /// A display field was truncated.
    pub display_truncated: bool,
}

impl FeedRow {
    /// Reads one row of a live `events` view; unknown members are ignored.
    fn read(value: &Value<'_>) -> Result<FeedRow, UiError> {
        let value = wire::object(value)?;
        Ok(FeedRow {
            id: required(value, "id", counter)?,
            node: required(value, "node", number)?,
            time: required(value, "time", counter)?,
            ip: Text::new(required(value, "ip", text)?)?,
            path: Text::new(required(value, "path", text)?)?,
            category: Text::new(required(value, "category", text)?)?,
            display_truncated: or(value, "display_truncated", false, wire::boolean)?,
        })
    }
}

/// The security overview of one query generation.
///
/// Independent views share one frozen [`Request`] range, but each keeps its own
/// observation time. The tickets identify the outstanding request of each view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    /// The chosen period, one of [`PERIODS`].
    pub hours: u16,
    /// The frozen node and half-open range of every view.
    pub request: Request,
    /// The ticket of each view's outstanding request; 0 for none.
    pub tickets: [u64; VIEWS],
    /// A view's request is in flight.
    pub busy: [bool; VIEWS],
    /// A view holds a page of the current request.
    pub loaded: [bool; VIEWS],
    /// A view's request failed.
    pub failed: [bool; VIEWS],
    /// When storage read each view, in Unix seconds.
    pub observed_at: [u64; VIEWS],
    /// Findings by module ordinal (the modules view).
    pub modules: [Findings; 3],
    /// The five largest categories.
    pub categories: [Option<Rank>; 5],
    /// The five largest paths.
    pub paths: [Option<Rank>; 5],
    /// All findings of the categories view, including those outside the top five.
    pub category_total: u64,
    /// The newest live summaries, newest first, at most [`FEED_ROWS`].
    pub feed: Vec<FeedRow>,
}

impl Default for Model {
    fn default() -> Model {
        Model {
            hours: 24,
            request: Request { until: 1, ..Request::default() },
            tickets: [0; VIEWS],
            busy: [false; VIEWS],
            loaded: [false; VIEWS],
            failed: [false; VIEWS],
            observed_at: [0; VIEWS],
            modules: Default::default(),
            categories: Default::default(),
            paths: Default::default(),
            category_total: 0,
            feed: Vec::new(),
        }
    }
}

/// Returns the index of `view` in the model's per-view arrays.
pub fn view_index(view: View) -> usize {
    match view {
        View::Modules => 0,
        View::Categories => 1,
        View::Paths => 2,
    }
}

impl Model {
    /// Takes a page of the current request.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for another format version, node or range; nothing
    /// changes.
    pub fn accept(&mut self, page: Page) -> Result<(), UiError> {
        let served = page.request;
        if page.version != 2
            || served.node != self.request.node
            || served.from != self.request.from
            || served.until != self.request.until
        {
            return Err(UiError::InvalidResponse);
        }
        match served.view {
            View::Modules => self.modules = page.modules,
            View::Categories => {
                self.categories = page.rows;
                self.category_total = page.total;
            }
            View::Paths => self.paths = page.rows,
        }
        let index = view_index(served.view);
        self.observed_at[index] = page.observed_at;
        self.loaded[index] = true;
        self.failed[index] = false;
        Ok(())
    }

    /// Takes a live `events` view: the newest [`FEED_ROWS`] of its rows replace the feed.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] when the view has no rows, more than 64, a row that
    /// cannot be read, or a row of another node than the query's; the feed is unchanged.
    pub fn live(&mut self, view: &Value<'_>) -> Result<(), UiError> {
        let rows = required(view, "rows", |rows| wire::list(rows, LIVE_ROWS))?;
        let mut candidate: Vec<FeedRow> = Vec::with_capacity(FEED_ROWS);
        for item in rows {
            let mut next = FeedRow::read(item)?;
            if self.request.node != 0 && next.node != self.request.node {
                return Err(UiError::InvalidResponse);
            }
            // Zig's insertion, kept for its order of equal rows: the carried row replaces
            // every older row it passes, which is carried on in its place.
            for row in &mut candidate {
                if (next.time, next.id) > (row.time, row.id) {
                    std::mem::swap(row, &mut next);
                }
            }
            if candidate.len() < FEED_ROWS {
                candidate.push(next);
            }
        }
        self.feed = candidate;
        Ok(())
    }
}
