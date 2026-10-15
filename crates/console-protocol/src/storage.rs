//! The typed requests and results of the storage owner's mailbox.
//!
//! Every request is owned, so a queued request carries no borrowed caller memory and can
//! be fenced by authorization and revision checks when storage executes it. Zig bounded
//! the result union to one fixed envelope and moved larger documents through heap blocks
//! that the receiver had to free (`releaseRequest`, `releaseResult`); here large values
//! are boxed or owned and dropped with their message.

use std::fmt;

use crate::access::{AuthUser, AuthorizationCheck, Principal};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::text::{Text, check_bytes};
use crate::{
    audit, auth, challenge_minutes, challenge_records, events, geo, incident_heads, kiosk,
    minute_summary, minutes, nodes, notifications, pages, policies, ranking_history,
    ranking_storage, rankings, retention, rule_hit_history, security, similarity,
    subscription_feed, tokens, users, workflows,
};

/// The rows one incidents page may hold.
pub const MAX_PAGE_ROWS: u16 = crate::MAX_PAGE_ROWS;
/// The largest inline document a result carries.
pub const MAX_MESSAGE: usize = crate::MAX_MESSAGE;
/// The largest GeoIP batch a result carries.
pub const MAX_GEO_BYTES: usize = geo::MAX_BATCH_BYTES;

/// Live-coverage metadata of an aggregated view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Coverage {
    /// Nodes reporting.
    pub reporting: u16,
    /// Nodes expected.
    pub expected: u16,
    /// Samples lost.
    pub lost_samples: u64,
    /// Samples without a country.
    pub unknown_country: u64,
    /// The incident population is complete.
    pub incident_complete: bool,
    /// Age of the view, in milliseconds.
    pub age_ms: u64,
}

/// The committed and applied policy revisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Revision {
    /// The committed revision.
    pub committed: u64,
    /// The applied revision.
    pub applied: u64,
}

/// Why storage refused or could not finish a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Failure {
    /// No valid credential.
    Unauthorized,
    /// The credential's role or scope does not allow it.
    Forbidden,
    /// The expected revision is stale.
    Conflict,
    /// Storage is not available.
    Unavailable,
    /// A bounded table is full.
    Capacity,
    /// The request breaks its contract.
    InvalidInput,
    /// The request was cancelled.
    Cancelled,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Failure::Unauthorized => "unauthorized",
            Failure::Forbidden => "forbidden",
            Failure::Conflict => "conflict",
            Failure::Unavailable => "unavailable",
            Failure::Capacity => "capacity",
            Failure::InvalidInput => "invalid input",
            Failure::Cancelled => "cancelled",
        })
    }
}

impl std::error::Error for Failure {}

/// A request to the storage owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Reads the next page of an incident or audit feed.
    SubscriptionRead(subscription_feed::Request),
    /// Reads the cluster view for the `nodes` topic.
    SubscriptionNodes,
    /// Reads the policy view for the `policy` topic.
    SubscriptionPolicy,
    /// Reads a page of audit rows.
    AuditQuery(audit::Query),
    /// Reads one audit row with its summaries.
    AuditRead(audit::Read),
    /// Reads a page of API tokens.
    TokensQuery(tokens::Query),
    /// Creates an API token.
    TokensCreate(tokens::Create),
    /// Disables or removes an API token.
    TokensRevoke(tokens::Revoke),
    /// Reads a page of accounts.
    UsersQuery(users::Query),
    /// Creates an account.
    UsersCreate(users::Create),
    /// Changes an account.
    UsersChange(users::Change),
    /// Acquires the retention lease.
    RetentionAcquire(retention::Holder),
    /// Runs one prune step under the retention lease.
    RetentionPrune(retention::Prune),
    /// Stores a traffic minute.
    MinutesWrite(minutes::RecordWrite),
    /// Reads a page of traffic minutes.
    MinutesQuery(minutes::Query),
    /// Summarizes traffic minutes in one bounded scan.
    MinutesSummary(minutes::Query),
    /// Deletes traffic minutes before a minute index.
    MinutesPrune(u64),
    /// Stores a challenge minute.
    ChallengeMinutesWrite(challenge_minutes::RecordWrite),
    /// Deletes challenge minutes before a minute index.
    ChallengeMinutesPrune(u64),
    /// Summarizes challenge minutes in bounded scans.
    ChallengeSummary(challenge_minutes::Query),
    /// Stores a batch of challenge records.
    ChallengeRecordsWrite(challenge_records::Batch),
    /// Stores an adaptive-difficulty transition.
    ChallengeTransition(challenge_records::Transition),
    /// Reads a page of challenge records.
    ChallengeRecordsQuery(challenge_records::Query),
    /// Reads a page of difficulty transitions.
    ChallengeDifficultyQuery(challenge_records::DifficultyQuery),
    /// Reads an incident's redacted heads.
    IncidentHeadsRead(incident_heads::Read),
    /// Starts rule-hit recording for this boot.
    RuleHitsStart,
    /// Reads one part of a rule's hit history.
    RuleHitHistory(rule_hit_history::Query),
    /// Reads one retained ranking archive.
    RankingsQuery(ranking_history::Query),
    /// Starts storing a ranking archive.
    RankingsBegin(ranking_storage::Begin),
    /// Stores one chunk of a ranking archive.
    RankingsChunk(ranking_storage::Chunk),
    /// Publishes a stored ranking archive.
    RankingsFinish(ranking_storage::Finish),
    /// Deletes ranking archives before a minute index.
    RankingsPrune(u64),
    /// Asks whether the first administrator still has to be created.
    SetupStatus,
    /// Reads an account's second factor.
    TotpRead(u64),
    /// Starts a second-factor enrollment.
    TotpBegin(Box<auth::Enrollment>),
    /// Confirms a second-factor enrollment.
    TotpConfirm(Box<auth::Confirmation>),
    /// Reads the active GeoIP dataset's metadata.
    GeoMetadata,
    /// Deletes abandoned GeoIP stages older than a time.
    GeoPrune(u64),
    /// Starts staging a GeoIP dataset.
    GeoBegin(geo::Begin),
    /// Stages one GeoIP batch.
    GeoBatch(geo::Batch),
    /// Activates a staged GeoIP dataset.
    GeoActivate(geo::Activate),
    /// Reads one batch of the active GeoIP dataset.
    GeoRead(geo::Read),
    /// Creates the first administrator.
    Bootstrap(auth::Bootstrap),
    /// Reads an account by name for sign-in.
    AuthUser(Text<64>),
    /// Records a refused sign-in.
    LoginDenied(auth::Denied),
    /// Creates a session after sign-in.
    SessionCreate(auth::Session),
    /// Ends a session.
    Logout(auth::Logout),
    /// Changes the account's own password.
    PasswordChange(auth::PasswordChange),
    /// Resolves a credential into a principal.
    Authorize(AuthorizationCheck),
    /// A page of incidents before an id.
    Incidents {
        /// Incidents with smaller ids.
        before_id: Option<u64>,
        /// Rows wanted, 1 to [`MAX_PAGE_ROWS`].
        limit: u16,
    },
    /// Reads a page of incidents.
    EventsQuery(Box<events::Query>),
    /// Reads the security overview.
    SecurityQuery(security::Query),
    /// Runs one bounded similarity scan.
    EventsSimilar(similarity::Query),
    /// Reads a policy catalog page.
    PoliciesQuery(policies::Query),
    /// Evaluates a request against the policy privately.
    PoliciesTest(Box<policies::Test>),
    /// Replaces the policy document.
    PolicyEdit(policies::Edit),
    /// Replaces the inspection document.
    InspectionEdit(policies::Edit),
    /// Reads a policy document, catalog or history.
    PolicyRead(policies::Read),
    /// Reads the local node's control status.
    NodeStatus(users::Auth),
    /// Records and runs a local node command.
    NodeCommand(nodes::Command),
    /// Reads a node command's receipt.
    NodeCommandRead(nodes::Read),
    /// Reads the cluster page.
    NodesQuery(users::Auth),
    /// Publishes this console's link.
    NodeAdvertise(Text<{ nodes::MAX_URL }>),
    /// Mints a kiosk code.
    KioskGrant(kiosk::Grant),
    /// Exchanges a kiosk code for a session.
    KioskExchange(kiosk::Exchange),
    /// Reads the settings.
    SettingsQuery(users::Auth),
    /// Changes a setting.
    SettingsChange(notifications::SettingChange),
    /// Reads a page of notification destinations.
    NotificationsQuery(notifications::Query),
    /// Creates or changes a destination.
    NotificationsSave(Box<notifications::Save>),
    /// Removes a destination.
    NotificationsRemove(notifications::Remove),
    /// Reads a destination's sealed secret.
    NotificationsRead(notifications::Read),
    /// Acquires the notifier lease.
    NotifierAcquire(retention::Holder),
    /// Queues a notification event.
    NotificationsEnqueue(notifications::Enqueue),
    /// Claims the next delivery.
    NotificationsClaim(notifications::Claim),
    /// Records a delivery attempt.
    NotificationsRecord(notifications::Record),
    /// Records a test delivery's intent or result.
    NotificationsTestAudit(notifications::TestAudit),
    /// Reads a page template.
    PageRead(pages::Read),
    /// Replaces or resets a page template.
    PageEdit(pages::Edit),
    /// Moves a rule in the order.
    PolicyOrder(workflows::Order),
    /// Replays retained events against a policy.
    PolicyReplay(workflows::Replay),
    /// Reads a page of reputation entries.
    ReputationQuery(workflows::ReputationQuery),
    /// Adds or changes a reputation entry.
    ReputationEdit(workflows::ReputationEdit),
    /// Removes a reputation entry.
    ReputationRemove(workflows::ReputationRemove),
    /// Stages a chunk of country prefixes.
    CountryChunk(workflows::CountryChunk),
    /// Previews a country replacement.
    CountryPreflight(workflows::CountryPreflight),
    /// Applies a country replacement.
    CountryApply(workflows::CountryApply),
    /// Stages a chunk of a policy import.
    ImportChunk(workflows::ImportChunk),
    /// Commits a staged policy import.
    ImportCommit(workflows::ImportCommit),
}

/// A result from the storage owner.
#[derive(Clone, Debug, PartialEq)]
pub enum Response {
    /// The security overview.
    SecurityPage(Box<security::Page>),
    /// A feed page.
    SubscriptionPage(subscription_feed::Page),
    /// The local node's control status.
    NodeStatus(nodes::Status),
    /// A node command's receipt.
    NodeReceipt(nodes::Receipt),
    /// The cluster page.
    NodesPage(nodes::Page),
    /// A minted kiosk code's deadlines.
    KioskGranted(kiosk::Granted),
    /// An exchanged kiosk session.
    KioskSession(kiosk::Session),
    /// The settings.
    SettingsPage(notifications::SettingsPage),
    /// A page of destinations.
    NotificationsPage(notifications::Page),
    /// The saved destination's id.
    NotificationSaved(u64),
    /// A destination's sealed secret.
    NotificationSecret(notifications::Secret),
    /// The notifier lease.
    NotifierLease(retention::Lease),
    /// The claimed delivery, if one was due.
    NotificationClaimed(Option<Box<notifications::Claimed>>),
    /// A page template.
    PageDocument(pages::Document),
    /// A replay's result.
    ReplaySummary(workflows::ReplaySummary),
    /// A page of reputation entries.
    ReputationPage(workflows::ReputationPage),
    /// A country replacement's preview or result.
    CountrySummary(Box<workflows::CountrySummary>),
    /// A page of audit rows.
    AuditPage(audit::Page),
    /// One audit row with its summaries.
    AuditDetail(Box<audit::Detail>),
    /// A page of API tokens.
    TokensPage(tokens::Page),
    /// The created token's id.
    TokenSaved(u64),
    /// The exact durable activation timestamp storage acknowledged.
    GeoActivated(u64),
    /// The changed account's id.
    UsersSaved(u64),
    /// A page of accounts.
    UsersPage(users::Page),
    /// The retention lease.
    RetentionLease(retention::Lease),
    /// A page of traffic minutes.
    MinutePage(minutes::Page),
    /// One part of a minute summary.
    MinuteSummary(Box<minute_summary::Part>),
    /// A challenge summary.
    ChallengeSummary(Box<challenge_minutes::Summary>),
    /// A page of challenge records.
    ChallengeRecords(challenge_records::Page),
    /// A page of difficulty transitions.
    ChallengeDifficulty(challenge_records::DifficultyPage),
    /// An incident's redacted heads.
    IncidentHeads(Box<incident_heads::Heads>),
    /// One part of a rule's hit history.
    RuleHitHistory(Box<rule_hit_history::Part>),
    /// One retained ranking archive.
    RankingHistory(Box<ranking_history::Page>),
    /// The retained archives.
    RankingInventory(rankings::Inventory),
    /// A policy document.
    PolicyDocument(policies::Document),
    /// One similarity scan's result.
    Similarity(Box<similarity::Part>),
    /// Whether the first administrator still has to be created.
    SetupRequired(bool),
    /// The active GeoIP dataset's metadata.
    GeoMetadata(Box<geo::Metadata>),
    /// At most [`MAX_GEO_BYTES`] bytes of a dataset batch.
    GeoBytes(Vec<u8>),
    /// An account for sign-in.
    AuthUser(Box<AuthUser>),
    /// An account's second factor.
    Totp(Box<auth::Totp>),
    /// The resolved principal.
    Authorized(Box<Principal>),
    /// An inline document of at most [`MAX_MESSAGE`] bytes.
    Page(String),
    /// The committed and applied policy revisions.
    Revision(Revision),
    /// The mutation was recorded.
    CommandRecorded,
    /// Why the request failed.
    Failed(Failure),
}

/// Checks a request's bounds before it is queued.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] or [`ValidationError::TooLarge`] from the request's
/// own validator; requests without bounds pass.
pub fn validate(request: &Request) -> Result<(), ValidationError> {
    match request {
        Request::SubscriptionRead(input) => subscription_feed::validate(input),
        Request::NodeCommand(input) => nodes::validate(input),
        Request::AuditQuery(input) => audit::validate(input),
        Request::AuditRead(input) => limit(input.id == 0 || input.id > audit::LAST_ID),
        Request::TokensQuery(input) => users::validate_query(&users::Query {
            auth: input.auth.clone(),
            after: input.after,
            limit: input.limit,
        }),
        Request::TokensCreate(input) => tokens::validate_create(input),
        Request::TokensRevoke(input) => tokens::validate_revoke(input),
        Request::UsersQuery(input) => users::validate_query(input),
        Request::UsersCreate(input) => users::validate_create(input),
        Request::UsersChange(input) => users::validate_change(input),
        Request::RetentionAcquire(holder) => limit(holder.validate().is_err()),
        Request::RetentionPrune(input) => limit(input.lease.validate().is_err()),
        Request::MinutesQuery(query) => minutes::validate(query),
        Request::MinutesSummary(query) => minute_summary::validate(query),
        Request::ChallengeSummary(query) => challenge_minutes::validate(query),
        Request::ChallengeRecordsQuery(query) => challenge_records::validate(query),
        Request::ChallengeDifficultyQuery(query) => challenge_records::validate_difficulty(query),
        Request::RuleHitHistory(query) => rule_hit_history::validate(query),
        Request::RankingsQuery(query) => ranking_history::validate(query),
        Request::RankingsChunk(input) => check_bytes(&input.bytes, ranking_storage::CHUNK_BYTES)
            .map_err(|_| ValidationError::TooLarge),
        Request::GeoBatch(input) => {
            check_bytes(&input.bytes, geo::MAX_BATCH_BYTES).map_err(|_| ValidationError::TooLarge)
        }
        _ => validate_management(request),
    }
}

/// The policy, workflow, event and authentication part of [`validate`].
fn validate_management(request: &Request) -> Result<(), ValidationError> {
    match request {
        Request::PolicyRead(input) => policies::validate_read(input),
        Request::PoliciesQuery(query) => policies::validate(query),
        Request::PoliciesTest(input) => policies::validate_test(input),
        Request::NotificationsSave(input) => notifications::validate_save(input),
        Request::PageEdit(input) => pages::validate_edit(input),
        Request::PolicyOrder(input) => workflows::validate_order(input),
        Request::PolicyReplay(input) => workflows::validate_replay(input),
        Request::ReputationEdit(input) => workflows::validate_reputation_edit(input),
        Request::ReputationRemove(input) => workflows::validate_reputation_remove(input),
        Request::CountryChunk(input) => workflows::validate_country_chunk(input),
        Request::CountryPreflight(input) => {
            workflows::validate_country(input.count, input.expected_revision)
        }
        Request::CountryApply(input) => {
            workflows::validate_country(input.count, input.expected_revision)?;
            limit(input.until.unwrap_or(0) > MAX_I64)
        }
        Request::ImportChunk(input) => workflows::validate_import_chunk(input),
        Request::ImportCommit(input) => workflows::validate_import_commit(input),
        Request::EventsQuery(query) => events::validate(query),
        Request::SecurityQuery(query) => security::validate(query),
        Request::EventsSimilar(query) => similarity::validate(query),
        Request::GeoBegin(input) => limit(input.expected_revision >= MAX_I64),
        Request::GeoActivate(input) => limit(input.expected_revision >= MAX_I64),
        Request::TotpBegin(input) => limit(input.expected_revision >= MAX_I64),
        Request::TotpConfirm(input) => {
            limit(input.expected_revision >= MAX_I64 || input.step > MAX_I64)
        }
        Request::Incidents { limit: rows, .. } => limit(*rows == 0 || *rows > MAX_PAGE_ROWS),
        Request::PolicyEdit(edit) | Request::InspectionEdit(edit) => {
            if edit.document.is_empty() {
                return Err(ValidationError::TooLarge);
            }
            limit(edit.expected_revision >= MAX_I64)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From root.zig "owned payload boundaries and pagination reject unbounded input".
    #[test]
    fn pagination_rejects_unbounded_input() {
        let request = Request::Incidents { before_id: None, limit: 101 };
        assert_eq!(validate(&request), Err(ValidationError::InvalidLimit));
        assert_eq!(validate(&Request::Incidents { before_id: None, limit: 100 }), Ok(()));
        assert_eq!(validate(&Request::SetupStatus), Ok(()));
        let edit = policies::Edit::default();
        assert_eq!(validate(&Request::PolicyEdit(edit)), Err(ValidationError::TooLarge));
        let read = audit::Read { id: 0, ..audit::Read::default() };
        assert_eq!(validate(&Request::AuditRead(read)), Err(ValidationError::InvalidLimit));
        let holder = retention::Holder::default();
        assert_eq!(
            validate(&Request::RetentionAcquire(holder)),
            Err(ValidationError::InvalidLimit)
        );
        let apply = workflows::CountryApply {
            auth: users::Auth::default(),
            expected_revision: 0,
            digest: [0; 32],
            count: 1,
            country: *b"DE",
            action: workflows::ReputationAction::Deny,
            until: Some(u64::MAX),
            geo_generation: Text::default(),
        };
        assert_eq!(validate(&Request::CountryApply(apply)), Err(ValidationError::InvalidLimit));
    }
}
