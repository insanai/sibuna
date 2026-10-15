//! The current-minute ranking contract. Decoders enforce the row count and key length.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, Encode, Fields, Path, WireEnum, decode_byte_array, decode_list, field,
    zig_byte_string,
};
use crate::ranking_storage::Families;
use crate::text::Text;

/// Rows per ranking.
pub const MAX_ROWS: usize = 12;
/// The longest displayed key: a 128-byte key in hex.
pub const MAX_KEY_BYTES: usize = 256;

/// How a row's key is written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// The key's own UTF-8 text.
    #[default]
    Utf8,
    /// The key's bytes in hex, when they are not UTF-8.
    Hex,
}

impl WireEnum for Encoding {
    const ALL: &'static [Encoding] = &[Encoding::Utf8, Encoding::Hex];

    fn name(self) -> &'static str {
        match self {
            Encoding::Utf8 => "utf8",
            Encoding::Hex => "hex",
        }
    }
}

/// The retained archives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Inventory {
    /// Archives are being retained.
    pub available: bool,
    /// Archives stored.
    pub archives: u64,
    /// The oldest archived minute.
    pub first_minute: Option<u64>,
    /// The newest archived minute.
    pub last_minute: Option<u64>,
    /// Charged bytes reserved.
    pub reserved_bytes: u64,
    /// When it was read, in Unix seconds.
    pub observed_at: u64,
}

impl Encode for Inventory {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "available", &self.available)?;
        field(json, "archives", &self.archives)?;
        field(json, "first_minute", &self.first_minute)?;
        field(json, "last_minute", &self.last_minute)?;
        field(json, "reserved_bytes", &self.reserved_bytes)?;
        field(json, "observed_at", &self.observed_at)?;
        json.end_object()
    }
}

impl Decode for Inventory {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Inventory, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let inventory = Inventory {
            available: fields.or_default("available")?,
            archives: fields.or_default("archives")?,
            first_minute: fields.or_default("first_minute")?,
            last_minute: fields.or_default("last_minute")?,
            reserved_bytes: fields.or_default("reserved_bytes")?,
            observed_at: fields.or_default("observed_at")?,
        };
        fields.finish()?;
        Ok(inventory)
    }
}

/// The archive writer's health.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ArchiveStatus {
    /// What is stored.
    pub stored: Inventory,
    /// Archives waiting to be written.
    pub pending: u32,
    /// Archives saved since boot.
    pub saved_since_boot: u64,
    /// Archives whose write was not confirmed.
    pub unconfirmed_since_boot: u64,
    /// Failed maintenance runs.
    pub maintenance_failures_since_boot: u64,
    /// The last minute saved.
    pub last_saved_minute: Option<u64>,
}

impl Encode for ArchiveStatus {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "stored", &self.stored)?;
        field(json, "pending", &self.pending)?;
        field(json, "saved_since_boot", &self.saved_since_boot)?;
        field(json, "unconfirmed_since_boot", &self.unconfirmed_since_boot)?;
        field(json, "maintenance_failures_since_boot", &self.maintenance_failures_since_boot)?;
        field(json, "last_saved_minute", &self.last_saved_minute)?;
        json.end_object()
    }
}

impl Decode for ArchiveStatus {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<ArchiveStatus, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let status = ArchiveStatus {
            stored: fields.or_default("stored")?,
            pending: fields.or_default("pending")?,
            saved_since_boot: fields.or_default("saved_since_boot")?,
            unconfirmed_since_boot: fields.or_default("unconfirmed_since_boot")?,
            maintenance_failures_since_boot: fields
                .or_default("maintenance_failures_since_boot")?,
            last_saved_minute: fields.or_default("last_saved_minute")?,
        };
        fields.finish()?;
        Ok(status)
    }
}

/// One ranked key with its Space-Saving bounds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Row {
    /// The key, as [`Row::encoding`] says.
    pub key: Text<MAX_KEY_BYTES>,
    /// How the key is written.
    pub encoding: Encoding,
    /// The upper bound of the key's sampled frequency.
    pub estimate: u64,
    /// How much the estimate may exceed it.
    pub error_bound: u64,
}

impl Encode for Row {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "key", &self.key)?;
        field(json, "encoding", &self.encoding)?;
        field(json, "estimate", &self.estimate)?;
        field(json, "error_bound", &self.error_bound)?;
        json.end_object()
    }
}

impl Decode for Row {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Row, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let row = Row {
            key: fields.required("key")?,
            encoding: fields.required("encoding")?,
            estimate: fields.required("estimate")?,
            error_bound: fields.required("error_bound")?,
        };
        fields.finish()?;
        Ok(row)
    }
}

/// A ranking query.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Query {
    /// One node, or `None` for the local one.
    pub node: Option<u32>,
}

/// The current minute's rankings.
///
/// The boot id is written as Zig's default serializer wrote a byte array: as a string
/// when its bytes happen to be UTF-8, otherwise as an array of numbers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Page {
    /// The node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// The archive writer's health.
    pub archive: ArchiveStatus,
    /// What is ranked, such as `path_prefix`.
    pub kind: String,
    /// The minute's start, in Unix seconds.
    pub minute_start: u64,
    /// When the snapshot was taken, in Unix seconds.
    pub snapshot_at: u64,
    /// The first sampled second.
    pub first_sample: Option<u64>,
    /// The last sampled second.
    pub last_sample: Option<u64>,
    /// Samples retained (N).
    pub retained_samples: u64,
    /// The sampling probability, such as `1/64`.
    pub sampling_probability: String,
    /// Samples whose key was truncated.
    pub truncated_records: u64,
    /// Samples refused.
    pub rejected_records: u64,
    /// Samples lost to a full queue since boot.
    pub queue_loss_since_boot: u64,
    /// The sketch's counters.
    pub counter_capacity: u16,
    /// The bound on any unlisted key's frequency.
    pub missing_key_bound: u64,
    /// At most [`MAX_ROWS`] path rows.
    pub rows: Vec<Row>,
    /// The bound on any unlisted referring host's frequency.
    pub referrer_missing_key_bound: u64,
    /// Samples with a referring host.
    pub referrer_samples: u64,
    /// At most [`MAX_ROWS`] referring hosts (24-byte host keys under the same bound).
    pub referrers: Vec<Row>,
    /// Exact sampled histograms over bounded label sets.
    pub families: Families,
}

impl Default for Page {
    fn default() -> Page {
        Page {
            node: 0,
            boot: [0; 16],
            archive: ArchiveStatus::default(),
            kind: String::from("path_prefix"),
            minute_start: 0,
            snapshot_at: 0,
            first_sample: None,
            last_sample: None,
            retained_samples: 0,
            sampling_probability: String::from("1/64"),
            truncated_records: 0,
            rejected_records: 0,
            queue_loss_since_boot: 0,
            counter_capacity: 256,
            missing_key_bound: 0,
            rows: Vec::new(),
            referrer_missing_key_bound: 0,
            referrer_samples: 0,
            referrers: Vec::new(),
            families: Families::default(),
        }
    }
}

impl Encode for Page {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        json.key("boot")?;
        zig_byte_string(json, &self.boot)?;
        field(json, "archive", &self.archive)?;
        field(json, "kind", &self.kind)?;
        field(json, "minute_start", &self.minute_start)?;
        field(json, "snapshot_at", &self.snapshot_at)?;
        field(json, "first_sample", &self.first_sample)?;
        field(json, "last_sample", &self.last_sample)?;
        field(json, "retained_samples", &self.retained_samples)?;
        field(json, "sampling_probability", &self.sampling_probability)?;
        field(json, "truncated_records", &self.truncated_records)?;
        field(json, "rejected_records", &self.rejected_records)?;
        field(json, "queue_loss_since_boot", &self.queue_loss_since_boot)?;
        field(json, "counter_capacity", &self.counter_capacity)?;
        field(json, "missing_key_bound", &self.missing_key_bound)?;
        field(json, "rows", &self.rows)?;
        field(json, "referrer_missing_key_bound", &self.referrer_missing_key_bound)?;
        field(json, "referrer_samples", &self.referrer_samples)?;
        field(json, "referrers", &self.referrers)?;
        field(json, "families", &self.families)?;
        json.end_object()
    }
}

impl Decode for Page {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Page, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let rows = |value: &Value<'_>, path: Path<'_>| decode_list(value, path, MAX_ROWS);
        let page = Page {
            node: fields.or_default("node")?,
            boot: fields.or_with("boot", [0; 16], decode_byte_array)?,
            archive: fields.or_default("archive")?,
            kind: fields.or("kind", String::from("path_prefix"))?,
            minute_start: fields.required("minute_start")?,
            snapshot_at: fields.required("snapshot_at")?,
            first_sample: fields.required("first_sample")?,
            last_sample: fields.required("last_sample")?,
            retained_samples: fields.required("retained_samples")?,
            sampling_probability: fields.or("sampling_probability", String::from("1/64"))?,
            truncated_records: fields.required("truncated_records")?,
            rejected_records: fields.required("rejected_records")?,
            queue_loss_since_boot: fields.required("queue_loss_since_boot")?,
            counter_capacity: fields.or("counter_capacity", 256)?,
            missing_key_bound: fields.required("missing_key_bound")?,
            rows: fields.required_with("rows", rows)?,
            referrer_missing_key_bound: fields.or_default("referrer_missing_key_bound")?,
            referrer_samples: fields.or_default("referrer_samples")?,
            referrers: fields.or_with("referrers", Vec::new(), rows)?,
            families: fields.or_default("families")?,
        };
        fields.finish()?;
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    #[test]
    fn boot_ids_follow_zigs_byte_array_rule() {
        let mut page = Page { boot: *b"0123456789abcdef", ..Page::default() };
        page.rows.push(Row { key: Text::new("/a").unwrap(), estimate: 3, ..Row::default() });
        let text = to_json(&page);
        assert!(
            text.starts_with("{\"node\":0,\"boot\":\"0123456789abcdef\",\"archive\":{\"stored\":")
        );
        assert_eq!(from_json::<Page>(text.as_bytes()), Ok(page.clone()));
        page.boot = [0xff; 16];
        let text = to_json(&page);
        assert!(text.contains("\"boot\":[255,255,"));
        assert!(text.ends_with(
            "\"families\":{\"os\":[0,0,0,0,0,0,0,0],\"browser\":[0,0,0,0,0,0,0,0],\
             \"status\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}"
        ));
        assert_eq!(from_json::<Page>(text.as_bytes()), Ok(page.clone()));
        page.rows = vec![Row::default(); MAX_ROWS + 1];
        assert!(from_json::<Page>(to_json(&page).as_bytes()).is_err());
    }
}
