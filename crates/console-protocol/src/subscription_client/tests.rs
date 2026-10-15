use super::*;

/// The fields of a test frame, as Zig's `TestFrame` defaulted them.
#[derive(Clone)]
struct Frame {
    op: &'static str,
    topic: &'static str,
    epoch: String,
    seq: u64,
    snapshot: bool,
    watermark: u64,
    parts: u16,
    part: u16,
    update: u64,
    kind: &'static str,
    data: Option<&'static str>,
}

fn frame(op: &'static str) -> Frame {
    Frame {
        op,
        topic: "stats",
        epoch: format!("{}:1", "a".repeat(32)),
        seq: 0,
        snapshot: true,
        watermark: 0,
        parts: 1,
        part: 0,
        update: 1,
        kind: "patch",
        data: None,
    }
}

impl Frame {
    /// The frame as Zig's `Stringify` wrote the test struct.
    fn text(&self) -> String {
        let mut out = String::new();
        let mut json = Writer::new(&mut out);
        let _ = (|| -> fmt::Result {
            json.begin_object()?;
            json.key("op")?;
            json.string(self.op)?;
            json.key("topic")?;
            json.string(self.topic)?;
            json.key("epoch")?;
            json.string(&self.epoch)?;
            json.key("seq")?;
            json.uint(self.seq)?;
            json.key("snapshot")?;
            json.bool(self.snapshot)?;
            json.key("watermark")?;
            json.uint(self.watermark)?;
            json.key("parts")?;
            json.uint(u64::from(self.parts))?;
            json.key("part")?;
            json.uint(u64::from(self.part))?;
            json.key("update")?;
            json.uint(self.update)?;
            json.key("kind")?;
            json.string(self.kind)?;
            json.key("data")?;
            match self.data {
                Some(data) => json.string(data)?,
                None => json.null()?,
            }
            json.end_object()
        })();
        out
    }
}

fn send(client: &mut Client, frame: &Frame) -> Result<Event, ClientError> {
    client.receive_text(frame.text().as_bytes())
}

// Port of subscription_client.zig "client commits complete snapshots and patches without
// losing its last good view".
#[test]
fn client_commits_complete_snapshots_and_patches_without_losing_its_last_good_view() {
    let mut client = Client::new();
    send(&mut client, &frame("snapshot_begin")).unwrap();
    send(
        &mut client,
        &Frame { seq: 1, data: Some("{\"requests\":1}"), ..frame("snapshot_chunk") },
    )
    .unwrap();
    assert_eq!(client.view(Topic::Stats), "");
    let end = send(&mut client, &Frame { seq: 2, ..frame("snapshot_end") }).unwrap();
    assert_eq!(end, Event::Changed(Topic::Stats));
    let delta = Frame {
        snapshot: false,
        seq: 3,
        watermark: 1,
        data: Some("{\"set\":{\"requests\":\"9007199254740993\"},\"remove\":[]}"),
        ..frame("delta")
    };
    send(&mut client, &delta).unwrap();
    assert_eq!(client.view(Topic::Stats), "{\"requests\":\"9007199254740993\"}");
    let bad = Frame {
        snapshot: false,
        seq: 4,
        watermark: 2,
        data: Some("{\"set\":{\"requests\":2},\"remove\":[\"requests\"]}"),
        ..frame("delta")
    };
    assert_eq!(send(&mut client, &bad), Err(ClientError::InvalidMessage));
    assert_eq!(client.view(Topic::Stats), "{\"requests\":\"9007199254740993\"}");
    let epoch = format!("{}:2", "b".repeat(32));
    send(&mut client, &Frame { epoch: epoch.clone(), parts: 2, ..frame("snapshot_begin") })
        .unwrap();
    let chunk = Frame {
        epoch: epoch.clone(),
        parts: 2,
        seq: 1,
        data: Some("{\"requests\":"),
        ..frame("snapshot_chunk")
    };
    send(&mut client, &chunk).unwrap();
    let early = Frame { epoch, seq: 2, parts: 2, ..frame("snapshot_end") };
    assert_eq!(send(&mut client, &early), Err(ClientError::InvalidMessage));
    assert_eq!(client.view(Topic::Stats), "{\"requests\":\"9007199254740993\"}");
    client.reset();
    assert_eq!(client.view(Topic::Stats), "");
    assert!(client.slots[0].current.is_empty() && client.position(Topic::Stats).is_none());
}

#[test]
fn rows_prepend_and_keep_sixty_four() {
    let mut client = Client::new();
    send(&mut client, &frame("snapshot_begin")).unwrap();
    send(
        &mut client,
        &Frame {
            seq: 1,
            data: Some("{\"available\":true,\"rows\":[{\"id\":1}]}"),
            ..frame("snapshot_chunk")
        },
    )
    .unwrap();
    send(&mut client, &Frame { seq: 2, ..frame("snapshot_end") }).unwrap();
    let row = Frame {
        snapshot: false,
        seq: 3,
        kind: "row",
        data: Some("{\"id\":\"2\"}"),
        ..frame("delta")
    };
    assert_eq!(send(&mut client, &row), Ok(Event::Changed(Topic::Stats)));
    assert_eq!(
        client.view(Topic::Stats),
        "{\"available\":true,\"rows\":[{\"id\":\"2\"},{\"id\":1}]}"
    );
    let repeat = Frame { seq: 4, update: 2, ..row.clone() };
    assert_eq!(send(&mut client, &repeat), Err(ClientError::InvalidMessage));
    assert_eq!(client.position(Topic::Stats), None);
}

#[test]
fn deltas_split_over_parts_and_gaps_block_the_topic() {
    let mut client = Client::new();
    send(&mut client, &frame("snapshot_begin")).unwrap();
    send(
        &mut client,
        &Frame { seq: 1, data: Some("{\"a\":1,\"b\":2}"), ..frame("snapshot_chunk") },
    )
    .unwrap();
    send(&mut client, &Frame { seq: 2, ..frame("snapshot_end") }).unwrap();
    assert_eq!(client.position(Topic::Stats), Some(Position { sequence: 2, watermark: 0 }));
    let first = Frame {
        snapshot: false,
        seq: 3,
        parts: 2,
        watermark: 5,
        data: Some("{\"set\":{\"c\":3},"),
        ..frame("delta")
    };
    assert_eq!(send(&mut client, &first), Ok(Event::None));
    assert_eq!(client.position(Topic::Stats), None);
    let second = Frame { part: 1, seq: 4, data: Some("\"remove\":[\"a\"]}"), ..first.clone() };
    assert_eq!(send(&mut client, &second), Ok(Event::Changed(Topic::Stats)));
    assert_eq!(client.view(Topic::Stats), "{\"b\":2,\"c\":3}");
    assert_eq!(client.position(Topic::Stats), Some(Position { sequence: 4, watermark: 5 }));
    let gap = format!(
        "{{\"op\":\"gap\",\"topic\":\"stats\",\"epoch\":\"{}:1\",\"dropped\":\"3\"}}",
        "a".repeat(32)
    );
    assert_eq!(client.receive_text(gap.as_bytes()), Ok(Event::Gap(Topic::Stats)));
    let next =
        Frame { seq: 5, data: Some("{\"set\":{},\"remove\":[]}"), parts: 1, part: 0, ..first };
    assert_eq!(send(&mut client, &next), Err(ClientError::InvalidMessage));
    assert_eq!(client.view(Topic::Stats), "{\"b\":2,\"c\":3}");
    assert_eq!(client.receive_text(b"{\"error\":\"unauthorized\"}"), Ok(Event::Unauthorized));
    assert_eq!(client.receive_text(b"{\"error\":\"other\"}"), Err(ClientError::InvalidMessage));
    assert_eq!(client.receive_text(b"{\"op\":\"pong\"}"), Ok(Event::None));
}

#[test]
fn epochs_and_fragments_are_bounded() {
    let mut client = Client::new();
    for epoch in ["short", &format!("{}-1", "a".repeat(32)), &format!("{}:x", "g".repeat(32))] {
        let begin = Frame { epoch: epoch.to_string(), ..frame("snapshot_begin") };
        assert_eq!(send(&mut client, &begin), Err(ClientError::InvalidMessage), "{epoch}");
    }
    let underscored =
        Frame { epoch: format!("{}:1_0", "a".repeat(32)), ..frame("snapshot_begin") };
    assert_eq!(send(&mut client, &underscored), Ok(Event::None));
    let too_many =
        Frame { epoch: format!("{}:2", "a".repeat(32)), parts: 130, ..frame("snapshot_begin") };
    assert_eq!(send(&mut client, &too_many), Err(ClientError::InvalidMessage));
    send(
        &mut client,
        &Frame { epoch: format!("{}:3", "a".repeat(32)), parts: 129, ..frame("snapshot_begin") },
    )
    .unwrap();
    let long: &'static str = Box::leak("x".repeat(FRAGMENT_BYTES + 1).into_boxed_str());
    let chunk = Frame {
        epoch: format!("{}:3", "a".repeat(32)),
        parts: 129,
        seq: 1,
        data: Some(long),
        ..frame("snapshot_chunk")
    };
    assert_eq!(send(&mut client, &chunk), Err(ClientError::TooLarge));
}
