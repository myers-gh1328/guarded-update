//! Test-only framing boundary for the future managed reporter bridge.

use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("duplicate-free JSON")
            }
            fn visit_bool<E: Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_f64<E: Error>(self, v: f64) -> Result<Unique, E> {
                Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_string<E: Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_none<E: Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_unit<E: Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some((key, Unique(value))) = map.next_entry::<String, Unique>()? {
                    if values.insert(key, value).is_some() {
                        return Err(A::Error::custom("duplicate key"));
                    }
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

pub(super) fn parse_frame(raw: &[u8]) -> Result<Value, &'static str> {
    const ERROR: &str = "Invalid private reporter frame";
    if raw.is_empty()
        || raw.len() > 256 * 1024
        || raw.last() != Some(&b'\n')
        || raw[..raw.len() - 1].contains(&b'\n')
    {
        return Err(ERROR);
    }
    parse_object(raw)
}

pub(super) fn parse_object(raw: &[u8]) -> Result<Value, &'static str> {
    const ERROR: &str = "Invalid private reporter object";
    let Unique(value) = serde_json::from_slice::<Unique>(raw).map_err(|_| ERROR)?;
    if !value.is_object() {
        return Err(ERROR);
    }
    Ok(value)
}

const DATA_ERROR: &str = "Invalid private reporter data";
const SAFE: u64 = 9_007_199_254_740_991;
const SESSION_LIMIT: usize = 64 * 1024 * 1024;

pub(super) struct DataSession {
    poisoned: bool,
    active: bool,
    last: u64,
    used: usize,
    fixed: std::collections::BTreeSet<String>,
    policies: usize,
}
impl DataSession {
    pub(super) fn new() -> Self {
        Self {
            poisoned: false,
            active: false,
            last: 0,
            used: 0,
            fixed: Default::default(),
            policies: 0,
        }
    }
    pub(super) fn start(
        &mut self,
        id: u64,
        operation: &str,
    ) -> Result<DataAssembly<'_>, &'static str> {
        let limit = match operation {
            "installed" => 8 * 1024 * 1024,
            "architecture" => 128,
            "holds" => 1024 * 1024,
            "policy" => 16 * 1024 * 1024,
            _ => 0,
        };
        if self.poisoned
            || self.active
            || id == 0
            || id > SAFE
            || id <= self.last
            || limit == 0
            || (operation == "policy" && self.policies >= 67)
            || (operation != "policy" && self.fixed.contains(operation))
        {
            self.poisoned = true;
            return Err(DATA_ERROR);
        }
        self.active = true;
        self.last = id;
        if operation == "policy" {
            self.policies += 1;
        } else {
            self.fixed.insert(operation.to_owned());
        }
        Ok(DataAssembly {
            owner: self,
            id,
            operation: operation.to_owned(),
            limit,
            text: String::new(),
            chunks: 0,
            done: false,
            taken: false,
        })
    }
}

pub(super) struct DataAssembly<'a> {
    owner: &'a mut DataSession,
    id: u64,
    operation: String,
    limit: usize,
    text: String,
    chunks: u64,
    done: bool,
    taken: bool,
}
impl DataAssembly<'_> {
    pub(super) fn feed(&mut self, raw: &[u8]) -> Result<(), &'static str> {
        let result = self.feed_inner(raw);
        if result.is_err() {
            self.owner.poisoned = true;
            self.text.clear();
        }
        result
    }
    fn feed_inner(&mut self, raw: &[u8]) -> Result<(), &'static str> {
        if self.owner.poisoned || !self.owner.active || self.done {
            return Err(DATA_ERROR);
        }
        let value = parse_frame(raw).map_err(|_| DATA_ERROR)?;
        let object = value.as_object().ok_or(DATA_ERROR)?;
        if object.get("schema_version").and_then(Value::as_u64) != Some(1)
            || object.get("id").and_then(Value::as_u64) != Some(self.id)
            || object.get("operation").and_then(Value::as_str) != Some(&self.operation)
        {
            return Err(DATA_ERROR);
        }
        match object.get("phase").and_then(Value::as_str) {
            Some("data") if object.len() == 6 => {
                let text = object
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or(DATA_ERROR)?;
                let length = text.len();
                if object.get("chunk_index").and_then(Value::as_u64) != Some(self.chunks)
                    || self.chunks >= 1024
                    || text.is_empty()
                    || text.chars().count() > 16384
                    || length > 65536
                    || self
                        .text
                        .len()
                        .checked_add(length)
                        .is_none_or(|n| n > self.limit)
                    || self
                        .owner
                        .used
                        .checked_add(length)
                        .is_none_or(|n| n > SESSION_LIMIT)
                {
                    return Err(DATA_ERROR);
                }
                self.owner.used += length;
                self.chunks += 1;
                self.text.push_str(text);
                Ok(())
            }
            Some("data_complete") if object.len() == 6 => {
                if object.get("chunks").and_then(Value::as_u64) != Some(self.chunks)
                    || object.get("utf8_bytes").and_then(Value::as_u64)
                        != Some(self.text.len() as u64)
                {
                    return Err(DATA_ERROR);
                }
                self.done = true;
                Ok(())
            }
            _ => Err(DATA_ERROR),
        }
    }
    pub(super) fn complete(&self) -> bool {
        self.done && !self.owner.poisoned
    }
    pub(super) fn take(mut self) -> Result<String, &'static str> {
        if self.owner.poisoned || !self.owner.active || !self.done {
            self.owner.poisoned = true;
            return Err(DATA_ERROR);
        }
        self.taken = true;
        self.owner.active = false;
        Ok(std::mem::take(&mut self.text))
    }
}
impl Drop for DataAssembly<'_> {
    fn drop(&mut self) {
        if !self.taken {
            self.owner.poisoned = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DataSession, parse_frame};

    #[test]
    fn data_session_assembles_only_exact_ordered_frames_and_poison_is_absorbing() {
        let mut session = DataSession::new();
        let mut data = session.start(4, "installed").unwrap();
        data.feed(b"{\"schema_version\":1,\"id\":4,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":0,\"text\":\"a\\u00e9\"}\n").unwrap();
        data.feed(b"{\"schema_version\":1,\"id\":4,\"operation\":\"installed\",\"phase\":\"data_complete\",\"chunks\":1,\"utf8_bytes\":3}\n").unwrap();
        assert_eq!(data.take().unwrap(), "aé");
        let mut data = session.start(5, "architecture").unwrap();
        assert!(data.feed(b"{\"schema_version\":1,\"id\":5,\"operation\":\"architecture\",\"phase\":\"data\",\"chunk_index\":1,\"text\":\"x\"}\n").is_err());
        drop(data);
        assert!(session.start(6, "holds").is_err());
    }

    #[test]
    fn malformed_data_never_yields_a_partial_result() {
        for frame in [
            "{\"schema_version\":1,\"id\":4,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":0,\"text\":\"\"}\n",
            "{\"schema_version\":1,\"id\":4,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":false,\"text\":\"x\"}\n",
            "{\"schema_version\":1,\"id\":4.0,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":0,\"text\":\"x\"}\n",
            "{\"schema_version\":1,\"id\":4,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":0,\"text\":\"x\",\"extra\":0}\n",
            "{\"schema_version\":1,\"id\":4,\"operation\":\"installed\",\"phase\":\"data_complete\",\"chunks\":0,\"utf8_bytes\":1}\n",
            "{\"schema_version\":1,\"id\":4,\"id\":4,\"operation\":\"installed\",\"phase\":\"data_complete\",\"chunks\":0,\"utf8_bytes\":0}\n",
        ] {
            let mut session = DataSession::new();
            let mut data = session.start(4, "installed").unwrap();
            assert!(data.feed(frame.as_bytes()).is_err());
            assert!(data.take().is_err());
            assert!(session.start(5, "holds").is_err());
        }
    }

    #[test]
    fn empty_data_and_untaken_completion_follow_session_ownership() {
        let complete = b"{\"schema_version\":1,\"id\":1,\"operation\":\"holds\",\"phase\":\"data_complete\",\"chunks\":0,\"utf8_bytes\":0}\n";
        let mut session = DataSession::new();
        let mut data = session.start(1, "holds").unwrap();
        data.feed(complete).unwrap();
        assert_eq!(data.take().unwrap(), "");
        assert!(session.start(2, "holds").is_err());

        let mut session = DataSession::new();
        let mut data = session.start(1, "holds").unwrap();
        data.feed(complete).unwrap();
        drop(data);
        assert!(session.start(2, "policy").is_err());
    }

    #[test]
    fn architecture_limit_counts_utf8_bytes_and_chunk_limit_is_enforced() {
        let mut session = DataSession::new();
        let mut data = session.start(1, "architecture").unwrap();
        let frame = format!(
            "{{\"schema_version\":1,\"id\":1,\"operation\":\"architecture\",\"phase\":\"data\",\"chunk_index\":0,\"text\":\"{}\"}}\n",
            "é".repeat(65)
        );
        assert!(data.feed(frame.as_bytes()).is_err());

        let mut session = DataSession::new();
        let mut data = session.start(1, "installed").unwrap();
        for index in 0..1024 {
            let frame = format!(
                "{{\"schema_version\":1,\"id\":1,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":{index},\"text\":\"x\"}}\n"
            );
            data.feed(frame.as_bytes()).unwrap();
        }
        let extra = b"{\"schema_version\":1,\"id\":1,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":1024,\"text\":\"x\"}\n";
        assert!(data.feed(extra).is_err());
    }

    #[test]
    fn policy_count_and_id_limits_are_absorbing() {
        let mut session = DataSession::new();
        for id in 1..=67 {
            let mut data = session.start(id, "policy").unwrap();
            let final_frame = format!(
                "{{\"schema_version\":1,\"id\":{id},\"operation\":\"policy\",\"phase\":\"data_complete\",\"chunks\":0,\"utf8_bytes\":0}}\n"
            );
            data.feed(final_frame.as_bytes()).unwrap();
            assert_eq!(data.take().unwrap(), "");
        }
        assert!(session.start(68, "policy").is_err());
        assert!(session.start(69, "holds").is_err());
        let mut session = DataSession::new();
        assert!(session.start(9_007_199_254_740_992, "holds").is_err());
        assert!(session.start(1, "holds").is_err());
    }

    #[test]
    fn forgotten_assembly_keeps_the_session_reserved() {
        let mut session = DataSession::new();
        let data = session.start(1, "installed").unwrap();
        std::mem::forget(data);
        assert!(session.start(2, "holds").is_err());
        assert!(session.start(3, "policy").is_err());
    }

    #[test]
    fn shared_budget_spans_completed_responses() {
        let mut session = DataSession::new();
        let text = "x".repeat(16384);
        for id in 1..=4 {
            let mut data = session.start(id, "policy").unwrap();
            for index in 0..1024 {
                let frame = format!(
                    "{{\"schema_version\":1,\"id\":{id},\"operation\":\"policy\",\"phase\":\"data\",\"chunk_index\":{index},\"text\":\"{text}\"}}\n"
                );
                data.feed(frame.as_bytes()).unwrap();
            }
            let complete = format!(
                "{{\"schema_version\":1,\"id\":{id},\"operation\":\"policy\",\"phase\":\"data_complete\",\"chunks\":1024,\"utf8_bytes\":16777216}}\n"
            );
            data.feed(complete.as_bytes()).unwrap();
            assert_eq!(data.take().unwrap().len(), 16 * 1024 * 1024);
        }
        let mut data = session.start(5, "policy").unwrap();
        assert!(data.feed(b"{\"schema_version\":1,\"id\":5,\"operation\":\"policy\",\"phase\":\"data\",\"chunk_index\":0,\"text\":\"x\"}\n").is_err());
    }

    #[test]
    fn chunk_character_bound_is_independent_of_byte_bound() {
        let mut session = DataSession::new();
        let mut data = session.start(1, "installed").unwrap();
        let frame = format!(
            "{{\"schema_version\":1,\"id\":1,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":0,\"text\":\"{}\"}}\n",
            "x".repeat(16385)
        );
        assert!(data.feed(frame.as_bytes()).is_err());
    }

    #[test]
    fn astral_chunks_count_scalars_and_utf8_bytes_separately() {
        let mut session = DataSession::new();
        let mut data = session.start(1, "installed").unwrap();
        let text = "😀".repeat(16384);
        let frame = format!(
            "{{\"schema_version\":1,\"id\":1,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":0,\"text\":\"{text}\"}}\n"
        );
        data.feed(frame.as_bytes()).unwrap();
        data.feed(b"{\"schema_version\":1,\"id\":1,\"operation\":\"installed\",\"phase\":\"data_complete\",\"chunks\":1,\"utf8_bytes\":65536}\n").unwrap();
        assert_eq!(data.take().unwrap(), text);
        let mut session = DataSession::new();
        let mut data = session.start(1, "installed").unwrap();
        let over = format!(
            "{{\"schema_version\":1,\"id\":1,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":0,\"text\":\"{}\"}}\n",
            "😀".repeat(16385)
        );
        assert!(data.feed(over.as_bytes()).is_err());
    }

    #[test]
    fn installed_response_cannot_exceed_its_byte_cap() {
        let mut session = DataSession::new();
        let mut data = session.start(1, "installed").unwrap();
        let text = "x".repeat(16384);
        for index in 0..512 {
            let frame = format!(
                "{{\"schema_version\":1,\"id\":1,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":{index},\"text\":\"{text}\"}}\n"
            );
            data.feed(frame.as_bytes()).unwrap();
        }
        assert!(data.feed(b"{\"schema_version\":1,\"id\":1,\"operation\":\"installed\",\"phase\":\"data\",\"chunk_index\":512,\"text\":\"x\"}\n").is_err());
    }

    #[test]
    fn accepts_only_one_bounded_duplicate_free_object() {
        let value = parse_frame(
            br#"{"phase":"prepared","evidence":{"start":1},"items":[true,null]}
"#,
        )
        .unwrap();
        assert_eq!(value["phase"], "prepared");
        assert_eq!(value["evidence"]["start"], 1);
        assert_eq!(
            parse_frame(b"{\"text\":\"a\\nb\"} \n").unwrap()["text"],
            "a\nb"
        );

        for frame in [
            b"{\"a\":1,\"a\":2}\n".as_slice(),
            b"{\"outer\":{\"a\":1,\"a\":2}}\n",
            b"{\"outer\":[{\"a\":1,\"a\":2}]}\n",
            b"{\"id\":1,\"\\u0069d\":2}\n",
            b"{\"outer\":{\"id\":1,\"\\u0069d\":2}}\n",
            b"{}",
            b"{}\n{}\n",
            b"{} \n \n",
            b"[]\n",
            b"{\"a\":NaN}\n",
            b"{\"a\":1e400}\n",
            b"{\"a\":\xff}\n",
        ] {
            assert!(parse_frame(frame).is_err());
        }
        let oversized = vec![b' '; 256 * 1024 + 1];
        assert!(parse_frame(&oversized).is_err());
        let nested = format!("{{\"a\":{}{}}}\n", "[".repeat(140), "]".repeat(140));
        assert!(parse_frame(nested.as_bytes()).is_err());
        let boundary = format!("{{\"a\":\"{}\"}}\n", "a".repeat(256 * 1024 - 9));
        assert_eq!(boundary.len(), 256 * 1024);
        assert!(parse_frame(boundary.as_bytes()).is_ok());
    }
}
