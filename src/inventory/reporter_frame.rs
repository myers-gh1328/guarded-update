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

fn parse_frame(raw: &[u8]) -> Result<Value, &'static str> {
    const ERROR: &str = "Invalid private reporter frame";
    if raw.is_empty()
        || raw.len() > 256 * 1024
        || raw.last() != Some(&b'\n')
        || raw[..raw.len() - 1].contains(&b'\n')
    {
        return Err(ERROR);
    }
    let Unique(value) = serde_json::from_slice::<Unique>(raw).map_err(|_| ERROR)?;
    if !value.is_object() {
        return Err(ERROR);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::parse_frame;

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
