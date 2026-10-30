//! Portable inventory request foundation. Runtime integration is separately gated.
//!
//! This module contains no helper invocation, report snapshots or update authority.
//! A validated proof establishes its schema and ordering only: the Linux adapter
//! must admit and verify actual root-owned receipts before supplying evidence.
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX: u64 = 9_007_199_254_740_991;
pub const MAX_JOURNAL: usize = 64 * 1024;
// The process lock excludes other processes, but its shared reference does not
// exclude cached handles in this process. Serialize their compare-and-write.
static JOURNAL_ACCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());
type Result<T> = std::result::Result<T, String>;
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err("Invalid inventory request metadata".into())
    }
}
fn safe(value: u64) -> bool {
    value <= MAX
}
fn positive(value: u64) -> bool {
    value > 0 && safe(value)
}
fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else if i == 14 {
                (b'1'..=b'8').contains(&b)
            } else if i == 19 {
                b"89ab".contains(&b)
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn nonce_sequence(nonce: &str) -> Option<u64> {
    if !hex(nonce, 32) {
        return None;
    }
    u64::from_str_radix(&nonce[..16], 16)
        .ok()
        .filter(|v| positive(*v))
}
fn nullable<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(d)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    #[serde(rename = "inventory_refresh_v1")]
    Manual,
    #[serde(rename = "inventory_collection_v1")]
    Collection,
}
#[derive(Clone, Copy)]
pub enum Platform {
    Linux,
    Macos,
}
pub fn capabilities(
    platform: Platform,
    collection_enabled: bool,
    verified_linux_helper: bool,
) -> Vec<Capability> {
    let mut values = Vec::new();
    if collection_enabled {
        values.push(Capability::Collection);
    }
    if matches!(platform, Platform::Linux) && verified_linux_helper {
        values.push(Capability::Manual);
    }
    values
}
#[derive(Clone)]
pub struct Negotiated {
    identity: std::sync::Arc<()>,
    enabled: bool,
    agreed: Vec<Capability>,
}
impl Negotiated {
    pub fn new(advertised: &[Capability], supported: &[Capability], enabled: bool) -> Result<Self> {
        require(
            advertised.len() <= 2
                && supported.len() <= 2
                && advertised
                    .iter()
                    .enumerate()
                    .all(|(i, c)| !advertised[..i].contains(c))
                && supported
                    .iter()
                    .enumerate()
                    .all(|(i, c)| !supported[..i].contains(c)),
        )?;
        Ok(Self {
            identity: std::sync::Arc::new(()),
            enabled,
            agreed: advertised
                .iter()
                .copied()
                .filter(|c| supported.contains(c))
                .collect(),
        })
    }
    pub fn allows(&self, capability: Capability) -> bool {
        self.enabled && self.agreed.contains(&capability)
    }
}
/// Exact negotiated controller response; parse retained response bytes, not Value reserialization.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckIn {
    pub schema_version: u32,
    pub server_time: String,
    pub source_revision: u64,
    pub reporting_enabled: bool,
    #[serde(deserialize_with = "nullable")]
    pub receipt: Option<Receipt>,
    #[serde(deserialize_with = "nullable")]
    pub refresh_request: Option<ManualDelivery>,
    pub capabilities: Vec<Capability>,
    pub requests_enabled: bool,
    #[serde(deserialize_with = "nullable")]
    pub collection_request: Option<CollectionDelivery>,
    #[serde(deserialize_with = "nullable")]
    pub refresh_status: Option<Canonical>,
    #[serde(deserialize_with = "nullable")]
    pub collection_status: Option<Canonical>,
}
impl CheckIn {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= MAX_JOURNAL)?;
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| "Invalid inventory check-in response")?;
        require(
            value.schema_version == 1 && value.reporting_enabled && positive(value.source_revision),
        )?;
        utc_millis(&value.server_time)?;
        Negotiated::new(&[], &value.capabilities, value.requests_enabled)?;
        if let Some(delivery) = &value.refresh_request {
            Delivery::Manual(delivery.clone()).validate()?;
            require(value.requests_enabled && value.capabilities.contains(&Capability::Manual))?;
        }
        if let Some(delivery) = &value.collection_request {
            Delivery::Collection(delivery.clone()).validate()?;
            require(
                value.requests_enabled
                    && value.capabilities.contains(&Capability::Collection)
                    && delivery.source_revision == value.source_revision,
            )?;
        }
        if let Some(receipt) = &value.receipt {
            require(
                receipt.schema_version == 1
                    && uuid(&receipt.enrollment_id)
                    && uuid(&receipt.report_id)
                    && positive(receipt.sequence)
                    && hex(&receipt.sha256, 64)
                    && ["current", "comparison", "history"].contains(&receipt.disposition.as_str()),
            )?;
            utc_millis(&receipt.accepted_at)?;
        }
        for status in [&value.refresh_status, &value.collection_status]
            .into_iter()
            .flatten()
        {
            status.validate()?;
        }
        Ok(value)
    }
}

/// This permits only a fresh legacy check-in, never request work or rewriting a report.
pub fn legacy_fallback(status: u16, response: &[u8]) -> bool {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ErrorBody {
        error: OldError,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OldError {
        code: String,
        message: String,
        request_id: String,
    }
    status == 422
        && response.len() <= MAX_JOURNAL
        && serde_json::from_slice::<ErrorBody>(response).is_ok_and(|v| {
            v.error.code == "invalid_check_in"
                && v.error.message.len() <= 256
                && uuid(&v.error.request_id)
        })
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanProof {
    pub report_id: String,
    pub sequence: u64,
    pub source_revision: u64,
    pub started_boottime_ms: u64,
    #[serde(deserialize_with = "nullable")]
    pub finished_boottime_ms: Option<u64>,
}
impl ScanProof {
    fn validate(&self) -> Result<()> {
        require(
            uuid(&self.report_id)
                && positive(self.sequence)
                && positive(self.source_revision)
                && safe(self.started_boottime_ms)
                && self
                    .finished_boottime_ms
                    .is_none_or(|v| safe(v) && v >= self.started_boottime_ms),
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionProof {
    pub schema_version: u32,
    pub operation_nonce: String,
    pub collection_sequence: u64,
    pub boot_id: String,
    pub accepted_boottime_ms: u64,
    #[serde(deserialize_with = "nullable")]
    pub scan: Option<ScanProof>,
}
impl CollectionProof {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == 1
                && positive(self.collection_sequence)
                && nonce_sequence(&self.operation_nonce) == Some(self.collection_sequence)
                && uuid(&self.boot_id)
                && safe(self.accepted_boottime_ms),
        )?;
        if let Some(scan) = &self.scan {
            scan.validate()?;
            require(scan.started_boottime_ms >= self.accepted_boottime_ms)?;
        }
        Ok(())
    }
    pub fn ready(&self) -> bool {
        self.validate().is_ok()
            && self
                .scan
                .as_ref()
                .is_some_and(|s| s.finished_boottime_ms.is_some())
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperResult {
    Succeeded,
    Failed,
    Deferred,
    Unconfirmed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperProof {
    pub operation_nonce: String,
    pub helper_sequence: u64,
    pub boot_id: String,
    pub accepted_boottime_ms: u64,
    #[serde(deserialize_with = "nullable")]
    pub started_boottime_ms: Option<u64>,
    #[serde(deserialize_with = "nullable")]
    pub finished_boottime_ms: Option<u64>,
    #[serde(deserialize_with = "nullable")]
    pub result: Option<HelperResult>,
    #[serde(deserialize_with = "nullable")]
    pub cache_generation: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub policy_generation: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderProof {
    pub boot_id: String,
    pub cache_generation: String,
    pub policy_generation: String,
    pub opened_boottime_ms: u64,
    #[serde(deserialize_with = "nullable")]
    pub closed_boottime_ms: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationProof {
    pub nonce: String,
    pub boot_id: String,
    pub cache_generation: String,
    pub policy_generation: String,
    pub opened_boottime_ms: u64,
    pub expires_boottime_ms: u64,
    #[serde(deserialize_with = "nullable")]
    pub held_until_boottime_ms: Option<u64>,
    #[serde(deserialize_with = "nullable")]
    pub released_boottime_ms: Option<u64>,
    #[serde(deserialize_with = "nullable")]
    pub coherent: Option<bool>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualProof {
    pub schema_version: u32,
    pub operation_nonce: String,
    pub helper_sequence: u64,
    pub boot_id: String,
    pub accepted_boottime_ms: u64,
    pub deadline_boottime_ms: u64,
    #[serde(deserialize_with = "nullable")]
    pub helper: Option<HelperProof>,
    #[serde(deserialize_with = "nullable")]
    pub reader: Option<ReaderProof>,
    #[serde(deserialize_with = "nullable")]
    pub observation: Option<ObservationProof>,
    #[serde(deserialize_with = "nullable")]
    pub scan: Option<ScanProof>,
}
impl ManualProof {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == 1
                && positive(self.helper_sequence)
                && nonce_sequence(&self.operation_nonce) == Some(self.helper_sequence)
                && uuid(&self.boot_id)
                && safe(self.accepted_boottime_ms)
                && safe(self.deadline_boottime_ms)
                && self.deadline_boottime_ms >= self.accepted_boottime_ms
                && self.deadline_boottime_ms - self.accepted_boottime_ms <= 86_700_000,
        )?;
        if let Some(h) = &self.helper {
            require(
                h.operation_nonce == self.operation_nonce
                    && h.helper_sequence == self.helper_sequence
                    && h.boot_id == self.boot_id
                    && safe(h.accepted_boottime_ms)
                    && h.accepted_boottime_ms >= self.accepted_boottime_ms
                    && h.started_boottime_ms.is_none_or(|v| {
                        safe(v) && v >= h.accepted_boottime_ms && v <= self.deadline_boottime_ms
                    })
                    && h.finished_boottime_ms.is_none_or(|v| {
                        safe(v)
                            && v >= h.accepted_boottime_ms
                            && h.started_boottime_ms
                                .is_none_or(|s| v >= s && v - s <= 600_000)
                    })
                    && h.cache_generation.as_ref().is_none_or(|v| hex(v, 32))
                    && h.policy_generation.as_ref().is_none_or(|v| hex(v, 64)),
            )?;
            if h.result == Some(HelperResult::Succeeded) {
                require(
                    h.started_boottime_ms.is_some()
                        && h.finished_boottime_ms.is_some()
                        && h.cache_generation.is_some()
                        && h.policy_generation.is_some(),
                )?;
            }
        }
        if let Some(r) = &self.reader {
            let h = self.helper.as_ref().ok_or("Reader lacks helper evidence")?;
            require(
                h.result == Some(HelperResult::Succeeded)
                    && r.boot_id == self.boot_id
                    && Some(&r.cache_generation) == h.cache_generation.as_ref()
                    && Some(&r.policy_generation) == h.policy_generation.as_ref()
                    && safe(r.opened_boottime_ms)
                    && h.finished_boottime_ms
                        .is_some_and(|v| r.opened_boottime_ms >= v)
                    && r.closed_boottime_ms
                        .is_none_or(|v| safe(v) && v >= r.opened_boottime_ms),
            )?;
        }
        if let Some(o) = &self.observation {
            let r = self
                .reader
                .as_ref()
                .ok_or("Observation lacks reader evidence")?;
            require(
                nonce_sequence(&o.nonce).is_some()
                    && o.boot_id == self.boot_id
                    && o.cache_generation == r.cache_generation
                    && o.policy_generation == r.policy_generation
                    && safe(o.opened_boottime_ms)
                    && o.opened_boottime_ms >= r.opened_boottime_ms
                    && safe(o.expires_boottime_ms)
                    && o.expires_boottime_ms >= o.opened_boottime_ms
                    && o.expires_boottime_ms - o.opened_boottime_ms <= 120_000
                    && o.held_until_boottime_ms.is_none_or(|v| {
                        safe(v) && v >= o.opened_boottime_ms && v <= o.expires_boottime_ms
                    })
                    && o.released_boottime_ms.is_none_or(|v| {
                        safe(v)
                            && v <= o.expires_boottime_ms
                            && o.held_until_boottime_ms.is_some_and(|h| v >= h)
                    })
                    && (o.coherent.is_none()
                        || o.held_until_boottime_ms.is_some() && o.released_boottime_ms.is_some())
                    && r.closed_boottime_ms
                        .is_none_or(|v| o.held_until_boottime_ms.is_some_and(|h| v >= h)),
            )?;
        }
        if let Some(s) = &self.scan {
            s.validate()?;
            let o = self
                .observation
                .as_ref()
                .ok_or("Scan lacks observation evidence")?;
            require(
                s.started_boottime_ms >= o.opened_boottime_ms
                    && s.started_boottime_ms <= o.expires_boottime_ms
                    && s.finished_boottime_ms.is_none_or(|v| {
                        v <= o.expires_boottime_ms
                            && o.held_until_boottime_ms.is_none_or(|h| v <= h)
                    }),
            )?;
        }
        Ok(())
    }
    pub fn ready(&self) -> bool {
        self.validate().is_ok()
            && self.helper.as_ref().is_some_and(|h| {
                h.result == Some(HelperResult::Succeeded) && h.finished_boottime_ms.is_some()
            })
            && self
                .reader
                .as_ref()
                .is_some_and(|r| r.closed_boottime_ms.is_some())
            && self
                .observation
                .as_ref()
                .is_some_and(|o| o.coherent == Some(true) && o.released_boottime_ms.is_some())
            && self
                .scan
                .as_ref()
                .is_some_and(|s| s.finished_boottime_ms.is_some())
    }
    fn no_work(&self) -> bool {
        self.helper.as_ref().is_some_and(|h| {
            h.result == Some(HelperResult::Deferred)
                && h.started_boottime_ms.is_none()
                && h.finished_boottime_ms.is_some()
        }) && self.reader.is_none()
            && self.observation.is_none()
            && self.scan.is_none()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "evidence", deny_unknown_fields)]
pub enum Proof {
    Manual(Box<ManualProof>),
    Collection(CollectionProof),
}
impl Proof {
    pub fn parse(capability: Capability, bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= MAX_JOURNAL)?;
        let proof = match capability {
            Capability::Manual => {
                Self::Manual(serde_json::from_slice(bytes).map_err(|_| "Invalid manual proof")?)
            }
            Capability::Collection => Self::Collection(
                serde_json::from_slice(bytes).map_err(|_| "Invalid collection proof")?,
            ),
        };
        proof.validate()?;
        Ok(proof)
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Manual(p) => p.validate(),
            Self::Collection(p) => p.validate(),
        }
    }
    pub fn ready(&self) -> bool {
        match self {
            Self::Manual(p) => p.ready(),
            Self::Collection(p) => p.ready(),
        }
    }
    pub fn wire(&self) -> Result<Value> {
        match self {
            Self::Manual(p) => serde_json::to_value(p),
            Self::Collection(p) => serde_json::to_value(p),
        }
        .map_err(|_| "Cannot encode request proof".into())
    }
    pub fn merge(&self, next: &Self) -> Result<Self> {
        self.validate()?;
        next.validate()?;
        require(self.capability() == next.capability())?;
        fn fill(a: Value, b: Value) -> Result<Value> {
            if a.is_null() {
                return Ok(b);
            }
            if b.is_null() {
                return Ok(a);
            }
            if let (Some(left), Some(right)) = (a.as_object(), b.as_object()) {
                require(left.len() == right.len() && left.keys().all(|k| right.contains_key(k)))?;
                return Ok(Value::Object(
                    left.iter()
                        .map(|(k, v)| Ok((k.clone(), fill(v.clone(), right[k].clone())?)))
                        .collect::<Result<_>>()?,
                ));
            }
            require(a == b)?;
            Ok(a)
        }
        Self::parse(
            self.capability(),
            &serde_json::to_vec(&fill(self.wire()?, next.wire()?)?)
                .map_err(|_| "Cannot merge proof")?,
        )
    }
    fn capability(&self) -> Capability {
        match self {
            Self::Manual(_) => Capability::Manual,
            Self::Collection(_) => Capability::Collection,
        }
    }
    fn nonce(&self) -> &str {
        match self {
            Self::Manual(p) => &p.operation_nonce,
            Self::Collection(p) => &p.operation_nonce,
        }
    }
    fn sequence(&self) -> u64 {
        match self {
            Self::Manual(p) => p.helper_sequence,
            Self::Collection(p) => p.collection_sequence,
        }
    }
    fn boot(&self) -> &str {
        match self {
            Self::Manual(p) => &p.boot_id,
            Self::Collection(p) => &p.boot_id,
        }
    }
    fn accepted(&self) -> u64 {
        match self {
            Self::Manual(p) => p.accepted_boottime_ms,
            Self::Collection(p) => p.accepted_boottime_ms,
        }
    }
    fn scan(&self) -> Option<&ScanProof> {
        match self {
            Self::Manual(p) => p.scan.as_ref(),
            Self::Collection(p) => p.scan.as_ref(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualDelivery {
    pub request_id: String,
    pub delivery_sequence: u64,
    pub expires_at: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionDelivery {
    pub request_id: String,
    pub delivery_sequence: u64,
    pub not_before: String,
    pub source_revision: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "delivery", deny_unknown_fields)]
pub enum Delivery {
    Manual(ManualDelivery),
    Collection(CollectionDelivery),
}
impl Delivery {
    fn capability(&self) -> Capability {
        match self {
            Self::Manual(_) => Capability::Manual,
            Self::Collection(_) => Capability::Collection,
        }
    }
    fn id(&self) -> &str {
        match self {
            Self::Manual(d) => &d.request_id,
            Self::Collection(d) => &d.request_id,
        }
    }
    fn sequence(&self) -> u64 {
        match self {
            Self::Manual(d) => d.delivery_sequence,
            Self::Collection(d) => d.delivery_sequence,
        }
    }
    fn validate(&self) -> Result<()> {
        require(uuid(self.id()) && positive(self.sequence()))?;
        match self {
            Self::Manual(d) => {
                utc_millis(&d.expires_at)?;
            }
            Self::Collection(d) => {
                utc_millis(&d.not_before)?;
                require(positive(d.source_revision))?;
            }
        }
        Ok(())
    }
}
/// Server dates are canonical UTC RFC3339, with optional millisecond precision.
fn utc_millis(value: &str) -> Result<u64> {
    let b = value.as_bytes();
    require(
        (b.len() == 20 || b.len() == 24)
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[b.len() - 1] == b'Z',
    )?;
    require(b.iter().enumerate().all(|(i, c)| {
        [4, 7, 10, 13, 16, b.len() - 1].contains(&i)
            || (b.len() == 24 && i == 19 && *c == b'.')
            || c.is_ascii_digit()
    }))?;
    let number = |a: usize, z: usize| {
        value[a..z]
            .parse::<u64>()
            .map_err(|_| "Invalid request timestamp".to_owned())
    };
    let (year, month, day, hour, minute, second) = (
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    require(
        (1970..=9999).contains(&year)
            && (1..=12).contains(&month)
            && hour < 24
            && minute < 60
            && second < 60,
    )?;
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    require(day > 0 && day <= months[(month - 1) as usize])?;
    let days = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + months[..(month - 1) as usize].iter().sum::<u64>()
        + day
        - 1;
    Ok(((days * 24 + hour) * 60 * 60 + minute * 60 + second) * 1000
        + if b.len() == 24 { number(20, 23)? } else { 0 })
}
#[derive(Clone)]
pub struct Clock {
    pub boot_id: String,
    pub boottime_ms: u64,
    pub unix_ms: u64,
}
impl Clock {
    pub(super) fn validate(&self) -> Result<()> {
        require(uuid(&self.boot_id) && safe(self.boottime_ms) && safe(self.unix_ms))
    }
}
#[derive(Clone, Copy)]
pub enum OperationDomain {
    Helper,
    Collection,
    Observation,
}
/// Explicit initialization only, after trusted root-counter admission and proving
/// no unresolved old operation. Never silently reseed an existing journal.
pub struct CounterSeeds {
    pub helper: u64,
    pub observation: u64,
}
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Counters {
    helper: u64,
    collection: u64,
    observation: u64,
}
impl Counters {
    fn value(&self, domain: OperationDomain) -> u64 {
        match domain {
            OperationDomain::Helper => self.helper,
            OperationDomain::Collection => self.collection,
            OperationDomain::Observation => self.observation,
        }
    }
    fn reserve(&mut self, domain: OperationDomain, suffix: &str) -> Result<String> {
        require(hex(suffix, 16))?;
        let next = self
            .value(domain)
            .checked_add(1)
            .filter(|v| positive(*v))
            .ok_or("Operation counter exhausted; reconcile enrollment")?;
        match domain {
            OperationDomain::Helper => self.helper = next,
            OperationDomain::Collection => self.collection = next,
            OperationDomain::Observation => self.observation = next,
        }
        Ok(format!("{next:016x}{suffix}"))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientStatus {
    Received,
    Running,
    Deferred,
    Failed,
    ResultSuperseded,
    Unconfirmed,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalStatus {
    Queued,
    Delivered,
    Running,
    Deferred,
    Unconfirmed,
    Failed,
    Complete,
    Expired,
}
impl CanonicalStatus {
    fn terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Complete | Self::Expired)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusMessage {
    pub schema_version: u32,
    pub enrollment_id: String,
    pub request_id: String,
    pub delivery_sequence: u64,
    pub status: ClientStatus,
    #[serde(deserialize_with = "nullable")]
    pub report_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub report_sha256: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub operation_nonce: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub attempt: Option<Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRequest {
    pub request_id: String,
    pub delivery_sequence: u64,
    pub status: CanonicalStatus,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub report_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub report_sha256: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub operation_nonce: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub enrollment_id: String,
    pub report_id: String,
    pub sequence: u64,
    pub sha256: String,
    pub accepted_at: String,
    pub disposition: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Canonical {
    pub schema_version: u32,
    pub request: CanonicalRequest,
    #[serde(deserialize_with = "nullable")]
    pub receipt: Option<Receipt>,
}
impl Canonical {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= MAX_JOURNAL)?;
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| "Invalid canonical request response")?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        let r = &self.request;
        require(
            self.schema_version == 1
                && uuid(&r.request_id)
                && positive(r.delivery_sequence)
                && reason(&r.reason)
                && r.operation_nonce
                    .as_ref()
                    .is_none_or(|v| nonce_sequence(v).is_some()),
        )?;
        report_pair(&r.report_id, &r.report_sha256)?;
        if let Some(receipt) = &self.receipt {
            require(
                receipt.schema_version == 1
                    && uuid(&receipt.enrollment_id)
                    && uuid(&receipt.report_id)
                    && positive(receipt.sequence)
                    && hex(&receipt.sha256, 64)
                    && ["current", "comparison", "history"].contains(&receipt.disposition.as_str()),
            )?;
            utc_millis(&receipt.accepted_at)?;
        }
        Ok(())
    }
}
fn report_pair(id: &Option<String>, hash: &Option<String>) -> Result<()> {
    require(match (id, hash) {
        (None, None) => true,
        (Some(i), Some(h)) => uuid(i) && hex(h, 64),
        _ => false,
    })
}
fn reason(value: &Option<String>) -> bool {
    value.as_ref().is_none_or(|v| {
        [
            "busy",
            "resource_limit",
            "repository_failed",
            "unsupported_policy",
            "timeout",
            "cleanup_unknown",
            "unavailable",
            "expired_before_start",
            "collection_failed",
            "result_superseded",
            "minimum_interval",
            "package_manager_busy",
            "executor_busy",
            "policy_changed",
            "state_inconsistent",
            "cache_unavailable",
            "inventory_authority_changed",
            "reporting_revoked",
            "stale_refresh_evidence",
            "historical_report",
            "refresh_attempt_unconfirmed",
            "refresh_attempt_conflict",
        ]
        .contains(&v.as_str())
    })
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportRef {
    id: String,
    sha256: String,
    sequence: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeAttempt {
    observation_nonce: String,
    boot_id: String,
    admitted_boottime_ms: u64,
    #[serde(deserialize_with = "nullable")]
    release_requested_boottime_ms: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    delivery: Delivery,
    source_revision: u64,
    proof: Proof,
    #[serde(deserialize_with = "nullable")]
    previous_no_work: Option<ManualProof>,
    #[serde(deserialize_with = "nullable")]
    acknowledged_nonce: Option<String>,
    submitted: bool,
    #[serde(deserialize_with = "nullable")]
    native_attempt: Option<NativeAttempt>,
    no_work_acknowledged: bool,
    pending_status: ClientStatus,
    #[serde(deserialize_with = "nullable")]
    reason: Option<String>,
    #[serde(deserialize_with = "nullable")]
    report: Option<ReportRef>,
    #[serde(deserialize_with = "nullable")]
    terminal: Option<CanonicalStatus>,
    attempts: u32,
}
impl Entry {
    fn validate(&self) -> Result<()> {
        self.delivery.validate()?;
        self.proof.validate()?;
        require(
            positive(self.source_revision)
                && self.delivery.capability() == self.proof.capability()
                && (1..=512).contains(&self.attempts)
                && reason(&self.reason)
                && self
                    .acknowledged_nonce
                    .as_ref()
                    .is_none_or(|v| v == self.proof.nonce())
                && self.terminal.is_none_or(|s| s.terminal())
                && (!self.submitted || self.acknowledged_nonce.is_some())
                && !(matches!(self.proof, Proof::Collection(_))
                    && self.proof.ready()
                    && self.report.is_none()),
        )?;
        if let Some(native) = &self.native_attempt {
            require(
                matches!(self.proof, Proof::Collection(_))
                    && self.submitted
                    && self.acknowledged_nonce.is_some()
                    && native.boot_id == self.proof.boot()
                    && nonce_sequence(&native.observation_nonce).is_some()
                    && safe(native.admitted_boottime_ms)
                    && self.proof.accepted() <= native.admitted_boottime_ms
                    && self
                        .proof
                        .scan()
                        .is_none_or(|scan| native.admitted_boottime_ms <= scan.started_boottime_ms)
                    && native.release_requested_boottime_ms.is_none_or(|time| {
                        safe(time)
                            && time >= native.admitted_boottime_ms
                            && self
                                .proof
                                .scan()
                                .is_none_or(|scan| time >= scan.started_boottime_ms)
                    }),
            )?;
        }
        if let Delivery::Collection(d) = &self.delivery {
            require(d.source_revision == self.source_revision)?;
        }
        if let Some(scan) = self.proof.scan() {
            require(scan.source_revision == self.source_revision)?;
        }
        if let Some(old) = &self.previous_no_work {
            old.validate()?;
            require(
                matches!(self.proof, Proof::Manual(_))
                    && old.no_work()
                    && old.helper_sequence < self.proof.sequence(),
            )?;
        }
        if let Some(report) = &self.report {
            require(
                uuid(&report.id)
                    && hex(&report.sha256, 64)
                    && positive(report.sequence)
                    && self.proof.ready()
                    && self
                        .proof
                        .scan()
                        .is_some_and(|s| s.report_id == report.id && s.sequence == report.sequence),
            )?;
        }
        Ok(())
    }
    fn matches_native_intent(&self, intent: &NativeCollectionIntent) -> bool {
        self.submitted
            && self.pending_status == ClientStatus::Running
            && self.delivery.id() == intent.request_id
            && self.proof.nonce() == intent.operation_nonce
            && self.acknowledged_nonce.as_deref() == Some(intent.operation_nonce.as_str())
            && self.source_revision == intent.scan.source_revision
            && self.proof.boot() == intent.boot_id
            && self.proof.scan().is_none()
            && self.native_attempt.as_ref().is_some_and(|native| {
                native.observation_nonce == intent.observation_nonce
                    && native.boot_id == intent.boot_id
                    && native.admitted_boottime_ms == intent.admitted_boottime_ms
                    && native.release_requested_boottime_ms.is_none()
            })
    }
    fn status(&self, enrollment: &str) -> Result<StatusMessage> {
        Ok(StatusMessage {
            schema_version: 1,
            enrollment_id: enrollment.into(),
            request_id: self.delivery.id().into(),
            delivery_sequence: self.delivery.sequence(),
            status: self.pending_status,
            report_id: self.report.as_ref().map(|r| r.id.clone()),
            report_sha256: self.report.as_ref().map(|r| r.sha256.clone()),
            reason: self.reason.clone(),
            operation_nonce: Some(self.proof.nonce().into()),
            attempt: if self.pending_status == ClientStatus::Failed
                && self.acknowledged_nonce.is_none()
                && !self.submitted
            {
                None
            } else {
                Some(self.proof.wire()?)
            },
        })
    }
}
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Domain {
    delivery_highwater: u64,
    #[serde(deserialize_with = "nullable")]
    active: Option<Entry>,
    #[serde(deserialize_with = "nullable")]
    last_terminal: Option<Entry>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    enrollment_id: String,
    counters: Counters,
    manual: Domain,
    collection: Domain,
}
impl Journal {
    fn retained_collection(&self, id: &str) -> Result<&Entry> {
        let mut matches = [&self.collection.active, &self.collection.last_terminal]
            .into_iter()
            .flatten()
            .filter(|entry| entry.delivery.id() == id);
        let entry = matches.next().ok_or("No retained collection request")?;
        require(matches.next().is_none())?;
        Ok(entry)
    }
    fn retained_collection_mut(&mut self, id: &str) -> Result<&mut Entry> {
        self.retained_collection(id)?;
        if self
            .collection
            .active
            .as_ref()
            .is_some_and(|entry| entry.delivery.id() == id)
        {
            self.collection
                .active
                .as_mut()
                .ok_or("No retained collection request".into())
        } else {
            self.collection
                .last_terminal
                .as_mut()
                .ok_or("No retained collection request".into())
        }
    }
    fn domain(&self, cap: Capability) -> &Domain {
        match cap {
            Capability::Manual => &self.manual,
            Capability::Collection => &self.collection,
        }
    }
    fn domain_mut(&mut self, cap: Capability) -> &mut Domain {
        match cap {
            Capability::Manual => &mut self.manual,
            Capability::Collection => &mut self.collection,
        }
    }
    fn validate(&self) -> Result<()> {
        require(
            self.schema_version == 2
                && uuid(&self.enrollment_id)
                && safe(self.counters.helper)
                && safe(self.counters.collection)
                && safe(self.counters.observation),
        )?;
        let mut observations = Vec::new();
        for cap in [Capability::Manual, Capability::Collection] {
            let domain = self.domain(cap);
            require(safe(domain.delivery_highwater))?;
            if let Some(active) = &domain.active {
                require(active.terminal.is_none())?;
            }
            if let Some(last) = &domain.last_terminal {
                require(last.terminal.is_some())?;
            }
            if let (Some(a), Some(t)) = (&domain.active, &domain.last_terminal) {
                require(a.delivery.sequence() > t.delivery.sequence())?;
            }
            for entry in [&domain.active, &domain.last_terminal]
                .into_iter()
                .flatten()
            {
                entry.validate()?;
                let observation = match &entry.proof {
                    Proof::Manual(proof) => proof.observation.as_ref().map(|v| v.nonce.as_str()),
                    Proof::Collection(_) => entry
                        .native_attempt
                        .as_ref()
                        .map(|v| v.observation_nonce.as_str()),
                };
                if let Some(nonce) = observation {
                    let sequence =
                        nonce_sequence(nonce).ok_or("Invalid retained observation nonce")?;
                    require(
                        sequence <= self.counters.observation && !observations.contains(&sequence),
                    )?;
                    observations.push(sequence);
                }
                require(
                    entry.delivery.capability() == cap
                        && entry.delivery.sequence() <= domain.delivery_highwater
                        && entry.proof.sequence()
                            <= self.counters.value(match cap {
                                Capability::Manual => OperationDomain::Helper,
                                Capability::Collection => OperationDomain::Collection,
                            }),
                )?;
            }
        }
        Ok(())
    }
    fn historical_collection_safe(&self) -> Result<()> {
        require(!self.collection.last_terminal.as_ref().is_some_and(|last| {
            !last.proof.ready()
                && (last.submitted
                    || matches!(
                        last.pending_status,
                        ClientStatus::Running | ClientStatus::Unconfirmed
                    ))
        }))
    }
    fn collection_only_safe(&self) -> Result<()> {
        self.historical_collection_safe()?;
        require(
            self.manual.active.is_none()
                && !self
                    .manual
                    .last_terminal
                    .as_ref()
                    .is_some_and(|e| e.submitted && !e.proof.ready()),
        )
    }
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "Cannot encode request journal")?;
        require(bytes.len() <= MAX_JOURNAL)?;
        Ok(bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    New,
    Duplicate,
    Terminal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionRecovery {
    Idle,
    Waiting,
    Unfinished,
    Ready,
    Superseded,
}
/// Descriptor derived from the actual protected latest report bytes, never a receipt.
pub struct RetainedInventory {
    pub enrollment_id: String,
    pub report_id: String,
    pub sequence: u64,
    pub sha256: String,
}
/// All access borrows the existing inventory process lock. No second scheduler
/// or independent writer is introduced. Failed/uncertain persistence poisons
/// this handle: reopen and reconcile before any further request action.
/// Same-run, one-use admission correlation, never recoverable from submitted
/// metadata. Dropping it retains the durable uncertainty fence. Its raw nonce
/// is not permission to submit after epoch/negotiation invalidation; the fixed
/// Control adapter must check current authority before every external effect.
pub struct NativeCollectionIntent {
    epoch: std::sync::Arc<()>,
    negotiation: std::sync::Arc<()>,
    request_id: String,
    operation_nonce: String,
    boot_id: String,
    admitted_boottime_ms: u64,
    observation_nonce: String,
    scan: ScanProof,
}
impl NativeCollectionIntent {
    pub fn observation_nonce(&self) -> &str {
        &self.observation_nonce
    }
}
/// Consumed admission after bounded fixed-inbox publication ACK, not Root
/// acceptance/liveness/coherence. Cannot be recreated from durable metadata.
pub struct PublishedNativeCollection {
    intent: NativeCollectionIntent,
}
/// Local cleanup-publication correlation, never observation/scan authority.
/// The trusted bridge must bind its callback to the literal release port.
pub struct NativeReleaseIntent {
    epoch: std::sync::Arc<()>,
    request_id: String,
    observation_nonce: String,
    boot_id: String,
    first_requested_boottime_ms: u64,
}
impl NativeReleaseIntent {
    pub fn observation_nonce(&self) -> &str {
        &self.observation_nonce
    }
}
impl PublishedNativeCollection {
    pub fn observation_nonce(&self) -> &str {
        self.intent.observation_nonce()
    }
}
fn native_authority(
    intent: &NativeCollectionIntent,
    epoch: &std::sync::Arc<()>,
    clock: &Clock,
    session: &Negotiated,
) -> Result<()> {
    clock.validate()?;
    require(
        std::sync::Arc::ptr_eq(epoch, &intent.epoch)
            && std::sync::Arc::ptr_eq(&session.identity, &intent.negotiation)
            && session.allows(Capability::Collection)
            && clock.boot_id == intent.boot_id
            && clock.boottime_ms >= intent.admitted_boottime_ms,
    )
}
pub struct RequestJournal<'a> {
    epoch: std::sync::Arc<()>,
    dir: std::path::PathBuf,
    journal: Journal,
    snapshot: Vec<u8>,
    poisoned: bool,
    _lock: &'a super::state::Lock,
}
/// Conservative read-only runtime fence. This does not establish process cleanup.
pub(super) fn runtime_collection_fence(
    dir: &std::path::Path,
    enrollment: &str,
    lock: &super::state::Lock,
) -> Result<bool> {
    lock.verify_for(dir)?;
    fn present(path: &std::path::Path) -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err("Request journal state unavailable".into()),
        }
    }
    let pending = dir.join("requests.pending");
    if present(&pending)? {
        return Ok(true);
    }
    if !present(&dir.join("requests.json"))? {
        let pending = present(&pending)?;
        lock.verify_for(dir)?;
        return Ok(pending);
    }
    let journal = RequestJournal::open(dir, enrollment, lock)?;
    if present(&pending)? {
        return Ok(true);
    }
    lock.verify_for(dir)?;
    Ok([&journal.journal.manual, &journal.journal.collection]
        .iter()
        .any(|domain| {
            domain
                .active
                .as_ref()
                .is_some_and(|entry| !active_never_started(entry))
                || domain
                    .last_terminal
                    .as_ref()
                    .is_some_and(|entry| !terminal_never_started(entry))
        }))
}
fn no_start_authority(entry: &Entry) -> bool {
    let empty = match &entry.proof {
        Proof::Manual(proof) => {
            proof.helper.is_none()
                && proof.reader.is_none()
                && proof.observation.is_none()
                && proof.scan.is_none()
        }
        Proof::Collection(proof) => proof.scan.is_none(),
    };
    entry.acknowledged_nonce.is_none()
        && !entry.submitted
        && entry.native_attempt.is_none()
        && entry.report.is_none()
        && entry.previous_no_work.is_none()
        && !entry.no_work_acknowledged
        && entry.attempts == 1
        && empty
}
fn active_never_started(entry: &Entry) -> bool {
    entry.terminal.is_none()
        && entry.pending_status == ClientStatus::Received
        && no_start_authority(entry)
}
fn terminal_never_started(entry: &Entry) -> bool {
    matches!(
        entry.terminal,
        Some(CanonicalStatus::Failed | CanonicalStatus::Expired)
    ) && matches!(
        entry.pending_status,
        ClientStatus::Received | ClientStatus::Failed
    ) && no_start_authority(entry)
}
impl<'a> RequestJournal<'a> {
    pub fn initialize(
        dir: &std::path::Path,
        enrollment: &str,
        seeds: CounterSeeds,
        lock: &super::state::Lock,
    ) -> Result<()> {
        let _access = JOURNAL_ACCESS
            .lock()
            .map_err(|_| "Request journal access uncertain; restart and reconcile")?;
        lock.verify_for(dir)?;
        require(uuid(enrollment) && safe(seeds.helper) && safe(seeds.observation))?;
        let path = dir.join("requests.json");
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err("Existing request journal cannot be reset".into());
        }
        let journal = Journal {
            schema_version: 2,
            enrollment_id: enrollment.into(),
            counters: Counters {
                helper: seeds.helper,
                collection: 0,
                observation: seeds.observation,
            },
            manual: Domain::default(),
            collection: Domain::default(),
        };
        let saved = super::state::atomic(&path, &journal.encode()?);
        let checked = lock.verify_for(dir);
        saved?;
        checked
    }
    pub fn open(
        dir: &std::path::Path,
        enrollment: &str,
        lock: &'a super::state::Lock,
    ) -> Result<Self> {
        let _access = JOURNAL_ACCESS
            .lock()
            .map_err(|_| "Request journal access uncertain; restart and reconcile")?;
        lock.verify_for(dir)?;
        let snapshot = super::state::read(&dir.join("requests.json"), MAX_JOURNAL)?;
        let journal: Journal = serde_json::from_slice(&snapshot)
            .map_err(|_| "Request journal invalid; explicit recovery required")?;
        journal.validate()?;
        require(journal.enrollment_id == enrollment)?;
        lock.verify_for(dir)?;
        Ok(Self {
            dir: dir.to_owned(),
            journal,
            snapshot,
            poisoned: false,
            epoch: std::sync::Arc::new(()),
            _lock: lock,
        })
    }
    fn revoke_native_intents(&mut self) {
        self.epoch = std::sync::Arc::new(());
    }
    fn change<T>(&mut self, apply: impl FnOnce(&mut Journal) -> Result<T>) -> Result<T> {
        self.change_with(apply, super::state::atomic)
    }
    fn change_with<T>(
        &mut self,
        apply: impl FnOnce(&mut Journal) -> Result<T>,
        save: impl FnOnce(&std::path::Path, &[u8]) -> Result<()>,
    ) -> Result<T> {
        // Also protect private compare-and-write entry from future callers.
        self.revoke_native_intents();
        let _access = JOURNAL_ACCESS
            .lock()
            .map_err(|_| "Request journal access uncertain; restart and reconcile")?;
        if self.poisoned {
            return Err("Request journal persistence uncertain; reopen and reconcile".into());
        }
        if self._lock.verify_for(&self.dir).is_err() {
            self.poisoned = true;
            return Err("Request journal lock uncertain".into());
        }
        if !super::state::read(&self.dir.join("requests.json"), MAX_JOURNAL)
            .is_ok_and(|bytes| bytes == self.snapshot)
        {
            self.poisoned = true;
            return Err("Request journal view stale or unavailable; reopen and reconcile".into());
        }
        let mut next = self.journal.clone();
        let result = apply(&mut next)?;
        // Supersession is absorbing across every local mutator, including
        // generic error handling. Only canonical reconciliation may move the
        // unchanged entry into last-terminal metadata.
        for cap in [Capability::Manual, Capability::Collection] {
            if let Some(before) = self.journal.domain(cap).active.as_ref()
                && before.pending_status == ClientStatus::ResultSuperseded
            {
                let domain = next.domain(cap);
                let after = domain
                    .active
                    .as_ref()
                    .into_iter()
                    .chain(domain.last_terminal.as_ref())
                    .find(|entry| entry.delivery.id() == before.delivery.id())
                    .ok_or(
                        "Superseded request cannot be discarded before canonical reconciliation",
                    )?;
                let mut frozen = after.clone();
                frozen.terminal = before.terminal;
                require(
                    serde_json::to_vec(&frozen).map_err(|_| "Cannot encode superseded request")?
                        == serde_json::to_vec(before)
                            .map_err(|_| "Cannot encode superseded request")?,
                )?;
            }
        }
        let bytes = next.encode()?;
        self.poisoned = true;
        let saved = save(&self.dir.join("requests.json"), &bytes);
        let checked = self._lock.verify_for(&self.dir);
        saved?;
        checked?;
        self.journal = next;
        self.snapshot = bytes;
        self.poisoned = false;
        Ok(result)
    }
    pub fn reserve_nonce(&mut self, domain: OperationDomain, suffix: &str) -> Result<String> {
        self.revoke_native_intents();
        self.change(|j| j.counters.reserve(domain, suffix))
    }
    pub fn admit(
        &mut self,
        delivery: Delivery,
        source_revision: u64,
        clock: &Clock,
        suffix: &str,
        session: &Negotiated,
    ) -> Result<Admission> {
        self.revoke_native_intents();
        delivery.validate()?;
        clock.validate()?;
        require(positive(source_revision))?;
        let cap = delivery.capability();
        self.change(|j| {
            let domain = j.domain(cap);
            for entry in [&domain.active, &domain.last_terminal]
                .into_iter()
                .flatten()
            {
                if entry.delivery.id() == delivery.id() {
                    require(
                        serde_json::to_value(&entry.delivery).ok()
                            == serde_json::to_value(&delivery).ok()
                            && entry.source_revision == source_revision,
                    )?;
                    return Ok(if entry.terminal.is_some() {
                        Admission::Terminal
                    } else {
                        Admission::Duplicate
                    });
                }
            }
            if delivery.sequence() <= domain.delivery_highwater {
                return Err("Forgotten delivery cannot repeat work; reconcile enrollment".into());
            }
            if domain.active.is_some() {
                return Err("Previous request awaits canonical reconciliation".into());
            }
            if !session.allows(cap) {
                return Err("Inventory request capability unavailable or paused".into());
            }
            if let Delivery::Collection(d) = &delivery {
                require(d.source_revision == source_revision)?;
            }
            // New admission must not prune the only retained evidence of an
            // older physical operation whose logical request already ended.
            j.historical_collection_safe()?;
            let nonce = j.counters.reserve(
                match cap {
                    Capability::Manual => OperationDomain::Helper,
                    Capability::Collection => OperationDomain::Collection,
                },
                suffix,
            )?;
            let sequence = nonce_sequence(&nonce).ok_or("Invalid operation counter")?;
            let proof = match &delivery {
                Delivery::Manual(d) => {
                    let expiry = utc_millis(&d.expires_at)?;
                    require(expiry > clock.unix_ms)?;
                    let deadline = clock
                        .boottime_ms
                        .checked_add(expiry - clock.unix_ms)
                        .ok_or("Request deadline overflow")?;
                    Proof::Manual(
                        ManualProof {
                            schema_version: 1,
                            operation_nonce: nonce,
                            helper_sequence: sequence,
                            boot_id: clock.boot_id.clone(),
                            accepted_boottime_ms: clock.boottime_ms,
                            deadline_boottime_ms: deadline,
                            helper: None,
                            reader: None,
                            observation: None,
                            scan: None,
                        }
                        .into(),
                    )
                }
                Delivery::Collection(_) => Proof::Collection(CollectionProof {
                    schema_version: 1,
                    operation_nonce: nonce,
                    collection_sequence: sequence,
                    boot_id: clock.boot_id.clone(),
                    accepted_boottime_ms: clock.boottime_ms,
                    scan: None,
                }),
            };
            let domain = j.domain_mut(cap);
            domain.delivery_highwater = delivery.sequence();
            domain.active = Some(Entry {
                delivery,
                source_revision,
                proof,
                previous_no_work: None,
                acknowledged_nonce: None,
                submitted: false,
                native_attempt: None,
                no_work_acknowledged: false,
                pending_status: ClientStatus::Received,
                reason: None,
                report: None,
                terminal: None,
                attempts: 1,
            });
            Ok(Admission::New)
        })
    }
    pub fn pending(&self, cap: Capability) -> Result<Option<StatusMessage>> {
        let _access = JOURNAL_ACCESS
            .lock()
            .map_err(|_| "Request journal access uncertain; restart and reconcile")?;
        self._lock.verify_for(&self.dir)?;
        if !super::state::read(&self.dir.join("requests.json"), MAX_JOURNAL)
            .is_ok_and(|bytes| bytes == self.snapshot)
        {
            return Err("Request journal view stale or unavailable; reopen and reconcile".into());
        }
        if self.poisoned {
            return Err("Request journal persistence uncertain".into());
        }
        self._lock.verify_for(&self.dir)?;
        self.journal
            .domain(cap)
            .active
            .as_ref()
            .or(self.journal.domain(cap).last_terminal.as_ref())
            .map(|e| e.status(&self.journal.enrollment_id))
            .transpose()
    }
    pub fn recover_collection(
        &mut self,
        latest: Option<&RetainedInventory>,
    ) -> Result<CollectionRecovery> {
        self.revoke_native_intents();
        if let Some(latest) = latest {
            require(
                latest.enrollment_id == self.journal.enrollment_id
                    && uuid(&latest.report_id)
                    && positive(latest.sequence)
                    && hex(&latest.sha256, 64),
            )?;
        }
        self.change(|j| {
            // Logical cancellation/source failure is not a native cleanup receipt.
            // Retain the physical-work fence even after canonical terminal state.
            if let Some(last) = j.collection.last_terminal.as_ref()
                && !last.proof.ready()
                && (last.submitted
                    || matches!(
                        last.pending_status,
                        ClientStatus::Running | ClientStatus::Unconfirmed
                    ))
            {
                return Ok(CollectionRecovery::Unfinished);
            }
            let Some(entry) = j.collection.active.as_mut() else {
                return Ok(CollectionRecovery::Idle);
            };
            if entry.pending_status == ClientStatus::ResultSuperseded {
                return Ok(CollectionRecovery::Superseded);
            }
            if let Some(report) = &entry.report {
                if latest.is_some_and(|latest| {
                    latest.report_id == report.id
                        && latest.sequence == report.sequence
                        && latest.sha256 == report.sha256
                }) {
                    return Ok(CollectionRecovery::Ready);
                }
                entry.pending_status = ClientStatus::ResultSuperseded;
                entry.reason = Some("result_superseded".into());
                return Ok(CollectionRecovery::Superseded);
            }
            if entry.submitted
                || matches!(
                    entry.pending_status,
                    ClientStatus::Running | ClientStatus::Unconfirmed
                )
            {
                entry.pending_status = ClientStatus::Unconfirmed;
                entry.reason = Some("unavailable".into());
                return Ok(CollectionRecovery::Unfinished);
            }
            Ok(CollectionRecovery::Waiting)
        })
    }
    pub fn begin(
        &mut self,
        cap: Capability,
        clock: &Clock,
        session: &Negotiated,
    ) -> Result<String> {
        self.revoke_native_intents();
        clock.validate()?;
        self.change(|j| {
            let entry = j
                .domain_mut(cap)
                .active
                .as_mut()
                .ok_or("No active inventory request")?;
            require(
                entry.pending_status == ClientStatus::Received
                    && session.allows(cap)
                    && entry.acknowledged_nonce.as_deref() == Some(entry.proof.nonce())
                    && !entry.submitted
                    && entry.proof.boot() == clock.boot_id
                    && clock.boottime_ms >= entry.proof.accepted(),
            )?;
            if let Proof::Manual(p) = &entry.proof {
                require(clock.boottime_ms <= p.deadline_boottime_ms)?;
            }
            entry.submitted = true;
            if cap == Capability::Collection {
                entry.pending_status = ClientStatus::Running;
            }
            Ok(entry.proof.nonce().into())
        })
    }
    /// Fsync submission and Root nonce before any Root observation request.
    pub fn admit_native_collection(
        &mut self,
        report_id: &str,
        sequence: u64,
        source_revision: u64,
        clock: &Clock,
        suffix: &str,
        session: &Negotiated,
    ) -> Result<NativeCollectionIntent> {
        self.revoke_native_intents();
        clock.validate()?;
        let scan = ScanProof {
            report_id: report_id.into(),
            sequence,
            source_revision,
            started_boottime_ms: clock.boottime_ms,
            finished_boottime_ms: None,
        };
        scan.validate()?;
        let (request_id, operation_nonce, observation_nonce) = self.change(|j| {
            j.collection_only_safe()?;
            let entry = j
                .collection
                .active
                .as_mut()
                .ok_or("No active collection request")?;
            require(
                entry.pending_status == ClientStatus::Received
                    && !entry.submitted
                    && session.allows(Capability::Collection)
                    && entry.acknowledged_nonce.as_deref() == Some(entry.proof.nonce())
                    && entry.source_revision == source_revision
                    && entry.proof.boot() == clock.boot_id
                    && clock.boottime_ms >= entry.proof.accepted(),
            )?;
            require(matches!(&entry.proof, Proof::Collection(p) if p.scan.is_none()))?;
            entry.submitted = true;
            entry.pending_status = ClientStatus::Running;
            let id = entry.delivery.id().to_owned();
            let nonce = entry.proof.nonce().to_owned();
            let observation = j.counters.reserve(OperationDomain::Observation, suffix)?;
            j.collection
                .active
                .as_mut()
                .ok_or("No active collection request")?
                .native_attempt = Some(NativeAttempt {
                observation_nonce: observation.clone(),
                boot_id: clock.boot_id.clone(),
                admitted_boottime_ms: clock.boottime_ms,
                release_requested_boottime_ms: None,
            });
            Ok((id, nonce, observation))
        })?;
        Ok(NativeCollectionIntent {
            epoch: self.epoch.clone(),
            negotiation: session.identity.clone(),
            request_id,
            operation_nonce,
            boot_id: clock.boot_id.clone(),
            admitted_boottime_ms: clock.boottime_ms,
            observation_nonce,
            scan,
        })
    }
    /// Persist cleanup intent for one retained native scope, even after logical
    /// source/canonical failure. This cannot mint observation or scan authority.
    pub fn prepare_native_release(
        &mut self,
        request_id: &str,
        clock: &Clock,
    ) -> Result<NativeReleaseIntent> {
        self.revoke_native_intents();
        clock.validate()?;
        require(uuid(request_id))?;
        let (observation_nonce, boot_id, first_requested_boottime_ms) = self.change(|journal| {
            let entry = journal.retained_collection_mut(request_id)?;
            require(entry.submitted && entry.acknowledged_nonce.is_some() && !entry.proof.ready())?;
            let started = entry.proof.scan().map(|scan| scan.started_boottime_ms);
            let native = entry
                .native_attempt
                .as_mut()
                .ok_or("No native scope to release")?;
            require(
                native.boot_id == clock.boot_id
                    && clock.boottime_ms >= native.admitted_boottime_ms
                    && started.is_none_or(|time| clock.boottime_ms >= time)
                    && native
                        .release_requested_boottime_ms
                        .is_none_or(|time| clock.boottime_ms >= time),
            )?;
            let first = *native
                .release_requested_boottime_ms
                .get_or_insert(clock.boottime_ms);
            Ok((
                native.observation_nonce.clone(),
                native.boot_id.clone(),
                first,
            ))
        })?;
        Ok(NativeReleaseIntent {
            epoch: self.epoch.clone(),
            request_id: request_id.into(),
            observation_nonce,
            boot_id,
            first_requested_boottime_ms,
        })
    }
    /// Trusted bridge MUST select the fixed release port, never observation.
    /// Same bounded publication-only/no-ANY-Journal-reentry contract as OBS.
    /// The frozen time records intent, not Root grant/opening/acceptance.
    pub fn publish_native_release(
        &mut self,
        release: NativeReleaseIntent,
        clock: &Clock,
        publish_release: impl FnOnce(&str) -> Result<()>,
    ) -> Result<()> {
        let prepared_epoch = self.epoch.clone();
        self.revoke_native_intents();
        clock.validate()?;
        require(
            std::sync::Arc::ptr_eq(&prepared_epoch, &release.epoch)
                && release.boot_id == clock.boot_id
                && clock.boottime_ms >= release.first_requested_boottime_ms,
        )?;
        let _access = JOURNAL_ACCESS
            .lock()
            .map_err(|_| "Request journal access uncertain; restart and reconcile")?;
        self.native_snapshot()?;
        let entry = self.journal.retained_collection(&release.request_id)?;
        require(
            entry.submitted
                && !entry.proof.ready()
                && entry.acknowledged_nonce.as_deref() == Some(entry.proof.nonce())
                && entry.native_attempt.as_ref().is_some_and(|native| {
                    native.observation_nonce == release.observation_nonce
                        && native.boot_id == release.boot_id
                        && native.release_requested_boottime_ms
                            == Some(release.first_requested_boottime_ms)
                }),
        )?;
        let published = publish_release(&release.observation_nonce);
        let checked = self.native_snapshot();
        published?;
        checked?;
        Ok(())
    }
    fn native_snapshot(&mut self) -> Result<()> {
        if self.poisoned
            || self._lock.verify_for(&self.dir).is_err()
            || !super::state::read(&self.dir.join("requests.json"), MAX_JOURNAL)
                .is_ok_and(|bytes| bytes == self.snapshot)
            || self._lock.verify_for(&self.dir).is_err()
        {
            self.poisoned = true;
            return Err("Native publication journal unavailable or stale".into());
        }
        Ok(())
    }
    /// The trusted fixed callback does only bounded fsynced nonce publication.
    /// It MUST NOT call ANY RequestJournal/open/pending/read/recovery operation,
    /// even through another handle, or wait for Root lease/scan/receipt: the
    /// global journal mutex and caller's existing process lock remain held.
    pub fn publish_native_observation(
        &mut self,
        mut intent: NativeCollectionIntent,
        clock: &Clock,
        session: &Negotiated,
        publish: impl FnOnce(&str) -> Result<()>,
    ) -> Result<PublishedNativeCollection> {
        let admitted_epoch = self.epoch.clone();
        self.revoke_native_intents();
        native_authority(&intent, &admitted_epoch, clock, session)?;
        let _access = JOURNAL_ACCESS
            .lock()
            .map_err(|_| "Request journal access uncertain; restart and reconcile")?;
        self.native_snapshot()?;
        self.journal.collection_only_safe()?;
        require(
            self.journal
                .collection
                .active
                .as_ref()
                .is_some_and(|entry| entry.matches_native_intent(&intent)),
        )?;
        let published = publish(&intent.observation_nonce);
        // Also detect out-of-band/callback-side state replacement, not merely
        // cooperative mutex writers. Never roll back a possibly visible effect.
        let checked = self.native_snapshot();
        published?;
        checked?;
        intent.epoch = self.epoch.clone();
        Ok(PublishedNativeCollection { intent })
    }
    /// Consume same-run authority only after the adapter admits Root's opened
    /// lease. The supplied native clock becomes the actual scan start before reads.
    pub fn attach_native_scan(
        &mut self,
        published: PublishedNativeCollection,
        clock: &Clock,
        session: &Negotiated,
    ) -> Result<CollectionProof> {
        let admitted_epoch = self.epoch.clone();
        self.revoke_native_intents();
        let intent = published.intent;
        native_authority(&intent, &admitted_epoch, clock, session)?;
        self.change(|j| {
            j.collection_only_safe()?;
            let entry = j
                .collection
                .active
                .as_mut()
                .ok_or("No active collection request")?;
            require(entry.matches_native_intent(&intent))?;
            let Proof::Collection(mut proof) = entry.proof.clone() else {
                return Err("Invalid native collection proof".into());
            };
            require(proof.scan.is_none())?;
            let mut scan = intent.scan;
            scan.started_boottime_ms = clock.boottime_ms;
            proof.scan = Some(scan);
            proof.validate()?;
            entry.proof = entry.proof.merge(&Proof::Collection(proof.clone()))?;
            Ok(proof)
        })
    }
    /// Notice intentional replacement before discarding the single retained body.
    pub fn before_daily_collection(&mut self) -> Result<()> {
        self.revoke_native_intents();
        self.change(|j| {
            // Manual work needs the verified helper/cleanup adapter before this
            // collection-only lifecycle can safely replace its retained evidence.
            j.collection_only_safe()?;
            if let Some(entry) = j.collection.active.as_mut() {
                if entry.report.is_some() && entry.proof.ready() {
                    entry.pending_status = ClientStatus::ResultSuperseded;
                    entry.reason = Some("result_superseded".into());
                } else {
                    require(
                        !entry.submitted
                            && !matches!(
                                entry.pending_status,
                                ClientStatus::Running | ClientStatus::Unconfirmed
                            ),
                    )?;
                }
            }
            Ok(())
        })
    }
    /// Atomically freeze a requested scan before any native process may start.
    pub fn start_collection(
        &mut self,
        report_id: &str,
        sequence: u64,
        source_revision: u64,
        clock: &Clock,
        session: &Negotiated,
    ) -> Result<CollectionProof> {
        self.revoke_native_intents();
        clock.validate()?;
        self.change(|j| {
            j.collection_only_safe()?;
            let entry = j
                .collection
                .active
                .as_mut()
                .ok_or("No active collection request")?;
            require(
                entry.pending_status == ClientStatus::Received
                    && !entry.submitted
                    && session.allows(Capability::Collection)
                    && entry.acknowledged_nonce.as_deref() == Some(entry.proof.nonce())
                    && entry.source_revision == source_revision
                    && entry.proof.boot() == clock.boot_id
                    && clock.boottime_ms >= entry.proof.accepted(),
            )?;
            let Proof::Collection(mut proof) = entry.proof.clone() else {
                return Err("Invalid collection proof".into());
            };
            proof.scan = Some(ScanProof {
                report_id: report_id.into(),
                sequence,
                source_revision,
                started_boottime_ms: clock.boottime_ms,
                finished_boottime_ms: None,
            });
            proof.validate()?;
            entry.proof = entry.proof.merge(&Proof::Collection(proof.clone()))?;
            entry.submitted = true;
            entry.pending_status = ClientStatus::Running;
            Ok(proof)
        })
    }
    pub fn progress(
        &mut self,
        cap: Capability,
        proof: &Proof,
        safe_reason: Option<&str>,
    ) -> Result<()> {
        self.revoke_native_intents();
        proof.validate()?;
        require(proof.capability() == cap)?;
        let safe_reason = safe_reason.map(str::to_owned);
        require(reason(&safe_reason))?;
        self.change(|j| {
            let entry = j
                .domain_mut(cap)
                .active
                .as_mut()
                .ok_or("No active inventory request")?;
            require(entry.submitted)?;
            require(entry.pending_status != ClientStatus::ResultSuperseded)?;
            // Native first-scan admission belongs exclusively to the consumed
            // published token. Generic proof merging cannot create that phase.
            require(
                entry.native_attempt.is_none()
                    || entry.proof.scan().is_some()
                    || proof.scan().is_none(),
            )?;
            let merged = entry.proof.merge(proof)?;
            require(cap != Capability::Collection || !merged.ready() || entry.report.is_some())?;
            entry.proof = merged;
            if let Proof::Manual(p) = &entry.proof {
                if p.no_work() {
                    require(safe_reason.is_some())?;
                    entry.pending_status = ClientStatus::Deferred;
                    entry.reason = safe_reason.clone();
                } else if p.helper.as_ref().is_some_and(|h| {
                    matches!(
                        h.result,
                        Some(HelperResult::Failed | HelperResult::Unconfirmed)
                    )
                }) {
                    require(safe_reason.is_some())?;
                    entry.pending_status = if p
                        .helper
                        .as_ref()
                        .is_some_and(|h| h.result == Some(HelperResult::Failed))
                    {
                        ClientStatus::Failed
                    } else {
                        ClientStatus::Unconfirmed
                    };
                    entry.reason = safe_reason.clone();
                } else if p
                    .helper
                    .as_ref()
                    .is_some_and(|h| h.started_boottime_ms.is_some())
                {
                    entry.pending_status = ClientStatus::Running;
                    entry.reason = None;
                }
            }
            Ok(())
        })
    }
    /// Persist finished proof and exact report binding in one journal commit.
    pub fn bind_ready_report(
        &mut self,
        cap: Capability,
        proof: &Proof,
        id: &str,
        sequence: u64,
        sha256: &str,
    ) -> Result<()> {
        self.revoke_native_intents();
        proof.validate()?;
        require(proof.capability() == cap)?;
        require(uuid(id) && positive(sequence) && hex(sha256, 64))?;
        self.change(|j| {
            let entry = j
                .domain_mut(cap)
                .active
                .as_mut()
                .ok_or("No active inventory request")?;
            require(
                entry.native_attempt.is_none()
                    || entry.proof.scan().is_some()
                    || proof.scan().is_none(),
            )?;
            let merged = entry.proof.merge(proof)?;
            require(
                entry.submitted
                    && entry.pending_status != ClientStatus::ResultSuperseded
                    && merged.ready()
                    && merged.scan().is_some_and(|s| {
                        s.report_id == id
                            && s.sequence == sequence
                            && s.source_revision == entry.source_revision
                    }),
            )?;
            if let Some(old) = &entry.report {
                require(old.id == id && old.sequence == sequence && old.sha256 == sha256)?;
            }
            entry.proof = merged;
            entry.report = Some(ReportRef {
                id: id.into(),
                sequence,
                sha256: sha256.into(),
            });
            entry.pending_status = ClientStatus::Running;
            entry.reason = None;
            Ok(())
        })
    }
    pub fn fail(&mut self, cap: Capability, safe_reason: &str) -> Result<()> {
        self.revoke_native_intents();
        let safe_reason = Some(safe_reason.to_owned());
        require(reason(&safe_reason))?;
        self.change(|j| {
            let entry = j
                .domain_mut(cap)
                .active
                .as_mut()
                .ok_or("No active inventory request")?;
            entry.pending_status = ClientStatus::Failed;
            entry.reason = safe_reason;
            Ok(())
        })
    }
    pub fn unconfirmed(&mut self, cap: Capability) -> Result<()> {
        self.revoke_native_intents();
        self.change(|j| {
            let entry = j
                .domain_mut(cap)
                .active
                .as_mut()
                .ok_or("No active inventory request")?;
            require(entry.submitted)?;
            entry.pending_status = ClientStatus::Unconfirmed;
            entry.reason = Some("unavailable".into());
            Ok(())
        })
    }
    pub fn superseded(&mut self, cap: Capability, id: &str, hash: &str) -> Result<()> {
        self.revoke_native_intents();
        self.change(|j| {
            let entry = j
                .domain_mut(cap)
                .active
                .as_mut()
                .ok_or("No active inventory request")?;
            require(
                entry
                    .report
                    .as_ref()
                    .is_some_and(|r| r.id == id && r.sha256 == hash),
            )?;
            entry.pending_status = ClientStatus::ResultSuperseded;
            entry.reason = Some("result_superseded".into());
            Ok(())
        })
    }
    pub fn retry_no_work(
        &mut self,
        clock: &Clock,
        suffix: &str,
        session: &Negotiated,
    ) -> Result<()> {
        self.revoke_native_intents();
        clock.validate()?;
        self.change(|j| {
            let entry = j.manual.active.as_ref().ok_or("No active manual request")?;
            let Proof::Manual(old) = &entry.proof else {
                return Err("Manual proof required".into());
            };
            require(
                session.allows(Capability::Manual)
                    && old.no_work()
                    && entry.no_work_acknowledged
                    && entry.report.is_none()
                    && entry.attempts < 512,
            )?;
            let Delivery::Manual(delivery) = &entry.delivery else {
                return Err("Manual delivery required".into());
            };
            let deadline = if clock.boot_id == old.boot_id {
                require(
                    clock.boottime_ms
                        >= old
                            .helper
                            .as_ref()
                            .and_then(|h| h.finished_boottime_ms)
                            .ok_or("No terminal no-work result")?,
                )?;
                old.deadline_boottime_ms
            } else {
                let expiry = utc_millis(&delivery.expires_at)?;
                require(expiry > clock.unix_ms)?;
                clock
                    .boottime_ms
                    .checked_add(expiry - clock.unix_ms)
                    .ok_or("Request deadline overflow")?
            };
            require(clock.boottime_ms <= deadline)?;
            let nonce = j.counters.reserve(OperationDomain::Helper, suffix)?;
            let entry = j.manual.active.as_mut().ok_or("No active manual request")?;
            let Proof::Manual(old) = &entry.proof else {
                return Err("Manual proof required".into());
            };
            entry.previous_no_work = Some(old.as_ref().clone());
            entry.proof = Proof::Manual(
                ManualProof {
                    schema_version: 1,
                    helper_sequence: nonce_sequence(&nonce).ok_or("Invalid operation nonce")?,
                    operation_nonce: nonce,
                    boot_id: clock.boot_id.clone(),
                    accepted_boottime_ms: clock.boottime_ms,
                    deadline_boottime_ms: deadline,
                    helper: None,
                    reader: None,
                    observation: None,
                    scan: None,
                }
                .into(),
            );
            entry.acknowledged_nonce = None;
            entry.submitted = false;
            entry.no_work_acknowledged = false;
            entry.pending_status = ClientStatus::Received;
            entry.reason = None;
            entry.attempts += 1;
            Ok(())
        })
    }
    pub fn canonical(&mut self, cap: Capability, response: &Canonical) -> Result<()> {
        self.revoke_native_intents();
        response.validate()?;
        self.change(|j| {
            let enrollment = j.enrollment_id.clone();
            let domain = j.domain_mut(cap);
            let r = &response.request;
            let active = domain
                .active
                .as_ref()
                .is_some_and(|e| e.delivery.id() == r.request_id);
            let entry = if active {
                domain.active.as_mut()
            } else {
                domain
                    .last_terminal
                    .as_mut()
                    .filter(|e| e.delivery.id() == r.request_id)
            }
            .ok_or("Canonical response has no matching local request")?;
            require(entry.delivery.sequence() == r.delivery_sequence)?;
            if let Some(nonce) = &r.operation_nonce {
                require(nonce == entry.proof.nonce())?;
            }
            if let Some(id) = &r.report_id {
                require(
                    entry.report.as_ref().is_some_and(|p| {
                        &p.id == id && Some(&p.sha256) == r.report_sha256.as_ref()
                    }),
                )?;
            }
            if let Some(receipt) = &response.receipt {
                require(
                    receipt.enrollment_id == enrollment
                        && entry.report.as_ref().is_some_and(|p| {
                            p.id == receipt.report_id
                                && p.sequence == receipt.sequence
                                && p.sha256 == receipt.sha256
                        }),
                )?;
            }
            if let Some(terminal) = entry.terminal {
                require(!r.status.terminal() || terminal == r.status)?;
                return Ok(());
            }
            if r.status == CanonicalStatus::Complete {
                require(
                    r.report_id.is_some()
                        && response
                            .receipt
                            .as_ref()
                            .is_some_and(|receipt| receipt.disposition != "history")
                        && r.operation_nonce.as_deref() == Some(entry.proof.nonce())
                        && (cap != Capability::Collection
                            || response
                                .receipt
                                .as_ref()
                                .is_some_and(|receipt| receipt.disposition == "current")),
                )?;
            }
            if r.status.terminal() {
                entry.terminal = Some(r.status);
                let terminal = domain
                    .active
                    .take()
                    .ok_or("Terminal response did not match active request")?;
                domain.last_terminal = Some(terminal);
            } else if r.operation_nonce.as_deref() == Some(entry.proof.nonce()) {
                if r.status == CanonicalStatus::Delivered
                    && entry.pending_status == ClientStatus::Received
                    && !entry.submitted
                {
                    entry.acknowledged_nonce = r.operation_nonce.clone();
                }
                if matches!(
                    r.status,
                    CanonicalStatus::Running | CanonicalStatus::Unconfirmed
                ) && !entry.submitted
                    && entry.pending_status == ClientStatus::Received
                {
                    // The controller may know work that this local view cannot
                    // prove. A later stale Delivered response cannot erase it.
                    entry.pending_status = ClientStatus::Unconfirmed;
                    entry.reason = Some("unavailable".into());
                }
                if r.status == CanonicalStatus::Deferred
                    && matches!(&entry.proof,Proof::Manual(p) if p.no_work())
                {
                    entry.no_work_acknowledged = true;
                }
            }
            Ok(())
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journal_rejects_lock_from_another_directory() {
        let first = Fixture::new();
        let other = Fixture::new();
        assert!(RequestJournal::open(&first.dir, BOOT, &other.lock).is_err());
    }
    #[test]
    #[cfg(unix)]
    fn replaced_lock_blocks_journal_mutation_even_if_restored() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
        let path = fixture.dir.join("running.lock");
        std::fs::rename(&path, fixture.dir.join("old.lock")).unwrap();
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            journal
                .reserve_nonce(OperationDomain::Helper, "aaaaaaaaaaaaaaaa")
                .is_err()
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(fixture.dir.join("old.lock"), &path).unwrap();
        assert!(
            journal
                .reserve_nonce(OperationDomain::Helper, "bbbbbbbbbbbbbbbb")
                .is_err()
        );
        assert_eq!(
            std::fs::read(fixture.dir.join("requests.json")).unwrap(),
            before
        );
    }
    #[test]
    #[cfg(unix)]
    fn publication_error_still_poisons_replaced_lock_for_all_handles() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
        let path = fixture.dir.join("running.lock");
        assert!(
            journal
                .publish_native_observation(intent, &clock(1002), &session, |_| {
                    std::fs::rename(&path, fixture.dir.join("old.lock")).unwrap();
                    std::fs::write(&path, b"").unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    Err("synthetic publication uncertainty".into())
                })
                .is_err()
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(fixture.dir.join("old.lock"), &path).unwrap();
        assert!(RequestJournal::open(&fixture.dir, BOOT, &fixture.lock).is_err());
        assert_eq!(
            std::fs::read(fixture.dir.join("requests.json")).unwrap(),
            before
        );
    }
    #[test]
    #[cfg(unix)]
    fn replaced_lock_prevents_native_publication_callback() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let path = fixture.dir.join("running.lock");
        std::fs::rename(&path, fixture.dir.join("old.lock")).unwrap();
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut called = false;
        assert!(
            journal
                .publish_native_observation(intent, &clock(1002), &session, |_| {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!called);
    }
    #[test]
    #[cfg(unix)]
    fn lock_replacement_after_journal_fsync_returns_uncertain_and_poisons() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let path = fixture.dir.join("running.lock");
        let result = journal.change_with(
            |j| {
                j.counters
                    .reserve(OperationDomain::Helper, "aaaaaaaaaaaaaaaa")
            },
            |destination, bytes| {
                super::super::state::atomic(destination, bytes)?;
                std::fs::rename(&path, fixture.dir.join("old.lock")).unwrap();
                std::fs::write(&path, b"").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                Ok(())
            },
        );
        assert!(result.is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(fixture.dir.join("old.lock"), &path).unwrap();
        assert!(RequestJournal::open(&fixture.dir, BOOT, &fixture.lock).is_err());
    }
    #[test]
    fn runtime_fence_preserves_empty_and_unfinished_journals() {
        let fixture = Fixture::new();
        let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
        assert!(!runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
        assert_eq!(
            std::fs::read(fixture.dir.join("requests.json")).unwrap(),
            before
        );
        let mut journal = fixture.open();
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
            .unwrap();
        let status = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&status, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
        assert!(runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
        assert_eq!(
            std::fs::read(fixture.dir.join("requests.json")).unwrap(),
            before
        );
    }
    #[test]
    fn runtime_fence_rejects_pending_and_invalid_state_without_repair() {
        let fixture = Fixture::new();
        let journal = fixture.dir.join("requests.json");
        std::fs::remove_file(&journal).unwrap();
        assert!(!runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
        let pending = fixture.dir.join("requests.pending");
        std::os::unix::fs::symlink("missing", &pending).unwrap();
        assert!(runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
        assert!(
            std::fs::symlink_metadata(&pending)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(&pending).unwrap();
        RequestJournal::initialize(
            &fixture.dir,
            BOOT,
            CounterSeeds {
                helper: 5,
                observation: 7,
            },
            &fixture.lock,
        )
        .unwrap();
        std::fs::write(&pending, b"pending").unwrap();
        assert!(runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
        assert_eq!(std::fs::read(&pending).unwrap(), b"pending");
        std::fs::remove_file(&pending).unwrap();
        assert!(
            runtime_collection_fence(
                &fixture.dir,
                "00000000-0000-4000-8000-000000000099",
                &fixture.lock
            )
            .is_err()
        );
        std::fs::write(&journal, b"invalid").unwrap();
        assert!(runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).is_err());
        assert_eq!(std::fs::read(journal).unwrap(), b"invalid");
    }
    #[test]
    fn runtime_fence_rejects_dangling_journal_and_unsafe_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let path = fixture.dir.join("requests.json");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).is_err());
        assert!(
            std::fs::symlink_metadata(path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    #[test]
    fn runtime_fence_retains_active_and_terminal_in_both_domains() {
        for cap in [Capability::Manual, Capability::Collection] {
            let fixture = Fixture::new();
            let mut journal = fixture.open();
            let delivery = if cap == Capability::Manual {
                manual_delivery(1)
            } else {
                delivery(1)
            };
            journal
                .admit(delivery, 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
                .unwrap();
            assert!(!runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
            let status = journal.pending(cap).unwrap().unwrap();
            journal
                .canonical(cap, &canonical(&status, CanonicalStatus::Failed, None))
                .unwrap();
            let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
            assert!(!runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
            assert_eq!(
                std::fs::read(fixture.dir.join("requests.json")).unwrap(),
                before
            );
        }
    }
    #[test]
    fn terminal_release_rejects_all_start_authority_and_work_markers() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(
                manual_delivery(1),
                1,
                &clock(1000),
                "aaaaaaaaaaaaaaaa",
                &session(),
            )
            .unwrap();
        let status = journal.pending(Capability::Manual).unwrap().unwrap();
        journal
            .canonical(
                Capability::Manual,
                &canonical(&status, CanonicalStatus::Failed, None),
            )
            .unwrap();
        let base = journal
            .journal
            .manual
            .last_terminal
            .as_ref()
            .unwrap()
            .clone();
        assert!(terminal_never_started(&base));
        let mut bad = Vec::new();
        let mut value = base.clone();
        value.acknowledged_nonce = Some(base.proof.nonce().into());
        bad.push(value);
        let mut value = base.clone();
        value.submitted = true;
        bad.push(value);
        let mut value = base.clone();
        value.no_work_acknowledged = true;
        bad.push(value);
        let mut value = base.clone();
        value.attempts = 2;
        bad.push(value);
        let mut value = base.clone();
        value.previous_no_work = Some(manual_ready(1, 1000, 100000));
        bad.push(value);
        let mut value = base.clone();
        value.report = Some(ReportRef {
            id: REPORT.into(),
            sequence: 1,
            sha256: "c".repeat(64),
        });
        bad.push(value);
        let mut value = base.clone();
        value.terminal = Some(CanonicalStatus::Complete);
        bad.push(value);
        let mut value = base.clone();
        value.pending_status = ClientStatus::Unconfirmed;
        bad.push(value);
        let mut value = base.clone();
        value.native_attempt = Some(NativeAttempt {
            observation_nonce: "0000000000000001aaaaaaaaaaaaaaaa".into(),
            boot_id: BOOT.into(),
            admitted_boottime_ms: 1001,
            release_requested_boottime_ms: None,
        });
        bad.push(value);
        let full = manual_ready(1, 1000, 100000);
        for field in 0..4 {
            let mut value = base.clone();
            let Proof::Manual(proof) = &mut value.proof else {
                panic!("manual proof expected")
            };
            match field {
                0 => proof.helper = full.helper.clone(),
                1 => proof.reader = full.reader.clone(),
                2 => proof.observation = full.observation.clone(),
                _ => proof.scan = full.scan.clone(),
            }
            bad.push(value);
        }
        assert!(bad.iter().all(|entry| !terminal_never_started(entry)));
    }
    #[test]
    fn safe_terminal_does_not_hide_acknowledged_work_in_other_domain() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(
                manual_delivery(1),
                1,
                &clock(1000),
                "aaaaaaaaaaaaaaaa",
                &session(),
            )
            .unwrap();
        let manual = journal.pending(Capability::Manual).unwrap().unwrap();
        journal
            .canonical(
                Capability::Manual,
                &canonical(&manual, CanonicalStatus::Failed, None),
            )
            .unwrap();
        journal
            .admit(delivery(1), 1, &clock(1000), "bbbbbbbbbbbbbbbb", &session())
            .unwrap();
        let collection = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&collection, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&collection, CanonicalStatus::Failed, None),
            )
            .unwrap();
        let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
        assert!(runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
        assert_eq!(
            std::fs::read(fixture.dir.join("requests.json")).unwrap(),
            before
        );
    }
    #[test]
    fn unacknowledged_active_delivery_remains_startable_only_after_durable_ack() {
        for cap in [Capability::Manual, Capability::Collection] {
            let fixture = Fixture::new();
            let mut journal = fixture.open();
            let delivery = if cap == Capability::Manual {
                manual_delivery(1)
            } else {
                delivery(1)
            };
            journal
                .admit(delivery, 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
                .unwrap();
            assert!(journal.begin(cap, &clock(1001), &session()).is_err());
            let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
            assert!(!runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
            assert_eq!(
                std::fs::read(fixture.dir.join("requests.json")).unwrap(),
                before
            );
            drop(journal);
            let mut journal = fixture.open();
            assert!(!runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
            assert!(journal.begin(cap, &clock(1001), &session()).is_err());
            let pending = journal.pending(cap).unwrap().unwrap();
            journal
                .canonical(cap, &canonical(&pending, CanonicalStatus::Delivered, None))
                .unwrap();
            assert!(runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
            drop(journal);
            let mut reopened = fixture.open();
            assert!(runtime_collection_fence(&fixture.dir, BOOT, &fixture.lock).unwrap());
            assert!(reopened.begin(cap, &clock(1001), &session()).is_ok());
        }
    }
    fn native_without_attached_scan<'a>(
        fixture: &'a Fixture,
        session: &Negotiated,
        stage: u8,
    ) -> RequestJournal<'a> {
        let mut journal = native_ready(fixture, session);
        let work = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", session)
            .unwrap();
        if stage == 1 {
            drop(published_test(&mut journal, session, work));
        } else {
            drop(work);
        }
        if stage == 2 {
            drop(
                journal
                    .prepare_native_release(delivery(1).id(), &clock(1010))
                    .unwrap(),
            );
        }
        journal
    }
    #[test]
    fn generic_progress_cannot_attach_first_native_scan_in_any_publication_phase() {
        for stage in 0..3 {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_without_attached_scan(&fixture, &session, stage);
            let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
            let mut proof = collection_proof();
            proof.scan = Some(ScanProof {
                report_id: REPORT.into(),
                sequence: 1,
                source_revision: 1,
                started_boottime_ms: 1005,
                finished_boottime_ms: None,
            });
            assert!(
                journal
                    .progress(Capability::Collection, &Proof::Collection(proof), None)
                    .is_err(),
                "stage {stage}"
            );
            assert_eq!(
                std::fs::read(fixture.dir.join("requests.json")).unwrap(),
                before
            );
        }
    }
    #[test]
    fn generic_report_binding_cannot_create_a_native_scan_or_ready_report() {
        for stage in 0..3 {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_without_attached_scan(&fixture, &session, stage);
            let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
            let mut proof = collection_proof();
            proof.scan = Some(ScanProof {
                report_id: REPORT.into(),
                sequence: 1,
                source_revision: 1,
                started_boottime_ms: 1005,
                finished_boottime_ms: Some(1006),
            });
            assert!(
                journal
                    .bind_ready_report(
                        Capability::Collection,
                        &Proof::Collection(proof),
                        REPORT,
                        1,
                        &"c".repeat(64)
                    )
                    .is_err(),
                "stage {stage}"
            );
            assert_eq!(
                std::fs::read(fixture.dir.join("requests.json")).unwrap(),
                before
            );
        }
    }
    #[test]
    fn repeated_native_release_preserves_first_time_and_rejects_rewind_or_old_token() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        drop(
            journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap(),
        );
        let first = journal
            .prepare_native_release(delivery(1).id(), &clock(1010))
            .unwrap();
        assert!(
            journal
                .prepare_native_release(delivery(1).id(), &clock(1005))
                .is_err()
        );
        let mut called = false;
        assert!(
            journal
                .publish_native_release(first, &clock(1011), |_| {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!called);
        let next = journal
            .prepare_native_release(delivery(1).id(), &clock(1015))
            .unwrap();
        journal
            .publish_native_release(next, &clock(1016), |_| Ok(()))
            .unwrap();
        let saved: Value =
            serde_json::from_slice(&std::fs::read(fixture.dir.join("requests.json")).unwrap())
                .unwrap();
        assert_eq!(
            saved["collection"]["active"]["native_attempt"]["release_requested_boottime_ms"],
            1010
        );
        assert_eq!(saved["counters"]["observation"], 8);
    }
    #[test]
    fn canonical_failed_restart_can_prepare_only_its_cleanup_not_observation() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let work = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let pending = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&pending, CanonicalStatus::Failed, None),
            )
            .unwrap();
        let mut reopened = fixture.open();
        let release = reopened
            .prepare_native_release(delivery(1).id(), &clock(1010))
            .unwrap();
        let mut work_called = false;
        assert!(
            reopened
                .publish_native_observation(work, &clock(1011), &session, |_| {
                    work_called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!work_called);
        // Rejected work publication revokes that cleanup token too; prepare a
        // new cleanup-only token without allocating or restarting an observation.
        assert!(
            reopened
                .publish_native_release(release, &clock(1012), |_| Ok(()))
                .is_err()
        );
        let release = reopened
            .prepare_native_release(delivery(1).id(), &clock(1013))
            .unwrap();
        reopened
            .publish_native_release(release, &clock(1014), |_| Ok(()))
            .unwrap();
        assert_eq!(
            reopened.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
        assert!(
            reopened
                .start_collection(REPORT, 2, 1, &clock(1015), &session)
                .is_err()
        );
    }
    #[test]
    fn native_release_preparation_revokes_published_work_before_any_scan() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let work = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let published = published_test(&mut journal, &session, work);
        let release = journal
            .prepare_native_release(delivery(1).id(), &clock(1010))
            .unwrap();
        assert!(
            journal
                .attach_native_scan(published, &clock(1011), &session)
                .is_err()
        );
        assert!(
            journal
                .publish_native_release(release, &clock(1012), |_| Ok(()))
                .is_err()
        );
        assert_eq!(
            journal.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
    }
    #[test]
    fn native_release_rejects_foreign_plain_ready_and_nonmonotonic_scopes() {
        for action in 0..5 {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_ready(&fixture, &session);
            if action == 1 {
                journal
                    .start_collection(REPORT, 1, 1, &clock(1001), &session)
                    .unwrap();
            } else {
                let work = journal
                    .admit_native_collection(
                        REPORT,
                        1,
                        1,
                        &clock(1001),
                        "bbbbbbbbbbbbbbbb",
                        &session,
                    )
                    .unwrap();
                if action == 2 {
                    let published = published_test(&mut journal, &session, work);
                    let mut proof = journal
                        .attach_native_scan(published, &clock(1010), &session)
                        .unwrap();
                    proof.scan.as_mut().unwrap().finished_boottime_ms = Some(1020);
                    journal
                        .bind_ready_report(
                            Capability::Collection,
                            &Proof::Collection(proof),
                            REPORT,
                            1,
                            &"c".repeat(64),
                        )
                        .unwrap();
                }
            }
            let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
            let mut now = clock(1030);
            if action == 3 {
                now.boot_id = "00000000-0000-4000-8000-000000000099".into();
            }
            if action == 4 {
                now.boottime_ms = 1000;
            }
            let id = if action == 0 {
                REPORT.to_owned()
            } else {
                delivery(1).id().to_owned()
            };
            assert!(
                journal.prepare_native_release(&id, &now).is_err(),
                "action {action}"
            );
            assert_eq!(
                std::fs::read(fixture.dir.join("requests.json")).unwrap(),
                before
            );
        }
    }
    #[test]
    fn stale_native_release_never_calls_fixed_sender() {
        for action in 0..5 {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_ready(&fixture, &session);
            drop(
                journal
                    .admit_native_collection(
                        REPORT,
                        1,
                        1,
                        &clock(1001),
                        "bbbbbbbbbbbbbbbb",
                        &session,
                    )
                    .unwrap(),
            );
            let release = journal
                .prepare_native_release(delivery(1).id(), &clock(1010))
                .unwrap();
            let mut now = clock(1020);
            match action {
                0 => {
                    journal
                        .reserve_nonce(OperationDomain::Observation, "cccccccccccccccc")
                        .unwrap();
                }
                1 => {
                    fixture
                        .open()
                        .reserve_nonce(OperationDomain::Observation, "cccccccccccccccc")
                        .unwrap();
                }
                2 => now.boot_id = "00000000-0000-4000-8000-000000000099".into(),
                3 => now.boottime_ms = 1009,
                _ => {
                    journal
                        .journal
                        .collection
                        .active
                        .as_mut()
                        .unwrap()
                        .native_attempt
                        .as_mut()
                        .unwrap()
                        .release_requested_boottime_ms = Some(1011)
                }
            }
            let mut called = false;
            assert!(
                journal
                    .publish_native_release(release, &now, |_| {
                        called = true;
                        Ok(())
                    })
                    .is_err()
            );
            assert!(!called, "action {action}");
        }
    }
    #[test]
    fn uncertain_or_out_of_band_release_sender_cannot_clear_physical_fence() {
        for changed in [false, true] {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_ready(&fixture, &session);
            drop(
                journal
                    .admit_native_collection(
                        REPORT,
                        1,
                        1,
                        &clock(1001),
                        "bbbbbbbbbbbbbbbb",
                        &session,
                    )
                    .unwrap(),
            );
            let release = journal
                .prepare_native_release(delivery(1).id(), &clock(1010))
                .unwrap();
            let path = fixture.dir.join("requests.json");
            let mut bytes = std::fs::read(&path).unwrap();
            assert!(
                journal
                    .publish_native_release(release, &clock(1011), |_| {
                        if changed {
                            bytes.push(b'\n');
                            std::fs::write(&path, &bytes).unwrap();
                            Ok(())
                        } else {
                            Err("Synthetic uncertain release".into())
                        }
                    })
                    .is_err()
            );
            if changed {
                assert!(journal.pending(Capability::Collection).is_err());
            }
            let mut reopened = fixture.open();
            assert_eq!(
                reopened.recover_collection(None).unwrap(),
                CollectionRecovery::Unfinished
            );
        }
    }
    #[test]
    fn native_release_intent_is_durable_before_fixed_sender_and_never_clears_work() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        drop(
            journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap(),
        );
        let path = fixture.dir.join("requests.json");
        let before: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let release = journal
            .prepare_native_release(delivery(1).id(), &clock(1005))
            .unwrap();
        assert_eq!(
            release.observation_nonce(),
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        let mut called = false;
        journal.publish_native_release(release, &clock(1006), |nonce| {
            called = true;
            let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved["collection"]["active"]["native_attempt"]["release_requested_boottime_ms"], 1005);
            assert_eq!(saved["counters"], before["counters"]);
            assert_eq!(nonce, "0000000000000008bbbbbbbbbbbbbbbb");
            Ok(())
        }).unwrap();
        assert!(called);
        assert_eq!(
            journal.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
        assert!(
            journal
                .admit_native_collection(REPORT, 2, 1, &clock(1010), "cccccccccccccccc", &session)
                .is_err()
        );
    }
    #[test]
    fn native_publication_rejects_stale_scope_before_calling_sender() {
        for action in 0..6 {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_ready(&fixture, &session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let mut now = clock(1002);
            let mut current = session.clone();
            match action {
                0 => {
                    journal
                        .reserve_nonce(OperationDomain::Observation, "cccccccccccccccc")
                        .unwrap();
                }
                1 => {
                    current =
                        Negotiated::new(&[Capability::Collection], &[Capability::Collection], true)
                            .unwrap()
                }
                2 => {
                    fixture
                        .open()
                        .reserve_nonce(OperationDomain::Observation, "cccccccccccccccc")
                        .unwrap();
                }
                3 => now.boot_id = "00000000-0000-4000-8000-000000000099".into(),
                4 => now.boottime_ms = 1000,
                _ => {
                    journal
                        .journal
                        .collection
                        .active
                        .as_mut()
                        .unwrap()
                        .native_attempt
                        .as_mut()
                        .unwrap()
                        .observation_nonce = "0000000000000008dddddddddddddddd".into()
                }
            }
            let mut called = false;
            assert!(
                journal
                    .publish_native_observation(intent, &now, &current, |_| {
                        called = true;
                        Ok(())
                    })
                    .is_err()
            );
            assert!(!called, "action {action}");
        }
    }
    #[test]
    fn failed_native_sender_keeps_scope_unfinished_without_replay_authority() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
        let marker = fixture.dir.join("synthetic-visible-request");
        assert!(
            journal
                .publish_native_observation(intent, &clock(1002), &session, |nonce| {
                    std::fs::write(&marker, nonce).unwrap();
                    Err("Synthetic publication uncertain".into())
                })
                .is_err()
        );
        assert_eq!(
            std::fs::read(fixture.dir.join("requests.json")).unwrap(),
            before
        );
        assert_eq!(
            std::fs::read_to_string(marker).unwrap(),
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            journal.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
        assert!(
            journal
                .admit_native_collection(REPORT, 1, 1, &clock(1010), "cccccccccccccccc", &session)
                .is_err()
        );
    }
    #[test]
    fn native_sender_out_of_band_journal_change_cannot_mint_published_token() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let path = fixture.dir.join("requests.json");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(b'\n');
        assert!(
            journal
                .publish_native_observation(intent, &clock(1002), &session, |_| {
                    std::fs::write(&path, &bytes).unwrap();
                    Ok(())
                })
                .is_err()
        );
        assert!(journal.pending(Capability::Collection).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    #[test]
    fn native_sender_panic_retains_scope_and_poison_is_fail_closed() {
        const FLAG: &str = "GUARDED_UPDATE_TEST_PUBLICATION_PANIC";
        if std::env::var_os(FLAG).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "inventory::requests::tests::native_sender_panic_retains_scope_and_poison_is_fail_closed"])
                .env(FLAG, "1").output().unwrap();
            assert!(
                output.status.success(),
                "Isolated panic verification failed"
            );
            return;
        }
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let path = fixture.dir.join("requests.json");
        let before = std::fs::read(&path).unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = journal.publish_native_observation(intent, &clock(1002), &session, |_| {
                panic!("Synthetic publisher panic")
            });
        }));
        assert!(outcome.is_err());
        assert!(journal.pending(Capability::Collection).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    fn published_test(
        journal: &mut RequestJournal<'_>,
        session: &Negotiated,
        intent: NativeCollectionIntent,
    ) -> PublishedNativeCollection {
        let now = clock(intent.admitted_boottime_ms);
        journal
            .publish_native_observation(intent, &now, session, |_| Ok(()))
            .unwrap()
    }
    fn native_ready<'a>(fixture: &'a Fixture, session: &Negotiated) -> RequestJournal<'a> {
        let mut journal = fixture.open();
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", session)
            .unwrap();
        let pending = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&pending, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        journal
    }
    #[test]
    fn native_publication_checks_durable_scope_before_one_shot_effect() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let mut calls = 0;
        let published = journal
            .publish_native_observation(intent, &clock(1002), &session, |nonce| {
                calls += 1;
                let value: Value = serde_json::from_slice(
                    &std::fs::read(fixture.dir.join("requests.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    value["collection"]["active"]["native_attempt"]["observation_nonce"],
                    nonce
                );
                assert_eq!(value["collection"]["active"]["submitted"], true);
                assert!(
                    value["collection"]["active"]["proof"]["evidence"]
                        .get("scan")
                        .unwrap()
                        .is_null()
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(
            published.observation_nonce(),
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        journal
            .attach_native_scan(published, &clock(1010), &session)
            .unwrap();
    }
    #[test]
    fn retained_native_and_manual_observations_cannot_reuse_counter_prefix() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        drop(
            journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap(),
        );
        let mut persisted: Journal =
            serde_json::from_slice(&std::fs::read(fixture.dir.join("requests.json")).unwrap())
                .unwrap();
        let mut manual = persisted.collection.active.as_ref().unwrap().clone();
        let mut proof = manual_ready(6, 1000, 100000);
        proof.observation.as_mut().unwrap().nonce = "0000000000000009dddddddddddddddd".into();
        manual.delivery = manual_delivery(1);
        manual.acknowledged_nonce = Some(proof.operation_nonce.clone());
        manual.proof = Proof::Manual(Box::new(proof));
        manual.native_attempt = None;
        persisted.manual.active = Some(manual);
        persisted.manual.delivery_highwater = 1;
        persisted.counters.helper = 6;
        persisted.counters.observation = 9;
        assert!(persisted.validate().is_ok());
        let Proof::Manual(proof) = &mut persisted.manual.active.as_mut().unwrap().proof else {
            unreachable!()
        };
        proof.observation.as_mut().unwrap().nonce = "0000000000000008dddddddddddddddd".into();
        assert!(persisted.validate().is_err()); // different suffix, same native Root sequence8
    }
    #[test]
    fn client_schema_one_is_rejected_without_migration_or_counter_reset() {
        let fixture = Fixture::new();
        let path = fixture.dir.join("requests.json");
        let mut legacy: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        legacy["schema_version"] = serde_json::json!(1);
        let bytes = serde_json::to_vec(&legacy).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(RequestJournal::open(&fixture.dir, BOOT, &fixture.lock).is_err());
        assert!(
            RequestJournal::initialize(
                &fixture.dir,
                BOOT,
                CounterSeeds {
                    helper: 0,
                    observation: 0
                },
                &fixture.lock
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    #[test]
    fn native_attempt_mapping_is_required_strict_and_counter_bound() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let intent = published_test(&mut journal, &session, intent);
        journal
            .attach_native_scan(intent, &clock(1010), &session)
            .unwrap();
        let path = fixture.dir.join("requests.json");
        let original: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for action in 0..12 {
            let mut invalid = original.clone();
            let entry = &mut invalid["collection"]["active"];
            match action {
                0 => {
                    entry.as_object_mut().unwrap().remove("native_attempt");
                }
                1 => entry["native_attempt"]["extra"] = serde_json::json!(true),
                2 => entry["native_attempt"]["admitted_boottime_ms"] = serde_json::json!(true),
                3 => entry["native_attempt"]["admitted_boottime_ms"] = serde_json::json!(999),
                4 => entry["native_attempt"]["admitted_boottime_ms"] = serde_json::json!(1011),
                5 => {
                    entry["native_attempt"]["boot_id"] =
                        serde_json::json!("00000000-0000-4000-8000-000000000099")
                }
                6 => {
                    entry["native_attempt"]["observation_nonce"] =
                        serde_json::json!("0000000000000009bbbbbbbbbbbbbbbb")
                }
                7 => entry["submitted"] = serde_json::json!(false),
                8 => {
                    entry["native_attempt"]
                        .as_object_mut()
                        .unwrap()
                        .remove("release_requested_boottime_ms");
                }
                9 => {
                    entry["native_attempt"]["release_requested_boottime_ms"] =
                        serde_json::json!(true)
                }
                10 => {
                    entry["native_attempt"]["release_requested_boottime_ms"] =
                        serde_json::json!(999)
                }
                _ => {
                    entry["native_attempt"]["release_requested_boottime_ms"] =
                        serde_json::json!(1005)
                }
            }
            let bytes = serde_json::to_vec(&invalid).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert!(
                RequestJournal::open(&fixture.dir, BOOT, &fixture.lock).is_err(),
                "action {action}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }
    #[test]
    fn native_scope_is_preserved_in_canonical_terminal_uncertainty() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let nonce = intent.observation_nonce().to_owned();
        drop(intent);
        let pending = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&pending, CanonicalStatus::Failed, None),
            )
            .unwrap();
        drop(journal);
        let mut reopened = fixture.open();
        assert_eq!(
            reopened.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
        let value: Value =
            serde_json::from_slice(&std::fs::read(fixture.dir.join("requests.json")).unwrap())
                .unwrap();
        assert_eq!(
            value["collection"]["last_terminal"]["native_attempt"]["observation_nonce"],
            nonce
        );
        assert!(
            reopened
                .admit(delivery(2), 1, &clock(1010), "cccccccccccccccc", &session)
                .is_err()
        );
    }
    #[test]
    fn generic_collection_path_keeps_explicit_null_native_mapping() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        journal
            .start_collection(REPORT, 1, 1, &clock(1001), &session)
            .unwrap();
        let value: Value =
            serde_json::from_slice(&std::fs::read(fixture.dir.join("requests.json")).unwrap())
                .unwrap();
        assert!(
            value["collection"]["active"]
                .as_object()
                .unwrap()
                .contains_key("native_attempt")
        );
        assert!(value["collection"]["active"]["native_attempt"].is_null());
    }
    #[test]
    fn native_exact_root_scope_survives_restart_without_reminting_authority() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let intent = published_test(&mut journal, &session, intent);
        let bytes = std::fs::read(fixture.dir.join("requests.json")).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema_version"], 2);
        assert_eq!(
            value["collection"]["active"]["native_attempt"],
            serde_json::json!({
            "observation_nonce":intent.observation_nonce(),"boot_id":BOOT,"admitted_boottime_ms":1001,"release_requested_boottime_ms":null})
        );
        let mut reopened = fixture.open();
        assert_eq!(
            reopened.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
        assert!(
            reopened
                .attach_native_scan(intent, &clock(1010), &session)
                .is_err()
        );
        let after: Value =
            serde_json::from_slice(&std::fs::read(fixture.dir.join("requests.json")).unwrap())
                .unwrap();
        assert_eq!(
            after["collection"]["active"]["native_attempt"],
            value["collection"]["active"]["native_attempt"]
        );
    }
    #[test]
    fn native_intent_is_revoked_even_when_mutator_prevalidation_rejects() {
        for action in 0..4 {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_ready(&fixture, &session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let intent = published_test(&mut journal, &session, intent);
            match action {
                0 => assert!(
                    journal
                        .admit_native_collection(
                            "invalid",
                            1,
                            1,
                            &clock(1002),
                            "cccccccccccccccc",
                            &session
                        )
                        .is_err()
                ),
                1 => assert!(
                    journal
                        .fail(Capability::Collection, "invalid reason")
                        .is_err()
                ),
                2 => {
                    let mut invalid = clock(1002);
                    invalid.boot_id = "invalid".into();
                    assert!(
                        journal
                            .begin(Capability::Collection, &invalid, &session)
                            .is_err()
                    );
                }
                _ => assert!(
                    journal
                        .recover_collection(Some(&RetainedInventory {
                            enrollment_id: BOOT.into(),
                            report_id: "invalid".into(),
                            sequence: 1,
                            sha256: "a".repeat(64)
                        }))
                        .is_err()
                ),
            }
            assert!(
                journal
                    .attach_native_scan(intent, &clock(1010), &session)
                    .is_err()
            );
        }
    }
    #[test]
    fn native_persistence_failure_returns_no_authority_and_poisoned_handle() {
        use std::os::unix::fs::PermissionsExt;
        for attach in [false, true] {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_ready(&fixture, &session);
            let intent = if attach {
                Some(
                    journal
                        .admit_native_collection(
                            REPORT,
                            1,
                            1,
                            &clock(1001),
                            "bbbbbbbbbbbbbbbb",
                            &session,
                        )
                        .unwrap(),
                )
            } else {
                None
            };
            let intent = intent.map(|intent| published_test(&mut journal, &session, intent));
            let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
            std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            if let Some(intent) = intent {
                assert!(
                    journal
                        .attach_native_scan(intent, &clock(1010), &session)
                        .is_err()
                );
            } else {
                assert!(
                    journal
                        .admit_native_collection(
                            REPORT,
                            1,
                            1,
                            &clock(1001),
                            "bbbbbbbbbbbbbbbb",
                            &session
                        )
                        .is_err()
                );
            }
            std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(
                std::fs::read(fixture.dir.join("requests.json")).unwrap(),
                before
            );
            assert!(
                journal
                    .reserve_nonce(OperationDomain::Observation, "cccccccccccccccc")
                    .is_err()
            );
        }
    }
    #[test]
    fn native_intent_cannot_attach_to_reopened_identical_journal() {
        let fixture = Fixture::new();
        let session = session();
        let mut first = native_ready(&fixture, &session);
        let intent = first
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let intent = published_test(&mut first, &session, intent);
        let mut reopened = fixture.open();
        assert!(
            reopened
                .attach_native_scan(intent, &clock(1010), &session)
                .is_err()
        );
        assert_eq!(
            reopened.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
        assert!(
            reopened
                .admit_native_collection(REPORT, 2, 1, &clock(1011), "cccccccccccccccc", &session)
                .is_err()
        );
    }
    #[test]
    fn native_intent_is_revoked_by_mutation_recovery_and_renegotiation() {
        for action in 0..4 {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_ready(&fixture, &session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let intent = published_test(&mut journal, &session, intent);
            let next = match action {
                0 => {
                    journal
                        .reserve_nonce(OperationDomain::Observation, "cccccccccccccccc")
                        .unwrap();
                    session.clone()
                }
                1 => {
                    assert_eq!(
                        journal.recover_collection(None).unwrap(),
                        CollectionRecovery::Unfinished
                    );
                    session.clone()
                }
                2 => Negotiated::new(&[Capability::Collection], &[Capability::Collection], true)
                    .unwrap(),
                _ => {
                    assert!(
                        journal
                            .reserve_nonce(OperationDomain::Observation, "invalid")
                            .is_err()
                    );
                    session.clone()
                }
            };
            assert!(
                journal
                    .attach_native_scan(intent, &clock(1010), &next)
                    .is_err()
            );
        }
    }
    #[test]
    fn dropping_native_intent_does_not_undo_submission_or_burned_nonce() {
        let fixture = Fixture::new();
        let session = session();
        let mut journal = native_ready(&fixture, &session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        drop(intent);
        assert!(
            journal
                .admit_native_collection(REPORT, 1, 1, &clock(1002), "cccccccccccccccc", &session)
                .is_err()
        );
        assert_eq!(
            journal.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
        assert_eq!(
            journal
                .reserve_nonce(OperationDomain::Observation, "dddddddddddddddd")
                .unwrap(),
            "0000000000000009dddddddddddddddd"
        );
    }
    #[test]
    fn native_admission_requires_ack_source_boot_and_negotiation() {
        for action in 0..4 {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_ready(&fixture, &session);
            let mut now = clock(1001);
            let source = if action == 0 { 2 } else { 1 };
            if action == 1 {
                now.boot_id = "00000000-0000-4000-8000-000000000099".into();
            }
            let negotiated = if action == 2 {
                Negotiated::new(&[], &[], false).unwrap()
            } else {
                session.clone()
            };
            if action == 3 {
                let no_ack_fixture = Fixture::new();
                let mut no_ack = no_ack_fixture.open();
                no_ack
                    .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session)
                    .unwrap();
                assert!(
                    no_ack
                        .admit_native_collection(REPORT, 1, 1, &now, "bbbbbbbbbbbbbbbb", &session)
                        .is_err()
                );
                continue;
            }
            assert!(
                journal
                    .admit_native_collection(
                        REPORT,
                        1,
                        source,
                        &now,
                        "bbbbbbbbbbbbbbbb",
                        &negotiated
                    )
                    .is_err()
            );
        }
    }
    #[test]
    fn native_intent_rejects_clock_rewind_and_stale_disk_before_attach() {
        for stale in [false, true] {
            let fixture = Fixture::new();
            let session = session();
            let mut journal = native_ready(&fixture, &session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1002), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let intent = published_test(&mut journal, &session, intent);
            if stale {
                fixture
                    .open()
                    .reserve_nonce(OperationDomain::Observation, "cccccccccccccccc")
                    .unwrap();
            }
            assert!(
                journal
                    .attach_native_scan(intent, &clock(if stale { 1010 } else { 1001 }), &session)
                    .is_err()
            );
            let mut reopened = fixture.open();
            assert_eq!(
                reopened.recover_collection(None).unwrap(),
                CollectionRecovery::Unfinished
            );
        }
    }
    #[test]
    fn native_admission_persists_submission_before_later_scan_start() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let session = session();
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session)
            .unwrap();
        let pending = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&pending, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let intent = published_test(&mut journal, &session, intent);
        assert_eq!(
            intent.observation_nonce(),
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        let bytes =
            super::super::state::read(&fixture.dir.join("requests.json"), MAX_JOURNAL).unwrap();
        let persisted: Journal = serde_json::from_slice(&bytes).unwrap();
        let entry = persisted.collection.active.unwrap();
        assert!(entry.submitted);
        assert!(matches!(
            entry.proof,
            Proof::Collection(CollectionProof { scan: None, .. })
        ));
        let proof = journal
            .attach_native_scan(intent, &clock(1010), &session)
            .unwrap();
        assert_eq!(proof.scan.as_ref().unwrap().started_boottime_ms, 1010);
        assert_eq!(proof.scan.as_ref().unwrap().report_id, REPORT);
        assert!(
            journal
                .admit_native_collection(REPORT, 2, 1, &clock(1011), "cccccccccccccccc", &session)
                .is_err()
        );
    }
    #[test]
    fn collection_only_start_refuses_unreconciled_manual_work_even_after_source_failure() {
        for terminal in [false, true] {
            let fixture = Fixture::new();
            let mut journal = fixture.open();
            journal
                .admit(
                    manual_delivery(1),
                    1,
                    &clock(1000),
                    "aaaaaaaaaaaaaaaa",
                    &session(),
                )
                .unwrap();
            let manual = journal.pending(Capability::Manual).unwrap().unwrap();
            journal
                .canonical(
                    Capability::Manual,
                    &canonical(&manual, CanonicalStatus::Delivered, None),
                )
                .unwrap();
            journal
                .begin(Capability::Manual, &clock(1001), &session())
                .unwrap();
            if terminal {
                journal
                    .canonical(
                        Capability::Manual,
                        &canonical(&manual, CanonicalStatus::Failed, None),
                    )
                    .unwrap();
            }
            journal
                .admit(delivery(1), 1, &clock(1002), "bbbbbbbbbbbbbbbb", &session())
                .unwrap();
            let collection = journal.pending(Capability::Collection).unwrap().unwrap();
            journal
                .canonical(
                    Capability::Collection,
                    &canonical(&collection, CanonicalStatus::Delivered, None),
                )
                .unwrap();
            assert!(
                journal
                    .start_collection(REPORT, 1, 1, &clock(1003), &session())
                    .is_err()
            );
            assert_eq!(
                journal
                    .pending(Capability::Collection)
                    .unwrap()
                    .unwrap()
                    .status,
                ClientStatus::Received
            );
        }
    }
    #[test]
    fn canonical_source_failure_does_not_prove_submitted_native_work_stopped() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
            .unwrap();
        let accepted = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&accepted, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        journal
            .begin(Capability::Collection, &clock(1001), &session())
            .unwrap();
        let mut failed = canonical(&accepted, CanonicalStatus::Failed, None);
        failed.request.reason = Some("inventory_authority_changed".into());
        journal.canonical(Capability::Collection, &failed).unwrap();
        drop(journal);
        let mut reopened = fixture.open();
        assert_eq!(
            reopened.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
    }
    #[test]
    fn storage_recovery_distinguishes_idle_waiting_and_matching_ready_bytes() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        assert_eq!(
            journal.recover_collection(None).unwrap(),
            CollectionRecovery::Idle
        );
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
            .unwrap();
        assert_eq!(
            journal.recover_collection(None).unwrap(),
            CollectionRecovery::Waiting
        );
        assert_eq!(
            journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::Received
        );
        drop(journal);
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        ready_collection(&mut journal, 1);
        let descriptor = RetainedInventory {
            enrollment_id: BOOT.into(),
            report_id: REPORT.into(),
            sequence: 1,
            sha256: "c".repeat(64),
        };
        assert_eq!(
            journal.recover_collection(Some(&descriptor)).unwrap(),
            CollectionRecovery::Ready
        );
        let mut foreign = descriptor;
        foreign.enrollment_id = "00000000-0000-4000-8000-000000000099".into();
        assert!(journal.recover_collection(Some(&foreign)).is_err());
        assert_eq!(
            journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::Running
        );
    }
    #[test]
    fn reopened_submitted_work_is_unconfirmed_and_never_authorizes_duplicate_collection() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
            .unwrap();
        let accepted = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&accepted, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        journal
            .begin(Capability::Collection, &clock(1001), &session())
            .unwrap();
        drop(journal);
        let mut reopened = fixture.open();
        assert_eq!(
            reopened.recover_collection(None).unwrap(),
            CollectionRecovery::Unfinished
        );
        assert_eq!(
            reopened
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::Unconfirmed
        );
        assert!(
            reopened
                .begin(Capability::Collection, &clock(1002), &session())
                .is_err()
        );
        assert!(
            reopened
                .admit(delivery(2), 1, &clock(1003), "bbbbbbbbbbbbbbbb", &session())
                .is_err()
        );
    }
    #[test]
    fn missing_ready_body_becomes_absorbing_supersession_with_metadata_only_recovery() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        ready_collection(&mut journal, 1);
        assert_eq!(
            journal.recover_collection(None).unwrap(),
            CollectionRecovery::Superseded
        );
        let descriptor = RetainedInventory {
            enrollment_id: BOOT.into(),
            report_id: REPORT.into(),
            sequence: 1,
            sha256: "c".repeat(64),
        };
        assert_eq!(
            journal.recover_collection(Some(&descriptor)).unwrap(),
            CollectionRecovery::Superseded
        );
        assert_eq!(
            journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::ResultSuperseded
        );
        assert!(!fixture.dir.join("latest.json").exists());
        assert_eq!(std::fs::read_dir(&fixture.dir).unwrap().count(), 2);
    }
    #[test]
    fn supersession_is_absorbing_even_through_generic_error_handlers() {
        for intermediate in ["failed", "unconfirmed"] {
            let fixture = Fixture::new();
            let mut journal = fixture.open();
            let ready = ready_collection(&mut journal, 1);
            let proof = Proof::parse(
                Capability::Collection,
                &serde_json::to_vec(ready.attempt.as_ref().unwrap()).unwrap(),
            )
            .unwrap();
            journal
                .superseded(Capability::Collection, REPORT, &"c".repeat(64))
                .unwrap();
            let mutation = if intermediate == "failed" {
                journal.fail(Capability::Collection, "unavailable")
            } else {
                journal.unconfirmed(Capability::Collection)
            };
            assert!(mutation.is_err());
            assert!(
                journal
                    .bind_ready_report(Capability::Collection, &proof, REPORT, 1, &"c".repeat(64))
                    .is_err()
            );
            drop(journal);
            let journal = fixture.open();
            assert_eq!(
                journal
                    .pending(Capability::Collection)
                    .unwrap()
                    .unwrap()
                    .status,
                ClientStatus::ResultSuperseded
            );
        }
    }
    #[test]
    fn superseded_report_binding_cannot_revive_local_running_state() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let ready = ready_collection(&mut journal, 1);
        let proof = Proof::parse(
            Capability::Collection,
            &serde_json::to_vec(ready.attempt.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        journal
            .superseded(Capability::Collection, REPORT, &"c".repeat(64))
            .unwrap();
        assert!(
            journal
                .bind_ready_report(Capability::Collection, &proof, REPORT, 1, &"c".repeat(64))
                .is_err()
        );
        assert_eq!(
            journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::ResultSuperseded
        );
    }
    #[test]
    fn finished_proof_and_report_binding_commit_together_or_leave_no_ready_evidence() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
            .unwrap();
        let accepted = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&accepted, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        journal
            .begin(Capability::Collection, &clock(1001), &session())
            .unwrap();
        let before =
            serde_json::to_value(journal.pending(Capability::Collection).unwrap().unwrap())
                .unwrap();
        let mut ready = collection_proof();
        ready.scan = Some(ScanProof {
            report_id: REPORT.into(),
            sequence: 1,
            source_revision: 1,
            started_boottime_ms: 1100,
            finished_boottime_ms: Some(1200),
        });
        let proof = Proof::Collection(ready);
        assert!(
            journal
                .progress(Capability::Collection, &proof, None)
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(journal.pending(Capability::Collection).unwrap().unwrap())
                .unwrap(),
            before
        );
        assert!(
            journal
                .bind_ready_report(Capability::Collection, &proof, REPORT, 1, "not-a-hash")
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(journal.pending(Capability::Collection).unwrap().unwrap())
                .unwrap(),
            before
        );
        journal
            .bind_ready_report(Capability::Collection, &proof, REPORT, 1, &"c".repeat(64))
            .unwrap();
        drop(journal);
        let reopened = fixture.open();
        let pending = reopened.pending(Capability::Collection).unwrap().unwrap();
        assert_eq!(pending.report_id.as_deref(), Some(REPORT));
        assert_eq!(
            pending.attempt.unwrap()["scan"]["finished_boottime_ms"],
            1200
        );
    }
    #[test]
    fn negotiated_checkin_is_strict_and_never_offers_paused_or_unsupported_delivery() {
        let body = serde_json::json!({"schema_version":1,"server_time":"2026-10-28T00:00:00Z","source_revision":2,"reporting_enabled":true,"receipt":null,"refresh_request":null,"capabilities":["inventory_collection_v1"],"requests_enabled":true,"collection_request":{"request_id":"00000000-0000-4000-8000-000000000001","delivery_sequence":1,"not_before":"2026-10-28T00:00:00Z","source_revision":2},"refresh_status":null,"collection_status":null});
        assert_eq!(
            CheckIn::parse(&serde_json::to_vec(&body).unwrap())
                .unwrap()
                .source_revision,
            2
        );
        for (key, value) in [
            ("requests_enabled", serde_json::json!(false)),
            ("capabilities", serde_json::json!([])),
            ("source_revision", serde_json::json!(3)),
        ] {
            let mut altered = body.clone();
            altered[key] = value;
            assert!(CheckIn::parse(&serde_json::to_vec(&altered).unwrap()).is_err());
        }
        let mut unknown = body.clone();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(CheckIn::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let duplicate =
            serde_json::to_string(&body)
                .unwrap()
                .replacen("{", "{\"capabilities\":[],", 1);
        assert!(CheckIn::parse(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn negotiation_is_per_capability_and_fallback_is_only_explicit_old_checkin() {
        let mac = capabilities(Platform::Macos, true, true);
        assert_eq!(mac, vec![Capability::Collection]);
        let session =
            Negotiated::new(&mac, &[Capability::Manual, Capability::Collection], true).unwrap();
        assert!(session.allows(Capability::Collection));
        assert!(!session.allows(Capability::Manual));
        assert!(
            !Negotiated::new(&mac, &[Capability::Collection], false)
                .unwrap()
                .allows(Capability::Collection)
        );
        assert!(legacy_fallback(422, br#"{"error":{"code":"invalid_check_in","message":"Request could not be accepted.","request_id":"00000000-0000-4000-8000-000000000001"}}"#));
        assert!(!legacy_fallback(
            401,
            br#"{"error":{"code":"invalid_check_in"}}"#
        ));
        assert!(!legacy_fallback(422, b"<html>login</html>"));
        assert!(!legacy_fallback(503, b"{}"));
    }
    #[test]
    fn collection_proof_has_no_metadata_requirement_and_immutable_identity() {
        let mut proof = collection_proof();
        assert!(!proof.ready());
        proof.scan = Some(ScanProof {
            report_id: REPORT.into(),
            sequence: 1,
            source_revision: 1,
            started_boottime_ms: 1100,
            finished_boottime_ms: Some(1200),
        });
        proof.validate().unwrap();
        assert!(proof.ready());
        let before = Proof::Collection(collection_proof());
        let merged = before.merge(&Proof::Collection(proof.clone())).unwrap();
        assert!(merged.ready());
        proof.accepted_boottime_ms = 1001;
        assert!(merged.merge(&Proof::Collection(proof)).is_err());
    }
    #[test]
    fn durable_admission_ack_before_start_and_independent_counters() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let session = session();
        let delivery = delivery(1);
        let first = journal
            .admit(
                delivery.clone(),
                1,
                &clock(1000),
                "aaaaaaaaaaaaaaaa",
                &session,
            )
            .unwrap();
        assert_eq!(first, Admission::New);
        assert!(
            journal
                .begin(Capability::Collection, &clock(1001), &session)
                .is_err()
        );
        let accepted = journal.pending(Capability::Collection).unwrap().unwrap();
        assert_eq!(accepted.status, ClientStatus::Received);
        journal
            .canonical(
                Capability::Collection,
                &canonical(&accepted, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        assert!(
            journal
                .begin(Capability::Collection, &clock(1002), &session)
                .is_ok()
        );
        assert!(
            journal
                .begin(Capability::Collection, &clock(1003), &session)
                .is_err()
        );
        assert!(
            journal
                .admit(
                    delivery.clone(),
                    1,
                    &clock(1004),
                    "bbbbbbbbbbbbbbbb",
                    &session
                )
                .is_ok()
        );
        drop(journal);
        let mut restored = fixture.open();
        assert!(
            restored
                .begin(Capability::Collection, &clock(1005), &session)
                .is_err()
        );
        assert_eq!(
            restored
                .reserve_nonce(OperationDomain::Helper, "bbbbbbbbbbbbbbbb")
                .unwrap(),
            "0000000000000006bbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            restored
                .reserve_nonce(OperationDomain::Observation, "bbbbbbbbbbbbbbbb")
                .unwrap(),
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            restored
                .reserve_nonce(OperationDomain::Collection, "bbbbbbbbbbbbbbbb")
                .unwrap(),
            "0000000000000002bbbbbbbbbbbbbbbb"
        );
    }
    #[test]
    fn old_client_fallback_never_rewrites_package_report_or_schedule() {
        let fixture = Fixture::new();
        let latest = fixture.dir.join("latest.json");
        let schedule = fixture.dir.join("schedule.json");
        std::fs::write(&latest, b"exact retained report bytes").unwrap();
        std::fs::write(&schedule, b"existing unchanged schedule").unwrap();
        let mut journal = fixture.open();
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
            .unwrap();
        assert_eq!(
            std::fs::read(latest).unwrap(),
            b"exact retained report bytes"
        );
        assert_eq!(
            std::fs::read(schedule).unwrap(),
            b"existing unchanged schedule"
        );
        assert!(journal.pending(Capability::Collection).unwrap().is_some());
    }
    #[test]
    fn manual_vector_requires_real_lock_coverage_and_strict_null_fields() {
        let good = manual_ready(1, 1000, 100000);
        good.validate().unwrap();
        assert!(good.ready());
        let bytes = serde_json::to_vec(&good).unwrap();
        assert!(Proof::parse(Capability::Manual, &bytes).unwrap().ready());
        let mut bad = good.clone();
        bad.observation.as_mut().unwrap().held_until_boottime_ms = Some(2900);
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.helper.as_mut().unwrap().started_boottime_ms = Some(900);
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.reader.as_mut().unwrap().policy_generation = "d".repeat(64);
        assert!(bad.validate().is_err());
        let mut missing = serde_json::to_value(&good).unwrap();
        missing.as_object_mut().unwrap().remove("reader");
        assert!(Proof::parse(Capability::Manual, &serde_json::to_vec(&missing).unwrap()).is_err());
        let duplicate = String::from_utf8(bytes).unwrap().replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        );
        assert!(Proof::parse(Capability::Manual, duplicate.as_bytes()).is_err());
    }
    #[test]
    fn no_work_retry_requires_canonical_deferral_and_keeps_original_deadline() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(
                manual_delivery(1),
                1,
                &clock(1000),
                "aaaaaaaaaaaaaaaa",
                &session(),
            )
            .unwrap();
        let received = journal.pending(Capability::Manual).unwrap().unwrap();
        journal
            .canonical(
                Capability::Manual,
                &canonical(&received, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        journal
            .begin(Capability::Manual, &clock(1001), &session())
            .unwrap();
        let mut proof = match Proof::parse(
            Capability::Manual,
            &serde_json::to_vec(received.attempt.as_ref().unwrap()).unwrap(),
        )
        .unwrap()
        {
            Proof::Manual(p) => p,
            _ => unreachable!(),
        };
        proof.helper = Some(HelperProof {
            operation_nonce: proof.operation_nonce.clone(),
            helper_sequence: proof.helper_sequence,
            boot_id: BOOT.into(),
            accepted_boottime_ms: 1100,
            started_boottime_ms: None,
            finished_boottime_ms: Some(1200),
            result: Some(HelperResult::Deferred),
            cache_generation: None,
            policy_generation: None,
        });
        journal
            .progress(
                Capability::Manual,
                &Proof::Manual(proof.clone()),
                Some("minimum_interval"),
            )
            .unwrap();
        assert!(
            journal
                .retry_no_work(&clock(1300), "bbbbbbbbbbbbbbbb", &session())
                .is_err()
        );
        let deferred = journal.pending(Capability::Manual).unwrap().unwrap();
        assert_eq!(deferred.reason.as_deref(), Some("minimum_interval"));
        journal
            .canonical(
                Capability::Manual,
                &canonical(&deferred, CanonicalStatus::Deferred, None),
            )
            .unwrap();
        journal
            .retry_no_work(&clock(1300), "bbbbbbbbbbbbbbbb", &session())
            .unwrap();
        let retried = journal.pending(Capability::Manual).unwrap().unwrap();
        assert_eq!(
            retried.attempt.as_ref().unwrap()["deadline_boottime_ms"],
            proof.deadline_boottime_ms
        );
        assert_eq!(
            retried.operation_nonce.as_deref(),
            Some("0000000000000007bbbbbbbbbbbbbbbb")
        );
        assert!(
            journal
                .begin(Capability::Manual, &clock(1301), &session())
                .is_err()
        );
        drop(journal);
        let restored = fixture.open();
        assert_eq!(
            restored
                .pending(Capability::Manual)
                .unwrap()
                .unwrap()
                .operation_nonce,
            retried.operation_nonce
        );
    }
    #[test]
    fn started_or_unconfirmed_helper_work_cannot_allocate_another_attempt() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(
                manual_delivery(1),
                1,
                &clock(1000),
                "aaaaaaaaaaaaaaaa",
                &session(),
            )
            .unwrap();
        let received = journal.pending(Capability::Manual).unwrap().unwrap();
        journal
            .canonical(
                Capability::Manual,
                &canonical(&received, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        journal
            .begin(Capability::Manual, &clock(1001), &session())
            .unwrap();
        journal.unconfirmed(Capability::Manual).unwrap();
        assert!(
            journal
                .retry_no_work(&clock(1300), "bbbbbbbbbbbbbbbb", &session())
                .is_err()
        );
        assert!(
            journal
                .begin(Capability::Manual, &clock(1300), &session())
                .is_err()
        );
        let mut proof = manual_ready(6, 1000, 86_401_000);
        proof.helper.as_mut().unwrap().result = Some(HelperResult::Failed);
        proof.reader = None;
        proof.observation = None;
        proof.scan = None;
        journal
            .progress(
                Capability::Manual,
                &Proof::Manual(proof.into()),
                Some("repository_failed"),
            )
            .unwrap();
        assert_eq!(
            journal.pending(Capability::Manual).unwrap().unwrap().status,
            ClientStatus::Failed
        );
        assert!(
            journal
                .retry_no_work(&clock(4000), "bbbbbbbbbbbbbbbb", &session())
                .is_err()
        );
    }
    #[test]
    fn report_receipt_alone_is_not_terminal_and_old_ack_cannot_clear_new_request() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let ready = ready_collection(&mut journal, 1);
        let receipt = receipt(&ready);
        journal
            .canonical(
                Capability::Collection,
                &canonical(&ready, CanonicalStatus::Unconfirmed, Some(receipt.clone())),
            )
            .unwrap();
        assert!(
            journal
                .admit(delivery(2), 1, &clock(2000), "bbbbbbbbbbbbbbbb", &session())
                .is_err()
        );
        journal
            .superseded(Capability::Collection, REPORT, &"c".repeat(64))
            .unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&ready, CanonicalStatus::Complete, Some(receipt.clone())),
            )
            .unwrap();
        journal
            .admit(delivery(2), 1, &clock(2000), "bbbbbbbbbbbbbbbb", &session())
            .unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&ready, CanonicalStatus::Complete, Some(receipt)),
            )
            .unwrap();
        assert_eq!(
            journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .request_id,
            delivery(2).id()
        );
        assert!(
            journal
                .admit(delivery(1), 1, &clock(3000), "cccccccccccccccc", &session())
                .is_ok()
        );
    }
    #[test]
    fn terminal_fence_and_delivery_highwater_survive_pruned_uuid_and_reboot() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        for sequence in 1..=2 {
            journal
                .admit(
                    delivery(sequence),
                    1,
                    &clock(1000),
                    "aaaaaaaaaaaaaaaa",
                    &session(),
                )
                .unwrap();
            let pending = journal.pending(Capability::Collection).unwrap().unwrap();
            journal
                .canonical(
                    Capability::Collection,
                    &canonical(&pending, CanonicalStatus::Failed, None),
                )
                .unwrap();
        }
        drop(journal);
        let mut restored = fixture.open();
        let mut reboot = clock(100);
        reboot.boot_id = "00000000-0000-4000-8000-000000000003".into();
        assert!(
            restored
                .admit(delivery(1), 1, &reboot, "bbbbbbbbbbbbbbbb", &session())
                .is_err()
        );
        assert_eq!(
            restored
                .reserve_nonce(OperationDomain::Helper, "bbbbbbbbbbbbbbbb")
                .unwrap(),
            "0000000000000006bbbbbbbbbbbbbbbb"
        );
        let terminal = restored.pending(Capability::Collection).unwrap().unwrap();
        assert!(
            restored
                .canonical(
                    Capability::Collection,
                    &canonical(&terminal, CanonicalStatus::Complete, None)
                )
                .is_err()
        );
    }
    #[test]
    fn corruption_oversize_and_uncertain_persistence_never_reset_counters() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let before = std::fs::read(fixture.dir.join("requests.json")).unwrap();
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(
            journal
                .reserve_nonce(OperationDomain::Helper, "aaaaaaaaaaaaaaaa")
                .is_err()
        );
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            journal
                .reserve_nonce(OperationDomain::Helper, "bbbbbbbbbbbbbbbb")
                .is_err()
        );
        assert_eq!(
            std::fs::read(fixture.dir.join("requests.json")).unwrap(),
            before
        );
        drop(journal);
        std::fs::write(
            fixture.dir.join("requests.json"),
            vec![b' '; MAX_JOURNAL + 1],
        )
        .unwrap();
        assert!(RequestJournal::open(&fixture.dir, BOOT, &fixture.lock).is_err());
        assert!(
            RequestJournal::initialize(
                &fixture.dir,
                BOOT,
                CounterSeeds {
                    helper: 0,
                    observation: 0
                },
                &fixture.lock
            )
            .is_err()
        );
    }
    #[test]
    fn invalid_evidence_never_reports_ready_and_canonical_wire_is_strict() {
        assert_eq!(
            capabilities(Platform::Linux, true, true),
            vec![Capability::Collection, Capability::Manual]
        );
        assert_eq!(
            capabilities(Platform::Linux, true, false),
            vec![Capability::Collection]
        );
        let mut bad = manual_ready(1, 1000, 100000);
        bad.observation.as_mut().unwrap().held_until_boottime_ms = Some(2900);
        assert!(!bad.ready());
        let mut collection = collection_proof();
        collection.scan = Some(ScanProof {
            report_id: REPORT.into(),
            sequence: 1,
            source_revision: 1,
            started_boottime_ms: 900,
            finished_boottime_ms: Some(1200),
        });
        assert!(!collection.ready());
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
            .unwrap();
        let pending = journal.pending(Capability::Collection).unwrap().unwrap();
        let response = canonical(&pending, CanonicalStatus::Delivered, None);
        Canonical::parse(&serde_json::to_vec(&response).unwrap()).unwrap();
        let mut invalid = serde_json::to_value(&response).unwrap();
        invalid["request"]["reason"] = serde_json::json!("https://credential.invalid/private");
        assert!(Canonical::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
        let mut invalid = serde_json::to_value(response).unwrap();
        invalid["extra"] = serde_json::json!(true);
        assert!(Canonical::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    #[test]
    fn paused_delivery_reboot_and_explicit_failure_never_start_work() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
            .unwrap();
        let pending = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&pending, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        let paused =
            Negotiated::new(&[Capability::Collection], &[Capability::Collection], false).unwrap();
        assert!(
            journal
                .begin(Capability::Collection, &clock(1100), &paused)
                .is_err()
        );
        let mut reboot = clock(1100);
        reboot.boot_id = "00000000-0000-4000-8000-000000000003".into();
        assert!(
            journal
                .begin(Capability::Collection, &reboot, &session())
                .is_err()
        );
        journal
            .fail(Capability::Collection, "collection_failed")
            .unwrap();
        assert_eq!(
            journal
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .status,
            ClientStatus::Failed
        );
        assert!(
            journal
                .begin(Capability::Collection, &clock(1200), &session())
                .is_err()
        );
    }
    #[test]
    fn no_work_retry_after_reboot_keeps_absolute_expiry_and_root_counter() {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        journal
            .admit(
                manual_delivery(1),
                1,
                &clock(1000),
                "aaaaaaaaaaaaaaaa",
                &session(),
            )
            .unwrap();
        let received = journal.pending(Capability::Manual).unwrap().unwrap();
        journal
            .canonical(
                Capability::Manual,
                &canonical(&received, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        journal
            .begin(Capability::Manual, &clock(1001), &session())
            .unwrap();
        let Proof::Manual(mut proof) = Proof::parse(
            Capability::Manual,
            &serde_json::to_vec(&received.attempt.unwrap()).unwrap(),
        )
        .unwrap() else {
            unreachable!()
        };
        proof.helper = Some(HelperProof {
            operation_nonce: proof.operation_nonce.clone(),
            helper_sequence: 6,
            boot_id: BOOT.into(),
            accepted_boottime_ms: 1100,
            started_boottime_ms: None,
            finished_boottime_ms: Some(1200),
            result: Some(HelperResult::Deferred),
            cache_generation: None,
            policy_generation: None,
        });
        journal
            .progress(Capability::Manual, &Proof::Manual(proof), Some("busy"))
            .unwrap();
        let pending = journal.pending(Capability::Manual).unwrap().unwrap();
        journal
            .canonical(
                Capability::Manual,
                &canonical(&pending, CanonicalStatus::Deferred, None),
            )
            .unwrap();
        let mut reboot = clock(100);
        reboot.boot_id = "00000000-0000-4000-8000-000000000003".into();
        reboot.unix_ms += 10000;
        journal
            .retry_no_work(&reboot, "bbbbbbbbbbbbbbbb", &session())
            .unwrap();
        let next = journal.pending(Capability::Manual).unwrap().unwrap();
        assert_eq!(
            next.operation_nonce.as_deref(),
            Some("0000000000000007bbbbbbbbbbbbbbbb")
        );
        assert_eq!(next.attempt.unwrap()["deadline_boottime_ms"], 86_390_100u64);
        assert!(
            journal
                .begin(Capability::Manual, &reboot, &session())
                .is_err()
        );
    }
    #[test]
    fn stale_cached_handle_cannot_rewind_burned_counters_or_delivery_highwater() {
        let fixture = Fixture::new();
        let mut first = fixture.open();
        let mut stale = fixture.open();
        assert_eq!(
            first
                .reserve_nonce(OperationDomain::Helper, "aaaaaaaaaaaaaaaa")
                .unwrap(),
            "0000000000000006aaaaaaaaaaaaaaaa"
        );
        first
            .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
            .unwrap();
        let committed = std::fs::read(fixture.dir.join("requests.json")).unwrap();
        assert!(
            stale
                .reserve_nonce(OperationDomain::Helper, "bbbbbbbbbbbbbbbb")
                .is_err()
        );
        assert!(
            stale
                .admit(delivery(2), 1, &clock(2000), "bbbbbbbbbbbbbbbb", &session())
                .is_err()
        );
        assert!(stale.pending(Capability::Collection).is_err());
        assert_eq!(
            std::fs::read(fixture.dir.join("requests.json")).unwrap(),
            committed
        );
        drop(first);
        drop(stale);
        let mut reopened = fixture.open();
        assert_eq!(
            reopened
                .reserve_nonce(OperationDomain::Helper, "cccccccccccccccc")
                .unwrap(),
            "0000000000000007cccccccccccccccc"
        );
        assert_eq!(
            reopened
                .pending(Capability::Collection)
                .unwrap()
                .unwrap()
                .request_id,
            delivery(1).id()
        );
    }
    #[test]
    fn concurrent_cached_handles_have_one_durable_winner() {
        let fixture = Fixture::new();
        let mut first = fixture.open();
        let mut second = fixture.open();
        let barrier = std::sync::Barrier::new(2);
        let winners = std::thread::scope(|scope| {
            let barrier = &barrier;
            let a = scope.spawn(move || {
                barrier.wait();
                first
                    .reserve_nonce(OperationDomain::Helper, "aaaaaaaaaaaaaaaa")
                    .is_ok()
            });
            let b = scope.spawn(move || {
                barrier.wait();
                second
                    .reserve_nonce(OperationDomain::Helper, "bbbbbbbbbbbbbbbb")
                    .is_ok()
            });
            usize::from(a.join().unwrap()) + usize::from(b.join().unwrap())
        });
        assert_eq!(winners, 1);
        let mut reopened = fixture.open();
        assert_eq!(
            reopened
                .reserve_nonce(OperationDomain::Helper, "cccccccccccccccc")
                .unwrap(),
            "0000000000000007cccccccccccccccc"
        );
    }
    #[test]
    fn canonical_running_or_uncertainty_never_authorizes_a_first_start() {
        for outcome in [CanonicalStatus::Running, CanonicalStatus::Unconfirmed] {
            for received_was_acknowledged in [false, true] {
                let fixture = Fixture::new();
                let mut journal = fixture.open();
                journal
                    .admit(delivery(1), 1, &clock(1000), "aaaaaaaaaaaaaaaa", &session())
                    .unwrap();
                let received = journal.pending(Capability::Collection).unwrap().unwrap();
                if received_was_acknowledged {
                    journal
                        .canonical(
                            Capability::Collection,
                            &canonical(&received, CanonicalStatus::Delivered, None),
                        )
                        .unwrap();
                }
                journal
                    .canonical(Capability::Collection, &canonical(&received, outcome, None))
                    .unwrap();
                assert!(
                    journal
                        .begin(Capability::Collection, &clock(1001), &session())
                        .is_err()
                );
                // A delayed older Delivered response cannot erase known uncertainty.
                journal
                    .canonical(
                        Capability::Collection,
                        &canonical(&received, CanonicalStatus::Delivered, None),
                    )
                    .unwrap();
                assert!(
                    journal
                        .begin(Capability::Collection, &clock(1002), &session())
                        .is_err()
                );
                drop(journal);
                let mut reopened = fixture.open();
                assert!(
                    reopened
                        .begin(Capability::Collection, &clock(1003), &session())
                        .is_err()
                );
            }
        }
    }
    fn manual_delivery(sequence: u64) -> Delivery {
        Delivery::Manual(ManualDelivery {
            request_id: format!("10000000-0000-4000-8000-{sequence:012}"),
            delivery_sequence: sequence,
            expires_at: "2026-01-02T00:00:00.000Z".into(),
        })
    }
    fn manual_ready(sequence: u64, accepted: u64, deadline: u64) -> ManualProof {
        serde_json::from_value(serde_json::json!({"schema_version":1,"operation_nonce":format!("{sequence:016x}aaaaaaaaaaaaaaaa"),"helper_sequence":sequence,"boot_id":BOOT,"accepted_boottime_ms":accepted,"deadline_boottime_ms":deadline,
            "helper":{"operation_nonce":format!("{sequence:016x}aaaaaaaaaaaaaaaa"),"helper_sequence":sequence,"boot_id":BOOT,"accepted_boottime_ms":1100,"started_boottime_ms":1200,"finished_boottime_ms":2000,"result":"succeeded","cache_generation":"b".repeat(32),"policy_generation":"c".repeat(64)},
            "reader":{"boot_id":BOOT,"cache_generation":"b".repeat(32),"policy_generation":"c".repeat(64),"opened_boottime_ms":2100,"closed_boottime_ms":3300},
            "observation":{"nonce":"0000000000000001dddddddddddddddd","boot_id":BOOT,"cache_generation":"b".repeat(32),"policy_generation":"c".repeat(64),"opened_boottime_ms":2200,"expires_boottime_ms":100000,"held_until_boottime_ms":3100,"released_boottime_ms":3200,"coherent":true},
            "scan":{"report_id":REPORT,"sequence":1,"source_revision":1,"started_boottime_ms":2300,"finished_boottime_ms":3000}})).unwrap()
    }
    fn ready_collection(journal: &mut RequestJournal<'_>, sequence: u64) -> StatusMessage {
        journal
            .admit(
                delivery(sequence),
                1,
                &clock(1000),
                "aaaaaaaaaaaaaaaa",
                &session(),
            )
            .unwrap();
        let received = journal.pending(Capability::Collection).unwrap().unwrap();
        journal
            .canonical(
                Capability::Collection,
                &canonical(&received, CanonicalStatus::Delivered, None),
            )
            .unwrap();
        journal
            .begin(Capability::Collection, &clock(1001), &session())
            .unwrap();
        let mut proof = collection_proof();
        proof.collection_sequence = sequence;
        proof.operation_nonce = format!("{sequence:016x}aaaaaaaaaaaaaaaa");
        proof.scan = Some(ScanProof {
            report_id: REPORT.into(),
            sequence: 1,
            source_revision: 1,
            started_boottime_ms: 1100,
            finished_boottime_ms: Some(1200),
        });
        journal
            .bind_ready_report(
                Capability::Collection,
                &Proof::Collection(proof),
                REPORT,
                1,
                &"c".repeat(64),
            )
            .unwrap();
        journal.pending(Capability::Collection).unwrap().unwrap()
    }
    fn receipt(status: &StatusMessage) -> Receipt {
        Receipt {
            schema_version: 1,
            enrollment_id: BOOT.into(),
            report_id: status.report_id.clone().unwrap(),
            sequence: 1,
            sha256: status.report_sha256.clone().unwrap(),
            accepted_at: "2026-01-01T00:00:01.000Z".into(),
            disposition: "current".into(),
        }
    }
    fn session() -> Negotiated {
        Negotiated::new(
            &[Capability::Manual, Capability::Collection],
            &[Capability::Manual, Capability::Collection],
            true,
        )
        .unwrap()
    }
    fn clock(time: u64) -> Clock {
        Clock {
            boot_id: BOOT.into(),
            boottime_ms: time,
            unix_ms: 1_767_225_600_000,
        }
    }
    fn delivery(sequence: u64) -> Delivery {
        Delivery::Collection(CollectionDelivery {
            request_id: format!("00000000-0000-4000-8000-{sequence:012}"),
            delivery_sequence: sequence,
            not_before: "2026-01-01T00:00:00.000Z".into(),
            source_revision: 1,
        })
    }
    fn canonical(
        status: &StatusMessage,
        result: CanonicalStatus,
        receipt: Option<Receipt>,
    ) -> Canonical {
        Canonical {
            schema_version: 1,
            request: CanonicalRequest {
                request_id: status.request_id.clone(),
                delivery_sequence: status.delivery_sequence,
                status: result,
                reason: None,
                report_id: status.report_id.clone(),
                report_sha256: status.report_sha256.clone(),
                operation_nonce: status.operation_nonce.clone(),
            },
            receipt,
        }
    }
    struct Fixture {
        dir: std::path::PathBuf,
        lock: super::super::state::Lock,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "inventory-journal-{}",
                    super::super::transport::report_id().unwrap()
                ));
            std::fs::create_dir(&dir).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let lock = super::super::state::Lock::acquire(&dir).unwrap();
            RequestJournal::initialize(
                &dir,
                BOOT,
                CounterSeeds {
                    helper: 5,
                    observation: 7,
                },
                &lock,
            )
            .unwrap();
            Self { dir, lock }
        }
        fn open(&self) -> RequestJournal<'_> {
            RequestJournal::open(&self.dir, BOOT, &self.lock).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    const BOOT: &str = "00000000-0000-4000-8000-000000000001";
    const REPORT: &str = "00000000-0000-4000-8000-000000000002";
    fn collection_proof() -> CollectionProof {
        CollectionProof {
            schema_version: 1,
            operation_nonce: "0000000000000001aaaaaaaaaaaaaaaa".into(),
            collection_sequence: 1,
            boot_id: BOOT.into(),
            accepted_boottime_ms: 1000,
            scan: None,
        }
    }
}
