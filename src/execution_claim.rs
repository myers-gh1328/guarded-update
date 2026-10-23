//! Execution claims are separate from reporting approvals.
use serde::{Deserialize, Serialize};
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionClaim {
    pub schema_version: u32,
    pub claim_id: String,
    pub device_id: String,
    pub proposal_id: String,
    pub manifest_sha256: String,
    pub claim_nonce: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub allow_service_restarts: bool,
    pub execution_allowed: bool,
    pub allow_reboot: bool,
    pub signature: String,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.split('-').map(str::len).eq([8, 4, 4, 4, 12])
        && value
            .bytes()
            .all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl ExecutionClaim {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 8192 {
            return Err("Execution claim exceeds limit".into());
        }
        serde_json::from_slice(bytes).map_err(|_| "Invalid execution claim".into())
    }
    pub(crate) fn message(&self) -> String {
        format!(
            "guarded-update-execution-claim-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\ntrue\nfalse",
            self.claim_id,
            self.device_id,
            self.proposal_id,
            self.manifest_sha256,
            self.claim_nonce,
            self.issued_at_unix,
            self.expires_at_unix,
            self.allow_service_restarts
        )
    }
    pub(crate) fn validate(
        &self,
        device: &str,
        proposal: &str,
        digest: &str,
        nonce: &str,
        now: u64,
    ) -> Result<(), String> {
        if self.schema_version != 1
            || !uuid(&self.claim_id)
            || !hex(&self.proposal_id, 32)
            || !hex(&self.manifest_sha256, 64)
            || !hex(&self.claim_nonce, 32)
            || self.device_id != device
            || self.proposal_id != proposal
            || self.manifest_sha256 != digest
            || self.claim_nonce != nonce
            || !self.allow_service_restarts
            || !self.execution_allowed
            || self.allow_reboot
            || self.issued_at_unix > now
            || self.expires_at_unix <= now
            || self.expires_at_unix <= self.issued_at_unix
            || self.expires_at_unix - self.issued_at_unix > 120
            || self.signature.len() < 128
            || self.signature.len() > 160
            || !self.signature.len().is_multiple_of(2)
            || !hex(&self.signature, self.signature.len())
        {
            return Err("Execution claim does not match live transaction authority".into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn claim() -> ExecutionClaim {
        ExecutionClaim {
            schema_version: 1,
            claim_id: "26e630b4-e3c9-4db3-b4fa-46a912aaab0c".into(),
            device_id: "fixture-device".into(),
            proposal_id: "a".repeat(32),
            manifest_sha256: "b".repeat(64),
            claim_nonce: "c".repeat(32),
            issued_at_unix: 1000,
            expires_at_unix: 1120,
            allow_service_restarts: true,
            execution_allowed: true,
            allow_reboot: false,
            signature: "ab".repeat(70),
        }
    }
    #[test]
    fn dcc_signed_execution_fixture_matches_and_verifies() {
        use crate::exec::SystemRunner;
        use std::time::Duration;
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/guarded-update-execution-claim-v1.json"
        ))
        .unwrap();
        let claim: ExecutionClaim = serde_json::from_value(fixture["claim"].clone()).unwrap();
        assert_eq!(claim.message(), fixture["canonical"].as_str().unwrap());
        claim
            .validate(
                "fixture-device",
                &"a".repeat(32),
                &claim.manifest_sha256,
                &"e".repeat(32),
                2_000_000_001,
            )
            .unwrap();
        let temporary =
            std::env::temp_dir().join(format!("guarded-claim-fixture-{}", std::process::id()));
        std::fs::create_dir(&temporary).unwrap();
        let key = temporary.join("public.pem");
        let signature = temporary.join("signature.der");
        std::fs::write(&key, fixture["public_key"].as_str().unwrap()).unwrap();
        let bytes: Vec<u8> = claim
            .signature
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        std::fs::write(&signature, bytes).unwrap();
        let runner = SystemRunner::new(Duration::from_secs(10));
        let verified = runner
            .run_input(
                "/usr/bin/openssl",
                &[
                    "dgst",
                    "-sha256",
                    "-verify",
                    key.to_str().unwrap(),
                    "-signature",
                    signature.to_str().unwrap(),
                ],
                &[("LC_ALL", "C")],
                Some(&claim.message()),
            )
            .unwrap();
        assert!(verified.success());
        let mut changed = claim.clone();
        changed.claim_nonce = "f".repeat(32);
        assert!(
            !runner
                .run_input(
                    "/usr/bin/openssl",
                    &[
                        "dgst",
                        "-sha256",
                        "-verify",
                        key.to_str().unwrap(),
                        "-signature",
                        signature.to_str().unwrap()
                    ],
                    &[("LC_ALL", "C")],
                    Some(&changed.message())
                )
                .unwrap()
                .success()
        );
        std::fs::remove_file(key).unwrap();
        std::fs::remove_file(signature).unwrap();
        std::fs::remove_dir(temporary).unwrap();
    }
    #[test]
    fn binds_manifest_nonce_device_and_short_validity() {
        let c = claim();
        assert!(
            c.validate(
                "fixture-device",
                &"a".repeat(32),
                &"b".repeat(64),
                &"c".repeat(32),
                1000
            )
            .is_ok()
        );
        assert!(
            c.validate(
                "wrong",
                &"a".repeat(32),
                &"b".repeat(64),
                &"c".repeat(32),
                1000
            )
            .is_err()
        );
        assert!(
            c.validate(
                "fixture-device",
                &"a".repeat(32),
                &"d".repeat(64),
                &"c".repeat(32),
                1000
            )
            .is_err()
        );
        assert!(
            c.validate(
                "fixture-device",
                &"a".repeat(32),
                &"b".repeat(64),
                &"d".repeat(32),
                1000
            )
            .is_err()
        );
        assert!(
            c.validate(
                "fixture-device",
                &"a".repeat(32),
                &"b".repeat(64),
                &"c".repeat(32),
                999
            )
            .is_err()
        );
        assert!(
            c.validate(
                "fixture-device",
                &"a".repeat(32),
                &"b".repeat(64),
                &"c".repeat(32),
                1120
            )
            .is_err()
        );
    }
    #[test]
    fn reporting_approval_or_reboot_never_authorizes_execution() {
        for mutate in [
            |c: &mut ExecutionClaim| c.execution_allowed = false,
            |c: &mut ExecutionClaim| c.allow_reboot = true,
            |c: &mut ExecutionClaim| c.expires_at_unix = 1121,
        ] {
            let mut c = claim();
            mutate(&mut c);
            assert!(
                c.validate(
                    "fixture-device",
                    &"a".repeat(32),
                    &"b".repeat(64),
                    &"c".repeat(32),
                    1000
                )
                .is_err()
            );
        }
    }
    #[test]
    fn canonical_signature_binds_all_authority() {
        let c = claim();
        assert_eq!(
            c.message(),
            format!(
                "guarded-update-execution-claim-v1\n{}\nfixture-device\n{}\n{}\n{}\n1000\n1120\ntrue\ntrue\nfalse",
                c.claim_id, c.proposal_id, c.manifest_sha256, c.claim_nonce
            )
        );
        let mut changed = c.clone();
        changed.allow_service_restarts = false;
        assert_ne!(c.message(), changed.message());
    }
}
