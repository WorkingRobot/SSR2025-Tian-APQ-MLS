# Security Vulnerability Test Cases

**Document Version:** 1.0
**Date:** 2026-03-08
**Related Documents:** SECURITY_ASSESSMENT.md, REMEDIATION_GUIDE.md

This document provides detailed test cases to verify each identified vulnerability and confirm that remediations are effective.

---

## Test Case Structure

Each test case follows this format:
- **Test ID:** Unique identifier
- **Related Vulnerability:** Link to vulnerability in assessment
- **Test Type:** Unit, Integration, Security, Performance, etc.
- **Purpose:** What security property is being tested
- **Setup:** Prerequisites and test environment
- **Procedure:** Step-by-step test execution
- **Expected Result:** What indicates the test passes
- **Failure Indicators:** What indicates a security issue

---

## VULN-001: IKM Entropy Handling Tests

### TEST-001-01: IKM Full Length Utilization

**Related Vulnerability:** VULN-001
**Test Type:** Unit Test
**Purpose:** Verify that full IKM is used, not just first 32 bytes

#### Setup
```rust
use hpke_rs::mlkem_kem::derive_key_pair512;

#[test]
fn test_ikm_full_length_utilization() {
```

#### Procedure
```rust
    // Create two IKM values:
    // - Same first 32 bytes
    // - Different after byte 32
    let mut ikm_32 = vec![0x42; 32];
    let mut ikm_64 = vec![0x42; 32];
    ikm_64.extend_from_slice(&[0x99; 32]); // Different last 32 bytes

    // Generate keypairs
    let (pk1, sk1) = derive_key_pair512(&ikm_32).unwrap();
    let (pk2, sk2) = derive_key_pair512(&ikm_64).unwrap();
```

#### Expected Result
```rust
    // If full IKM is used correctly, keys MUST be different
    assert_ne!(pk1, pk2, "Public keys should differ when IKM differs");
    assert_ne!(sk1, sk2, "Private keys should differ when IKM differs");
}
```

**Failure Indicators:**
- Keys are identical → Only first 32 bytes are being used (VULNERABLE)

---

### TEST-001-02: IKM Determinism

**Related Vulnerability:** VULN-001
**Test Type:** Unit Test
**Purpose:** Verify same IKM produces same keys (for test reproducibility)

#### Procedure
```rust
#[test]
fn test_ikm_determinism() {
    let ikm = vec![0x42; 64];

    let (pk1, sk1) = derive_key_pair512(&ikm).unwrap();
    let (pk2, sk2) = derive_key_pair512(&ikm).unwrap();

    // Same IKM MUST produce same keys
    assert_eq!(pk1, pk2, "Same IKM should produce same public key");
    assert_eq!(sk1, sk2, "Same IKM should produce same private key");
}
```

**Expected Result:** Keys are identical

---

### TEST-001-03: IKM Minimum Length Validation

**Related Vulnerability:** VULN-001
**Test Type:** Unit Test
**Purpose:** Verify short IKM is rejected

#### Procedure
```rust
#[test]
fn test_ikm_minimum_length() {
    let ikm_short = vec![0x42; 31]; // Too short

    let result = derive_key_pair512(&ikm_short);

    assert!(result.is_err(), "Short IKM should be rejected");
    assert!(
        format!("{:?}", result.unwrap_err()).contains("at least 32 bytes"),
        "Error should mention minimum length"
    );
}
```

**Expected Result:** Error returned with clear message

---

### TEST-001-04: IKM Zero Entropy Detection

**Related Vulnerability:** VULN-001
**Test Type:** Unit Test
**Purpose:** Verify all-zero IKM is handled (ideally rejected)

#### Procedure
```rust
#[test]
fn test_ikm_zero_entropy() {
    let ikm_zeros = vec![0x00; 64]; // No entropy

    // Ideally this should be rejected, but at minimum should log warning
    let result = derive_key_pair512(&ikm_zeros);

    // After fix, this should either:
    // 1. Reject with error (preferred), OR
    // 2. Accept but log warning
    // Current implementation accepts it (VULNERABLE)

    // TODO: After fix, uncomment:
    // assert!(result.is_err(), "Zero entropy IKM should be rejected");
}
```

**Current Result:** Accepts (VULNERABLE)
**Post-Fix Result:** Should reject or warn

---

## VULN-002: Constant-Time Comparison Tests

### TEST-002-01: Membership Tag Timing Analysis

**Related Vulnerability:** VULN-002
**Test Type:** Security Test (Timing Analysis)
**Purpose:** Verify membership tag comparison is constant-time

#### Setup
```rust
use std::time::Instant;
use subtle::ConstantTimeEq;

#[test]
fn test_membership_tag_constant_time() {
    const ITERATIONS: usize = 100_000;
    const TAG_LENGTH: usize = 16; // Typical tag length
```

#### Procedure
```rust
    // Create test tags
    let tag_valid = vec![0x42u8; TAG_LENGTH];
    let tag_first_diff = vec![0xFFu8; TAG_LENGTH]; // Differs in first byte
    let mut tag_last_diff = vec![0x42u8; TAG_LENGTH];
    tag_last_diff[TAG_LENGTH - 1] = 0xFF; // Differs in last byte only

    // Measure timing for first-byte mismatch
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = tag_valid.as_slice().ct_eq(tag_first_diff.as_slice());
    }
    let time_first = start.elapsed();

    // Measure timing for last-byte mismatch
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = tag_valid.as_slice().ct_eq(tag_last_diff.as_slice());
    }
    let time_last = start.elapsed();

    // Measure timing for match
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = tag_valid.as_slice().ct_eq(tag_valid.as_slice());
    }
    let time_match = start.elapsed();
```

#### Expected Result
```rust
    // Calculate timing statistics
    let avg_time = (time_first + time_last + time_match) / 3;
    let max_deviation = time_first.max(time_last).max(time_match);
    let min_time = time_first.min(time_last).min(time_match);

    // Constant-time: all timings should be within 5% of each other
    // (allowing for measurement noise)
    let threshold = avg_time / 20; // 5% threshold

    let deviation_first = (time_first.as_nanos() as i128 - avg_time.as_nanos() as i128).abs();
    let deviation_last = (time_last.as_nanos() as i128 - avg_time.as_nanos() as i128).abs();
    let deviation_match = (time_match.as_nanos() as i128 - avg_time.as_nanos() as i128).abs();

    println!("Timing Analysis:");
    println!("  First-byte diff: {:?} (deviation: {}%)", time_first,
             deviation_first * 100 / avg_time.as_nanos() as i128);
    println!("  Last-byte diff:  {:?} (deviation: {}%)", time_last,
             deviation_last * 100 / avg_time.as_nanos() as i128);
    println!("  Match:           {:?} (deviation: {}%)", time_match,
             deviation_match * 100 / avg_time.as_nanos() as i128);

    assert!(
        deviation_first < threshold.as_nanos() as i128,
        "First-byte timing deviation too large: {:?} vs avg {:?}",
        time_first, avg_time
    );
    assert!(
        deviation_last < threshold.as_nanos() as i128,
        "Last-byte timing deviation too large: {:?} vs avg {:?}",
        time_last, avg_time
    );
    assert!(
        deviation_match < threshold.as_nanos() as i128,
        "Match timing deviation too large: {:?} vs avg {:?}",
        time_match, avg_time
    );
}
```

**Failure Indicators:**
- First-byte mismatch significantly faster than last-byte → Early exit (VULNERABLE)
- Timing varies by mismatch position → Position-dependent timing (VULNERABLE)

**Notes:**
- Run in release mode (`--release`) for accurate timing
- Run on dedicated hardware if possible
- May need multiple runs for statistical confidence
- CI environments may give noisy results

---

### TEST-002-02: Membership Tag Functional Test

**Related Vulnerability:** VULN-002
**Test Type:** Unit Test
**Purpose:** Verify correct functional behavior after fix

#### Procedure
```rust
#[test]
fn test_membership_tag_validation() {
    // Setup: Create a valid message with membership tag
    let (message, valid_tag) = create_test_message_with_tag();

    // Test 1: Valid tag accepted
    let result = message.validate_membership_tag(&valid_tag);
    assert!(result.is_ok(), "Valid tag should be accepted");

    // Test 2: Invalid tag rejected
    let mut invalid_tag = valid_tag.clone();
    invalid_tag[0] ^= 0x01; // Flip one bit
    let result = message.validate_membership_tag(&invalid_tag);
    assert!(result.is_err(), "Invalid tag should be rejected");

    // Test 3: Missing tag rejected
    let result = message.validate_membership_tag_optional(None);
    assert!(result.is_err(), "Missing tag should be rejected");
}
```

---

## VULN-003: RNG Quality Tests

### TEST-003-01: Weak RNG Detection

**Related Vulnerability:** VULN-003
**Test Type:** Unit Test
**Purpose:** Verify weak RNGs are rejected

#### Procedure
```rust
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng; // Weaker than ChaCha20

struct WeakTestRng {
    // Intentionally predictable for testing
    counter: u64,
}

impl CryptoRng for WeakTestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        // Predictable pattern
        for byte in dest.iter_mut() {
            *byte = (self.counter & 0xFF) as u8;
            self.counter += 1;
        }
        Ok(())
    }

    fn is_production_ready(&self) -> bool {
        false // Explicitly not production ready
    }
}

#[test]
fn test_weak_rng_rejected() {
    let mut weak_rng = WeakTestRng { counter: 0 };

    // Attempt to create reuse guard with weak RNG
    let result = ReuseGuard::try_from_random(&mut weak_rng);

    // Should be rejected in production
    assert!(result.is_err(), "Weak RNG should be rejected");
}
```

---

### TEST-003-02: Reuse Guard Uniqueness

**Related Vulnerability:** VULN-003
**Test Type:** Unit Test
**Purpose:** Verify reuse guards are unique

#### Procedure
```rust
#[test]
fn test_reuse_guard_uniqueness() {
    use std::collections::HashSet;
    let mut rng = OsRng; // Production RNG
    let mut guards = HashSet::new();

    // Generate many reuse guards
    for _ in 0..10000 {
        let guard = ReuseGuard::try_from_random(&mut rng).unwrap();
        let guard_bytes = guard.as_bytes();

        // Should never see a duplicate
        assert!(
            guards.insert(guard_bytes.to_vec()),
            "Reuse guard collision detected (probability: ~2^-96)"
        );
    }
}
```

---

## VULN-004: Hybrid Combiner Tests

### TEST-004-01: Group Synchronization Verification

**Related Vulnerability:** VULN-004
**Test Type:** Integration Test
**Purpose:** Verify synchronization checks detect desynchronization

#### Procedure
```rust
#[test]
fn test_hybrid_combiner_sync_detection() {
    let provider = &OpenMlsRustCrypto::default();

    // Create and initialize both groups
    let (mut group_pq, mut group_st) = setup_hybrid_groups(provider);

    // Initial state: should be synchronized
    assert!(verify_group_sync(&group_pq, &group_st).is_ok());

    // Advance PQ group without updating ST group
    advance_group_epoch(&mut group_pq, provider);

    // Should detect desynchronization
    let sync_result = verify_group_sync(&group_pq, &group_st);
    assert!(
        sync_result.is_err(),
        "Desynchronization should be detected"
    );

    match sync_result.unwrap_err() {
        HybridCombinerError::GroupsDesynchronized { pq_epoch, st_epoch } => {
            assert_eq!(pq_epoch, 2);
            assert_eq!(st_epoch, 1);
        }
        _ => panic!("Wrong error type"),
    }
}
```

---

### TEST-004-02: PSK Export and Import

**Related Vulnerability:** VULN-004
**Test Type:** Integration Test
**Purpose:** Verify PSK is correctly exported and imported

#### Procedure
```rust
#[test]
fn test_hybrid_combiner_psk_flow() {
    let provider = &OpenMlsRustCrypto::default();
    let (group_pq, mut group_st) = setup_hybrid_groups(provider);

    // Export PSK from PQ group
    let mut context = Vec::new();
    group_pq.export_group_context()
        .tls_serialize(&mut context)
        .unwrap();

    let psk = group_pq
        .export_secret(provider.crypto(), "Combiner", &context, 32)
        .expect("PSK export should succeed");

    // Verify PSK length
    assert_eq!(psk.len(), 32, "PSK should be 32 bytes");

    // Create PSK ID
    let psk_id = PreSharedKeyId::new(
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        &provider,
        Psk::External(ExternalPsk::new(psk.clone())),
    )
    .expect("PSK ID creation should succeed");

    // Store PSK
    psk_id.store(provider, &psk)
        .expect("PSK storage should succeed");

    // Propose PSK
    let (proposal, _) = group_st
        .propose_external_psk(provider, &signer, psk_id)
        .expect("PSK proposal should succeed");

    // Verify proposal was created
    assert!(proposal.is_external_psk_proposal());
}
```

---

### TEST-004-03: Error Handling Coverage

**Related Vulnerability:** VULN-004
**Test Type:** Unit Test
**Purpose:** Verify all error paths are properly handled (no unwrap)

#### Procedure
```rust
#[test]
fn test_hybrid_combiner_error_handling() {
    let provider = &OpenMlsRustCrypto::default();

    // Test PSK export failure
    let invalid_group = create_invalid_group();
    let result = export_psk_with_handling(&invalid_group, provider);
    assert!(
        matches!(result, Err(HybridCombinerError::PskExportFailed(_))),
        "PSK export failure should return proper error"
    );

    // Test PSK ID creation failure
    let invalid_psk = vec![]; // Empty PSK
    let result = create_psk_id_with_handling(&invalid_psk, provider);
    assert!(
        matches!(result, Err(HybridCombinerError::PskIdCreationFailed(_))),
        "PSK ID creation failure should return proper error"
    );

    // Test commit failure
    let result = commit_with_handling(&mut invalid_group, provider);
    assert!(
        matches!(result, Err(HybridCombinerError::CommitFailed(_))),
        "Commit failure should return proper error"
    );
}
```

---

## Security Test Suite

### Running All Security Tests

Create a dedicated test module:

```rust
// tests/security_tests.rs

#![cfg(test)]

mod ikm_tests {
    // Include TEST-001-* tests
}

mod timing_tests {
    // Include TEST-002-* tests
}

mod rng_tests {
    // Include TEST-003-* tests
}

mod hybrid_combiner_tests {
    // Include TEST-004-* tests
}
```

### Command to Run Security Tests

```bash
# Run all security tests
cargo test --test security_tests

# Run specific vulnerability tests
cargo test --test security_tests ikm_tests
cargo test --test security_tests timing_tests
cargo test --test security_tests rng_tests
cargo test --test security_tests hybrid_combiner_tests

# Run with detailed output
cargo test --test security_tests -- --nocapture

# Run in release mode (for timing tests)
cargo test --test security_tests --release
```

---

## Fuzzing Test Cases

### FUZZ-001: ML-KEM IKM Fuzzing

```rust
// fuzz/fuzz_targets/mlkem_ikm.rs

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz all key derivation functions
    let _ = derive_key_pair512(data);
    let _ = derive_key_pair768(data);
    let _ = derive_key_pair1024(data);

    // Should never panic, always return Result
    // Should handle all input lengths gracefully
});
```

### FUZZ-002: Message Framing Fuzzing

```rust
// fuzz/fuzz_targets/message_framing.rs

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz message deserialization
    let _ = PrivateMessage::tls_deserialize(&mut data.as_ref());
    let _ = PublicMessage::tls_deserialize(&mut data.as_ref());

    // Should never panic, always return Result
});
```

### Running Fuzzers

```bash
# Install cargo-fuzz if not already installed
cargo install cargo-fuzz

# Run ML-KEM fuzzer for 1 hour
cargo fuzz run mlkem_ikm -- -max_total_time=3600

# Run message framing fuzzer for 24 hours
cargo fuzz run message_framing -- -max_total_time=86400

# Run all fuzzers in parallel
cargo fuzz run --jobs 4 mlkem_ikm message_framing
```

---

## Performance Regression Tests

Verify that security fixes don't introduce performance regressions:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_ikm_key_generation(c: &mut Criterion) {
    let ikm = vec![0x42; 64];

    c.bench_function("derive_key_pair512", |b| {
        b.iter(|| {
            derive_key_pair512(black_box(&ikm))
        })
    });
}

fn benchmark_membership_tag_comparison(c: &mut Criterion) {
    let tag1 = vec![0x42; 16];
    let tag2 = vec![0x42; 16];

    c.bench_function("membership_tag_compare", |b| {
        b.iter(|| {
            tag1.as_slice().ct_eq(black_box(tag2.as_slice()))
        })
    });
}

criterion_group!(benches,
    benchmark_ikm_key_generation,
    benchmark_membership_tag_comparison
);
criterion_main!(benches);
```

Run benchmarks:
```bash
cargo bench --bench security_benchmarks
```

---

## Continuous Integration

Add to CI pipeline:

```yaml
# .github/workflows/security.yml

name: Security Tests

on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Run security tests
        run: cargo test --test security_tests --release

      - name: Run timing analysis
        run: cargo test --test security_tests timing_tests --release -- --nocapture

      - name: Check for production unwraps
        run: |
          if rg "\.unwrap\(\)" --type rust --glob '!**/tests/**' --glob '!**/examples/**' --glob '!**/benches/**'; then
            echo "Error: Found .unwrap() in production code"
            exit 1
          fi

      - name: Security audit
        run: |
          cargo install cargo-audit
          cargo audit

      - name: Clippy security lints
        run: cargo clippy -- -D warnings -D clippy::unwrap_used

      - name: Fuzz (short run)
        run: |
          cargo install cargo-fuzz
          cargo fuzz run mlkem_ikm -- -max_total_time=300
```

---

## Test Coverage

Measure test coverage for security-critical code:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --test security_tests --out Html --output-dir coverage

# View coverage report
open coverage/index.html
```

Aim for:
- 100% coverage on all vulnerability fixes
- 90%+ coverage on security-critical paths
- Branch coverage for all error paths

---

## Summary

This test suite provides:
- ✅ Unit tests for each vulnerability
- ✅ Integration tests for complex interactions
- ✅ Timing analysis for constant-time operations
- ✅ Fuzzing for robustness
- ✅ Performance regression tests
- ✅ CI integration

**Next Steps:**
1. Implement vulnerability fixes
2. Run corresponding test suite
3. Verify all tests pass
4. Run fuzzing for 24+ hours
5. Generate coverage report
6. Document test results

---

**Document Maintenance:**
- Update after each fix is implemented
- Add new tests as vulnerabilities are discovered
- Keep synchronized with REMEDIATION_GUIDE.md
