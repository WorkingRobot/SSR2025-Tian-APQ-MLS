# MLS Post-Quantum Security Vulnerability Assessment

**Assessment Date:** 2026-03-08
**Repository:** SSR2025-Tian-APQ-MLS
**Assessed By:** Security Analysis Agent
**Assessment Scope:** OpenMLS fork with post-quantum cryptographic enhancements

## Executive Summary

This document provides a comprehensive security vulnerability assessment of a post-quantum enhanced fork of OpenMLS (RFC 9420 MLS protocol implementation). The codebase adds support for ML-KEM (FIPS 203) and hybrid cryptographic schemes to the standard OpenMLS implementation.

**Overall Risk Level:** **MEDIUM-HIGH**

The implementation demonstrates good security practices in many areas, but several critical vulnerabilities require immediate attention before production deployment.

---

## 1. Repository Structure

### 1.1 Overview

This repository is a fork of OpenMLS that adds post-quantum (PQ) cryptographic capabilities:

- **Base:** OpenMLS - RFC 9420 MLS protocol implementation in Rust
- **HPKE Module:** Modified HPKE-RS with post-quantum KEM support (`hpke-rs/`)
- **OpenMLS Core:** Protocol implementation (`openmls/openmls/src/`)
- **Application:** Test application and benchmarks (`app/`)

### 1.2 Key Components

```
Repository Root
├── hpke-rs/                    # HPKE with PQ KEM support
│   ├── src/mlkem_kem.rs       # ML-KEM integration (CRITICAL)
│   └── traits/                # Crypto provider traits
├── openmls/openmls/src/
│   ├── ciphersuite/           # Crypto primitives
│   ├── framing/               # Message encryption/decryption (CRITICAL)
│   ├── group/                 # Group management
│   ├── treesync/              # Tree-based key management
│   ├── schedule/              # Key schedule and secrets
│   ├── key_packages/          # Key package generation/validation
│   └── credentials/           # Identity credentials
└── app/                       # Benchmark application with hybrid combiner
```

---

## 2. Post-Quantum Modifications

### 2.1 Supported Ciphersuites

The implementation adds support for multiple post-quantum and hybrid ciphersuites beyond the standard OpenMLS offerings:

#### Pure Post-Quantum Ciphersuites
- MLKEM512_Ed25519
- MLKEM768_Ed25519
- MLKEM1024_Ed25519
- MLKEM512_P256
- MLKEM768_P256
- MLKEM1024_P384
- MLKEM512_MLDSA44
- MLKEM768_MLDSA65
- MLKEM1024_MLDSA87
- XWing_Ed25519

#### Hybrid Combiners
- MLKEM768_CHA_Ed25519/X25519_CHA_Ed25519
- MLKEM768_CHA_MLDSA65/X25519_CHA_Ed25519
- Multiple other hybrid combinations

### 2.2 Cryptographic Dependencies

- **ML-KEM:** RustCrypto KEMs (https://github.com/RustCrypto/KEMs.git)
- **X-Wing:** RustCrypto KEMs (https://github.com/RustCrypto/KEMs.git)
- **Base Crypto:** RustCrypto ecosystem (AEAD, signatures, hashes)

**Note:** The implementation uses pre-release versions from git. Verify that these versions have been audited and are production-ready.

---

## 3. Critical Vulnerabilities

### 3.1 VULNERABILITY #1: IKM Entropy Handling in ML-KEM Key Generation

**Severity:** 🔴 **HIGH**
**Location:** `/hpke-rs/src/mlkem_kem.rs:19-28`
**CVSS Score:** 7.5 (High)

#### Description

The ML-KEM key generation uses a deterministic RNG seeded from Input Key Material (IKM), but only uses the first 32 bytes of the IKM, discarding any additional entropy. There is no validation of IKM quality or entropy content.

#### Vulnerable Code

```rust
fn create_rng_from_ikm(ikm: &[u8]) -> Result<ChaChaRng, Error> {
    if ikm.len() < 32 {
        return Err(Error::CryptoLibraryError(
            "IKM must be at least 32 bytes long".into()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&ikm[0..32]);  // ⚠️ Only uses first 32 bytes
    Ok(ChaChaRng::from_seed(seed))      // ⚠️ Deterministic RNG
}
```

This function is used by:
- `derive_key_pair512()` (line 224)
- `derive_key_pair768()` (line 239)
- `derive_key_pair1024()` (line 254)
- `encaps()` (line 37)

#### Security Impact

1. **Entropy Truncation:** If IKM contains more than 32 bytes of entropy, the excess is discarded
2. **Deterministic Key Generation:** If IKM is reused or predictable, generated keypairs become deterministic
3. **No Validation:** No check for minimum entropy quality in the input IKM
4. **Replay Risk:** If IKM is reused across sessions, the same keypairs will be generated

#### Attack Scenarios

**Scenario 1: Low Entropy IKM**
- Attacker influences IKM generation to have low entropy
- Generated ML-KEM keypairs have reduced security margin
- Potential for key recovery through brute force

**Scenario 2: IKM Reuse**
- Application accidentally reuses IKM values
- Same keypairs are generated across sessions
- Complete loss of forward secrecy

**Scenario 3: Predictable IKM**
- IKM derived from predictable sources (timestamps, counters)
- Attacker can predict future keypairs
- Precomputation attacks become possible

#### Recommendations

**Immediate Actions:**
1. **Add entropy validation:** Implement minimum entropy checks on IKM
2. **Use KDF on full IKM:** Instead of truncating, use a KDF (e.g., HKDF) to process the entire IKM
3. **Add uniqueness checks:** Ensure IKM is not reused
4. **Documentation:** Clearly document IKM requirements (minimum 256 bits of entropy)

**Proposed Fix:**
```rust
fn create_rng_from_ikm(ikm: &[u8]) -> Result<ChaChaRng, Error> {
    if ikm.len() < 32 {
        return Err(Error::CryptoLibraryError(
            "IKM must be at least 32 bytes long".into()
        ));
    }

    // Use HKDF to process full IKM instead of truncating
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut seed = [0u8; 32];
    hk.expand(b"ML-KEM RNG Seed", &mut seed)
        .map_err(|_| Error::CryptoLibraryError("HKDF expansion failed".into()))?;

    Ok(ChaChaRng::from_seed(seed))
}
```

---

### 3.2 VULNERABILITY #2: Non-Constant-Time Membership Tag Comparison

**Severity:** 🔴 **MEDIUM-HIGH**
**Location:** `/openmls/openmls/src/framing/public_message_in.rs:159-160`
**CVSS Score:** 6.5 (Medium)

#### Description

The membership tag verification uses a non-constant-time comparison, which can leak information about the tag value through timing side channels. This is a known issue marked with a TODO comment.

#### Vulnerable Code

```rust
// Line 159-160
// TODO #133: make this a constant-time comparison
if membership_tag != expected_membership_tag {
    return Err(ValidationError::InvalidMembershipTag);
}
```

#### Security Impact

1. **Timing Side Channel:** Attacker can measure comparison timing to learn about tag bytes
2. **Tag Forgery:** With enough measurements, attacker may forge valid membership tags
3. **Group Membership Leak:** Timing differences may reveal group membership information

#### Attack Scenario

**Remote Timing Attack:**
1. Attacker sends crafted messages with modified membership tags
2. Measures response times for validation failures
3. Uses timing information to gradually recover valid tag bytes
4. Eventually forges valid membership tags to impersonate group members

#### Recommendations

**Immediate Action:**
Replace the comparison with a constant-time implementation.

**Proposed Fix:**
```rust
use subtle::ConstantTimeEq;

// Constant-time comparison
if membership_tag.ct_eq(expected_membership_tag).unwrap_u8() == 0 {
    return Err(ValidationError::InvalidMembershipTag);
}
```

---

### 3.3 VULNERABILITY #3: Reuse Guard RNG Quality

**Severity:** 🟡 **MEDIUM**
**Location:** `/openmls/openmls/src/framing/private_message.rs:178-179`
**CVSS Score:** 5.5 (Medium)

#### Description

The reuse guard is generated using a RNG provided by the caller, but there's no explicit validation that the RNG is cryptographically secure, particularly for post-quantum ciphersuites.

#### Vulnerable Code

```rust
// Line 178-179
let reuse_guard: ReuseGuard =
    ReuseGuard::try_from_random(rand).map_err(LibraryError::unexpected_crypto_error)?;
```

#### Security Impact

1. **Weak RNG:** If the RNG provider is weak, reuse guards may be predictable
2. **Nonce Reuse Risk:** Predictable reuse guards can lead to nonce reuse
3. **AEAD Compromise:** Nonce reuse in AEAD schemes (AES-GCM, ChaCha20Poly1305) breaks confidentiality

#### Recommendations

1. **Validate RNG Quality:** Add runtime checks for RNG quality
2. **Documentation:** Clearly document RNG requirements for all ciphersuites
3. **Fail Closed:** If RNG quality is uncertain, fail rather than continue
4. **Error Visibility:** Improve error handling to not hide RNG failures behind `unexpected_crypto_error`

---

### 3.4 VULNERABILITY #4: Hybrid Combiner Synchronization

**Severity:** 🟡 **MEDIUM**
**Location:** `/app/src/lib.rs:166+`
**CVSS Score:** 5.0 (Medium)

#### Description

The hybrid combiner implementation maintains two parallel MLS groups (one post-quantum, one standard) and synchronizes them via PSK export. If these groups become desynchronized, security guarantees may be violated.

#### Implementation Details

```rust
// Line 287-302
// Export PSK from PQ group
let combiner_psk = group_pq
    .export_secret(provider.crypto(), "Combiner", &mut w, 32)
    .unwrap();

// Inject into standard group
let psk_id = PreSharedKeyId::new(
    cs_st,
    &rng,
    openmls::schedule::Psk::External(openmls::schedule::psk::ExternalPsk::new(
        combiner_psk.clone(),
    )),
)
.unwrap();

psk_id.store(provider, &combiner_psk.as_slice()).unwrap();
```

#### Security Concerns

1. **Synchronization Risk:** Two groups must progress in lockstep
2. **Timing Issues:** PSK must be exported before it's used in ST group
3. **Error Handling:** Extensive use of `.unwrap()` hides potential failures
4. **Complexity:** More attack surface due to dual-group management

#### Attack Scenarios

**Scenario 1: Desynchronization Attack**
- Attacker selectively drops messages to one group
- Groups fall out of sync
- Security properties become undefined

**Scenario 2: PSK Timing Attack**
- Attacker delays PSK export/import
- Standard group uses incorrect PSK
- Potential for authentication bypass

#### Recommendations

1. **Add explicit synchronization checks:** Verify both groups are at matching states
2. **Implement recovery mechanisms:** Handle desynchronization gracefully
3. **Improve error handling:** Replace `.unwrap()` with proper error propagation
4. **Formal verification:** Prove synchronization properties hold under adversarial conditions

---

## 4. Medium Priority Issues

### 4.1 Generic Decryption Error Handling

**Location:** `/openmls/openmls/src/treesync/treekem.rs:139`
**Severity:** 🟡 **LOW-MEDIUM**

All decryption failures map to a generic `UnableToDecrypt` error, which may hide attack patterns and make debugging difficult.

**Recommendation:** Add internal logging of specific failure reasons for security monitoring while maintaining generic external errors.

---

### 4.2 Credential Validation Delegation

**Location:** `/openmls/openmls/src/credentials/mod.rs:165`
**Severity:** 🟡 **LOW-MEDIUM**

OpenMLS delegates credential validation to the application layer. If applications fail to properly validate credentials, malicious credentials could be accepted.

**Recommendation:** Provide secure default validators and clear documentation on proper credential validation.

---

### 4.3 Parallel Encryption Timing Side Channels

**Location:** `/openmls/openmls/src/treesync/treekem.rs:74-77`
**Severity:** 🟡 **LOW**

The implementation uses Rayon for parallel encryption of path secrets. This parallelization could introduce timing side channels.

**Recommendation:** Security review of parallel operations to ensure constant-time properties are maintained.

---

## 5. Positive Security Practices

The codebase demonstrates several good security practices:

### 5.1 Code Safety
- ✅ `#![forbid(unsafe_code)]` in HPKE module prevents memory unsafety
- ✅ Extensive use of type safety and Rust's ownership model

### 5.2 Cryptographic Hygiene
- ✅ Zeroization of private keys using `#[zeroize(drop)]`
- ✅ Constant-time comparison attempted in several areas
- ✅ TLS codec prevents many deserialization vulnerabilities

### 5.3 Validation
- ✅ Extensive validation checks with "ValSem" markers
- ✅ Structured error handling in many areas
- ✅ Input validation on cryptographic operations

---

## 6. Testing and Validation Recommendations

### 6.1 Security Testing

**Recommended Tests:**
1. **Entropy Testing:** Verify IKM entropy requirements
2. **Timing Analysis:** Profile all cryptographic comparisons for timing leaks
3. **Fuzzing:** Fuzz deserialization and crypto operations
4. **State Machine Testing:** Verify group state transitions
5. **Synchronization Testing:** Test hybrid combiner under adversarial conditions

### 6.2 Code Review

**Focus Areas:**
1. All uses of `.unwrap()` and `.expect()` in production code
2. Error handling paths that might hide crypto failures
3. RNG usage throughout the codebase
4. All TODO and FIXME comments

---

## 7. Compliance and Standards

### 7.1 RFC 9420 Compliance

The base OpenMLS implementation is designed for RFC 9420 compliance. The post-quantum extensions should maintain this compliance for standard ciphersuites.

### 7.2 NIST Standards

- ML-KEM: Aligned with FIPS 203
- Signature schemes: Should align with NIST standards

**Recommendation:** Verify that the RustCrypto ML-KEM implementation is FIPS 203 compliant.

---

## 8. Deployment Recommendations

### 8.1 Before Production Deployment

**Critical Actions:**
1. ✅ Fix IKM entropy handling (Vulnerability #1)
2. ✅ Implement constant-time membership tag comparison (Vulnerability #2)
3. ✅ Add RNG quality validation (Vulnerability #3)
4. ✅ Security audit of hybrid combiner (Vulnerability #4)
5. ✅ Replace all `.unwrap()` in production paths with proper error handling
6. ✅ Third-party cryptographic audit
7. ✅ Penetration testing focused on timing side channels

### 8.2 Operational Security

**Recommendations:**
1. **Monitoring:** Log cryptographic failures for security monitoring
2. **Key Rotation:** Implement aggressive key rotation schedules
3. **Incident Response:** Prepare incident response procedures for crypto failures
4. **Vulnerability Disclosure:** Establish security policy and disclosure process

---

## 9. Summary of Risk Assessment

| Vulnerability | Severity | Impact | Likelihood | Priority |
|--------------|----------|---------|------------|----------|
| IKM Entropy Handling | HIGH | High | Medium | P0 - Critical |
| Non-Constant-Time Comparison | MEDIUM-HIGH | Medium | Medium | P0 - Critical |
| Reuse Guard RNG Quality | MEDIUM | Medium | Low | P1 - High |
| Hybrid Combiner Sync | MEDIUM | Medium | Low | P1 - High |
| Generic Error Handling | LOW-MEDIUM | Low | Medium | P2 - Medium |
| Credential Validation | LOW-MEDIUM | Medium | Low | P2 - Medium |

---

## 10. Conclusion

This post-quantum enhanced OpenMLS implementation demonstrates sophisticated cryptographic engineering with many good security practices. However, several critical vulnerabilities require immediate attention:

1. **The IKM entropy handling issue (Vulnerability #1)** is the most serious concern and could lead to predictable keys if IKM quality is not ensured.

2. **The non-constant-time membership tag comparison (Vulnerability #2)** creates a known timing side channel that must be fixed.

3. **The hybrid combiner design (Vulnerability #4)** adds significant complexity that needs careful validation and formal analysis.

**Overall Assessment:** The codebase is **NOT READY FOR PRODUCTION** in its current state. With proper remediation of the identified vulnerabilities, particularly the critical IKM handling issue, this could become a robust post-quantum MLS implementation.

**Recommended Timeline:**
- **Week 1-2:** Fix Vulnerabilities #1 and #2 (Critical)
- **Week 3-4:** Address Vulnerabilities #3 and #4 (High Priority)
- **Week 5-6:** Security audit and penetration testing
- **Week 7-8:** Remediation of audit findings
- **Week 9+:** Production readiness evaluation

---

## 11. References

1. RFC 9420 - The Messaging Layer Security (MLS) Protocol
2. NIST FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism Standard
3. RustCrypto KEMs: https://github.com/RustCrypto/KEMs
4. OpenMLS Documentation: https://book.openmls.tech
5. OWASP Cryptographic Storage Cheat Sheet
6. NIST SP 800-90A/B/C - Recommendations for Random Number Generation

---

**Document Version:** 1.0
**Last Updated:** 2026-03-08
**Next Review:** 2026-03-22 (or upon significant code changes)
