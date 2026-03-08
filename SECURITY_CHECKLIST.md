# MLS Security Vulnerability Quick Reference

**Last Updated:** 2026-03-08
**Related Documents:** SECURITY_ASSESSMENT.md, REMEDIATION_GUIDE.md

This document provides a quick reference for the identified vulnerabilities and their remediation status.

---

## Critical Vulnerabilities (P0)

### 🔴 VULN-001: IKM Entropy Handling
- **File:** `/hpke-rs/src/mlkem_kem.rs:19-28`
- **Severity:** HIGH (CVSS 7.5)
- **Impact:** Predictable ML-KEM keys if IKM is weak or reused
- **Status:** ❌ NOT FIXED
- **Fix Effort:** 4-8 hours
- **Fix Summary:** Use HKDF on full IKM, add entropy validation
- **Dependencies:** Add `hkdf` and `sha2` crates
- **Testing Required:** IKM length tests, determinism tests, test vector updates

### 🔴 VULN-002: Non-Constant-Time Membership Tag Comparison
- **File:** `/openmls/openmls/src/framing/public_message_in.rs:159-160`
- **Severity:** MEDIUM-HIGH (CVSS 6.5)
- **Impact:** Timing side channel can leak membership information
- **Status:** ❌ NOT FIXED (Known issue with TODO comment)
- **Fix Effort:** 2-4 hours
- **Fix Summary:** Replace `!=` with `ConstantTimeEq::ct_eq()`
- **Dependencies:** `subtle` crate (should already be available)
- **Testing Required:** Timing analysis, functional regression tests

---

## High Priority Vulnerabilities (P1)

### 🟡 VULN-003: Reuse Guard RNG Quality
- **File:** `/openmls/openmls/src/framing/private_message.rs:178-179`
- **Severity:** MEDIUM (CVSS 5.5)
- **Impact:** Weak RNG → predictable reuse guards → nonce reuse → AEAD break
- **Status:** ❌ NOT FIXED
- **Fix Effort:** 4-6 hours
- **Fix Summary:** Add RNG validation, improve error handling
- **Dependencies:** None (trait modification)
- **Testing Required:** RNG quality tests, error path tests

### 🟡 VULN-004: Hybrid Combiner Synchronization
- **File:** `/app/src/lib.rs:166+`
- **Severity:** MEDIUM (CVSS 5.0)
- **Impact:** Group desynchronization → undefined security properties
- **Status:** ❌ NOT FIXED
- **Fix Effort:** 8-16 hours
- **Fix Summary:** Add sync checks, replace .unwrap(), add recovery
- **Dependencies:** None (requires new error types)
- **Testing Required:** Synchronization tests, error injection tests

---

## Medium Priority Issues (P2)

### 🟢 ISSUE-001: Generic Decryption Errors
- **Files:** Multiple, e.g., `/openmls/openmls/src/treesync/treekem.rs:139`
- **Severity:** LOW-MEDIUM
- **Impact:** Hidden attack patterns, difficult debugging
- **Status:** ❌ NOT FIXED
- **Fix Effort:** 16-24 hours
- **Fix Summary:** Add internal logging before genericizing errors

### 🟢 ISSUE-002: Credential Validation Delegation
- **File:** `/openmls/openmls/src/credentials/mod.rs:165`
- **Severity:** LOW-MEDIUM
- **Impact:** Applications may fail to validate credentials properly
- **Status:** ❌ NOT FIXED (By design, but needs better defaults)
- **Fix Effort:** 8-12 hours
- **Fix Summary:** Provide secure default validator, improve docs

### 🟢 ISSUE-003: Parallel Encryption Timing
- **File:** `/openmls/openmls/src/treesync/treekem.rs:74-77`
- **Severity:** LOW
- **Impact:** Potential timing side channels from parallel operations
- **Status:** ❌ NOT ANALYZED
- **Fix Effort:** 8-16 hours
- **Fix Summary:** Security review of Rayon usage

---

## Remediation Priority Order

### Phase 1: Critical Fixes (Week 1-2)
1. ✅ **VULN-001:** Fix IKM entropy handling
2. ✅ **VULN-002:** Fix constant-time comparison
3. ✅ Run security test suite
4. ✅ Update test vectors

### Phase 2: High Priority (Week 3-4)
5. ✅ **VULN-003:** Add RNG validation
6. ✅ **VULN-004:** Fix hybrid combiner
7. ✅ Fuzzing campaign (24+ hours)
8. ✅ Code review

### Phase 3: Medium Priority (Week 5-6)
9. ✅ **ISSUE-001:** Improve error handling
10. ✅ **ISSUE-002:** Add credential validators
11. ✅ **ISSUE-003:** Analyze parallel encryption
12. ✅ Remove all production `.unwrap()`

### Phase 4: Validation (Week 7-8)
13. ✅ Third-party security audit
14. ✅ Penetration testing
15. ✅ Performance regression testing
16. ✅ Documentation updates

### Phase 5: Deployment (Week 9+)
17. ✅ Staging deployment
18. ✅ Production readiness review
19. ✅ Monitoring setup
20. ✅ Production deployment

---

## Quick Test Commands

```bash
# Run all tests
cargo test --all

# Run security-specific tests
cargo test --test security_tests

# Run fuzzer (ML-KEM operations)
cargo fuzz run mlkem_operations -- -max_total_time=86400

# Check for vulnerable dependencies
cargo audit

# Run clippy with security lints
cargo clippy -- -D warnings -D clippy::unwrap_used

# Check for production unwraps
rg "\.unwrap\(\)" --type rust --glob '!**/tests/**' --glob '!**/examples/**'

# Run timing analysis
cargo test test_membership_tag_comparison_timing --release
```

---

## Pre-Production Checklist

### Code Quality
- [ ] All P0 vulnerabilities fixed
- [ ] All P1 vulnerabilities fixed
- [ ] No `.unwrap()` in production paths
- [ ] No `.expect()` in production paths
- [ ] All TODOs related to security addressed
- [ ] All FIXMEs related to security addressed

### Testing
- [ ] Security test suite: PASS
- [ ] Integration tests: PASS
- [ ] Fuzzing (24h+): NO CRASHES
- [ ] Timing analysis: NO LEAKS
- [ ] Performance regression: ACCEPTABLE
- [ ] Backward compatibility: VERIFIED or MIGRATION PLAN

### Review
- [ ] Internal code review: COMPLETE
- [ ] Security expert review: COMPLETE
- [ ] Third-party audit: COMPLETE
- [ ] Audit findings: REMEDIATED

### Documentation
- [ ] Security policy: PUBLISHED
- [ ] Vulnerability disclosure: PUBLISHED
- [ ] API documentation: UPDATED
- [ ] Migration guide: PREPARED (if breaking changes)
- [ ] Deployment guide: UPDATED

### Operations
- [ ] Monitoring: CONFIGURED
- [ ] Logging: CONFIGURED
- [ ] Alerts: CONFIGURED
- [ ] Incident response: DOCUMENTED
- [ ] Rollback plan: PREPARED
- [ ] Support contacts: PUBLISHED

---

## Tracking & Reporting

### Status Tracking
Track remediation status in your issue tracker with labels:
- `security-critical` (P0)
- `security-high` (P1)
- `security-medium` (P2)

### Progress Metrics
- **Critical Vulnerabilities:** 0/2 fixed (0%)
- **High Priority:** 0/2 fixed (0%)
- **Medium Priority:** 0/3 fixed (0%)
- **Overall Progress:** 0/7 fixed (0%)

### Report Updates
Update this document after each vulnerability is fixed:
1. Change status from ❌ to ✅
2. Update progress metrics
3. Add verification results
4. Commit with message: `security: Fix VULN-XXX - [description]`

---

## Contact Information

### Security Issues
- **Report privately:** [security contact email/form]
- **Response time:** 48 hours for critical, 7 days for others
- **Disclosure policy:** 90 days after fix release

### Questions
- GitHub Issues: [repository URL]/issues
- Security Mailing List: [if applicable]
- Chat: [if applicable]

---

## Additional Notes

### Known Limitations
1. **ML-KEM implementations:** Using pre-release RustCrypto versions from git
2. **Hybrid combiner:** Experimental, needs formal analysis
3. **Timing analysis:** Manual testing only, automated tools recommended

### Future Work
1. Formal verification of key security properties
2. Hardware security module (HSM) integration
3. FIPS 140-3 certification path
4. Post-quantum signature schemes (ML-DSA improvements)

---

**Document Version:** 1.0
**Next Review:** After each vulnerability fix or every 2 weeks
**Maintainer:** Security team
