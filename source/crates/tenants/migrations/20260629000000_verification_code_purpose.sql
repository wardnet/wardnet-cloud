-- PR3 (#18 / #20): bind every one-time code to the flow it was issued for, so a
-- password_reset code can never be replayed against signup (web or daemon) and
-- vice-versa. The existing tenant_id column keeps its orthogonal daemon meaning
-- (NULL = new-signup, set = add-daemon); `purpose` is the flow binding.

-- Pre-purpose rows are ambiguous (a tenant_id-NULL row could have been a web signup,
-- a password reset, or a daemon new-signup) — and they are single-use codes with a
-- ~300s TTL. Rather than relabel them (which would mislabel an in-flight reset/signup
-- as daemon-enrollable, the exact cross-purpose this PR forbids), clear them: any
-- holder simply re-requests a fresh, purpose-bound code. The per-IP rate-limit log
-- (enrollment_code_log) is untouched.
DELETE FROM enrollment_codes;

ALTER TABLE enrollment_codes
    ADD COLUMN purpose VARCHAR(20) NOT NULL
    CHECK (purpose IN ('signup', 'password_reset', 'enrollment'));
