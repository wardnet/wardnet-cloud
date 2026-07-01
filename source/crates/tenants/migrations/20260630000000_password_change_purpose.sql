-- Allow the new `password_change` verification-code purpose (authenticated
-- set/change password via POST /v1/me/password). The original CHECK constraint
-- (20260629000000) enumerated only signup / password_reset / enrollment, so an
-- insert with the new purpose fails. Widen the constraint to include it.
ALTER TABLE enrollment_codes
    DROP CONSTRAINT enrollment_codes_purpose_check;
ALTER TABLE enrollment_codes
    ADD CONSTRAINT enrollment_codes_purpose_check
    CHECK (purpose IN ('signup', 'password_reset', 'password_change', 'enrollment'));
