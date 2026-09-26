-- 0030_enrollment_claim_failures.sql
--
-- WHY: the claim form is the one place a short code selects a row. Ten wrong
-- codes lock that device id until the device announces again, which is the
-- only event the real hardware can produce and a remote guesser cannot.
-- The counter lives on every row for the id and the form takes the worst,
-- so a squatter row cannot hide a locked real row.

ALTER TABLE device_enrollments
    ADD COLUMN claim_failures INTEGER NOT NULL DEFAULT 0;

ALTER TABLE device_enrollments
    ADD CONSTRAINT device_enrollments_claim_failures_nonneg
        CHECK (claim_failures >= 0);
