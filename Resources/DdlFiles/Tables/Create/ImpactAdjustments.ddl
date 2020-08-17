CREATE TABLE IF NOT EXISTS ImpactAdjustments (
    ImpactAdjustment_ID INTEGER PRIMARY KEY,
    AdjustedConfidentiality NVARCHAR (25),
    AdjustedConfidentialityJustification NVARCHAR (200),
    AdjustedIntegrity NVARCHAR (25),
    AdjustedIntegrityJustification NVARCHAR (200),
    AdjustedAvailability NVARCHAR (25),
    AdjustedAvailabilityJustification NVARCHAR (200)
);