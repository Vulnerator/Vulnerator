CREATE TABLE IF NOT EXISTS SecurityAssessmentProcedures (
    SecurityAssessmentProcedure_ID INTEGER PRIMARY KEY,
    Scope NVARCHAR (50) NOT NULL,
    TestConfiguration NVARCHAR (2000) NOT NULL,
    LogisticsSupport NVARCHAR (1000) NOT NULL,
    Security NVARCHAR (1000) NOT NULL
);