CREATE TABLE IF NOT EXISTS AdditionalTestConsiderations (
    AdditionalTestConsideration_ID INTEGER PRIMARY KEY,
    AdditionalTestConsiderationTitle NVARCHAR (25) NOT NULL,
    AdditionalTestConsiderationDetails NVARCHAR (1000) NOT NULL
);