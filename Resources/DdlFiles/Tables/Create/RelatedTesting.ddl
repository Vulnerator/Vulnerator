CREATE TABLE IF NOT EXISTS RelatedTesting (
    RelatedTesting_ID INTEGER PRIMARY KEY,
    TestTitle NVARCHAR (200) NOT NULL,
    DateConducted DATETIME NOT NULL,
    RelatedSystemTested NVARCHAR (200) NOT NULL,
    ResponsibleOrganization NVARCHAR (200) NOT NULL,
    TestingImpact NVARCHAR (500) NOT NULL
);