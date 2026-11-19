CREATE TABLE IF NOT EXISTS StigSubmissions (
    StigSubmission_ID INTEGER PRIMARY KEY,
    FindingType NVARCHAR (25) NOT NULL,
    SourceName NVARCHAR (100) NOT NULL,
    SourceVersion NVARCHAR (25),
    SourceRelease NVARCHAR (25),
    BenchmarkDate DATETIME,
    DiscoveredHostName NVARCHAR (50),
    FindingSourceFileName NVARCHAR (500),
    ImportedOn DATETIME NOT NULL,
    UNIQUE (FindingSourceFileName, DiscoveredHostName, SourceName) ON CONFLICT REPLACE
);