CREATE TABLE IF NOT EXISTS SCAP_Scores (
    SCAP_Score_ID INTEGER PRIMARY KEY,
    Score INTEGER NOT NULL,
    Hardware_ID INTEGER NOT NULL,
    FindingSourceFile_ID INTEGER NOT NULL,
    VulnerabilitySource_ID INTEGER NOT NULL,
    ScanDate DATETIME NOT NULL,
    UNIQUE (
           Hardware_ID,
           FindingSourceFile_ID,
           VulnerabilitySource_ID
       ) ON CONFLICT IGNORE,
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
    FOREIGN KEY (FindingSourceFile_ID) REFERENCES UniqueFindingsSourceFiles(FindingSourceFile_ID),
    FOREIGN KEY (VulnerabilitySource_ID) REFERENCES VulnerabilitySources(VulnerabilitySource_ID)
);