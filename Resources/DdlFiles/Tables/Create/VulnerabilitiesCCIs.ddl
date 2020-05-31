CREATE TABLE IF NOT EXISTS VulnerabilitiesCCIs (
    VulnerabilityCCI_ID INTEGER PRIMARY KEY,
    Vulnerability_ID INTEGER NOT NULL,
    CCI_ID INTEGER NOT NULL,
    UNIQUE (Vulnerability_ID, CCI_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
    FOREIGN KEY (CCI_ID) REFERENCES CCIs(CCI_ID)
);