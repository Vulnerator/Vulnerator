CREATE TABLE IF NOT EXISTS VulnerabilitiesIA_Controls (
    Vulnerability_IA_Control_ID INTEGER PRIMARY KEY,
    Vulnerability_ID INTEGER NOT NULL,
    IA_Control_ID INTEGER NOT NULL,
    UNIQUE (Vulnerability_ID, IA_Control_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
    FOREIGN KEY (IA_Control_ID) REFERENCES IA_Controls(IA_Control_ID)
);