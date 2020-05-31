CREATE TABLE IF NOT EXISTS NIST_ControlsConfidentialityLevels (
    NIST_ControlConfidentialityLevel_ID INTEGER PRIMARY KEY,
    NIST_Control_ID INTEGER NOT NULL,
    ConfidentialityLevel_ID INTEGER NOT NULL,
    NSS_Systems_Only NVARCHAR (10) NOT NULL,
    UNIQUE (NIST_Control_ID, ConfidentialityLevel_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
    FOREIGN KEY (ConfidentialityLevel_ID) REFERENCES ConfidentialityLevels(ConfidentialityLevel_ID)
);