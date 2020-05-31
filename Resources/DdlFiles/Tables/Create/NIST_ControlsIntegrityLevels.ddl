CREATE TABLE IF NOT EXISTS NIST_ControlsIntegrityLevels (
    NIST_ControlIntegrityLevel_ID INTEGER PRIMARY KEY,
    NIST_Control_ID INTEGER NOT NULL,
    IntegrityLevel_ID INTEGER NOT NULL,
    NSS_Systems_Only NVARCHAR (10) NOT NULL,
    UNIQUE (NIST_Control_ID, IntegrityLevel_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
    FOREIGN KEY (IntegrityLevel_ID) REFERENCES IntegrityLevels(IntegrityLevel_ID)
);