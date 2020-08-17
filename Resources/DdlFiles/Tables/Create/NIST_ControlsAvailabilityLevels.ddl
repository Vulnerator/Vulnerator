CREATE TABLE IF NOT EXISTS NIST_ControlsAvailabilityLevels (
    NIST_ControlAvailabilityLevel_ID INTEGER PRIMARY KEY,
    NIST_Control_ID INTEGER NOT NULL,
    AvailabilityLevel_ID INTEGER NOT NULL,
    NSS_SystemsOnly NVARCHAR (10) NOT NULL,
    UNIQUE (NIST_Control_ID, AvailabilityLevel_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
    FOREIGN KEY (AvailabilityLevel_ID) REFERENCES AvailabilityLevels(AvailabilityLevel_ID)
);