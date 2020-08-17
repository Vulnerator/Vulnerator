CREATE TABLE IF NOT EXISTS NIST_ControlsCAAs (
    NIST_ControlCAA_ID INTEGER PRIMARY KEY,
    NIST_Control_ID INTEGER NOT NULL,
    ControlApplicabilityAssessment_ID INTEGER NOT NULL,
    LegacyDifficulty NVARCHAR (10) NOT NULL,
    Applicability NVARCHAR (25) NOT NULL,
    UNIQUE (NIST_Control_ID, ControlApplicabilityAssessment_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
    FOREIGN KEY (ControlApplicabilityAssessment_ID) REFERENCES ControlApplicabilityAssessment(ControlApplicabilityAssessment_ID)
);