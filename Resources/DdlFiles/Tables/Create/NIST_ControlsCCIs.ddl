CREATE TABLE IF NOT EXISTS NIST_ControlsCCIs
(
    NIST_ControlCCI_ID             INTEGER PRIMARY KEY,
    NIST_Control_ID                INTEGER        NOT NULL,
    CCI_ID                         INTEGER        NOT NULL,
    DOD_AssessmentProcedureMapping NVARCHAR(10),
    ControlIndicator               NVARCHAR(25)   NOT NULL,
    ImplementationGuidance         NVARCHAR(1000) NOT NULL,
    AssessmentProcedureText        NVARCHAR(1000) NOT NULL,
    UNIQUE (NIST_Control_ID, CCI_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls (NIST_Control_ID),
    FOREIGN KEY (CCI_ID) REFERENCES CCIs (CCI_ID)
);
