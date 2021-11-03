CREATE TABLE IF NOT EXISTS AssessmentProcedureTestResults (
    AssessmentProcedureTestResult_ID        INTEGER PRIMARY KEY,
    ComplianceStatus                        NVARCHAR (20) NOT NULL,
    TestResultText                          NVARCHAR (MAX),
    TestResultDate                          DATE,
    TestedBy                                DATE,
    PolicyText                              NVARCHAR (MAX),
    Inheritability                          NVARCHAR (20) NOT NULL,
    Group_ID                                INTEGER NOT NULL,
    NIST_ControlCCI_ID                      INTEGER NOT NULL,
    UNIQUE (
        Group_ID,
        NIST_ControlCCI_ID
    ) ON CONFLICT IGNORE,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    FOREIGN KEY (NIST_ControlCCI_ID) REFERENCES NIST_ControlsCCIs(NIST_ControlCCI_ID)
);