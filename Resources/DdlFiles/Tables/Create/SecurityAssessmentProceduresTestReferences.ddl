CREATE TABLE IF NOT EXISTS SecurityAssessmentProceduresTestReferences (
    SecurityAssessmentProcedureTestReference_ID INTEGER PRIMARY KEY,
    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
    TestReference_ID INTEGER NOT NULL,
    UNIQUE (SecurityAssessmentProcedure_ID, TestReference_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
    FOREIGN KEY (TestReference_ID) REFERENCES TestReferences(TestReference_ID)
);