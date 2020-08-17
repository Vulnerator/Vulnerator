CREATE TABLE IF NOT EXISTS SecurityAssessmentProceduresCustomTestCases (
    SecurityAssessmentProcedureCustomTestCase_ID INTEGER PRIMARY KEY,
    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
    CustomTestCase_ID INTEGER NOT NULL,
    UNIQUE (SecurityAssessmentProcedure_ID, CustomTestCase_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
    FOREIGN KEY (CustomTestCase_ID) REFERENCES CustomTestCases(CustomTestCase_ID)
);