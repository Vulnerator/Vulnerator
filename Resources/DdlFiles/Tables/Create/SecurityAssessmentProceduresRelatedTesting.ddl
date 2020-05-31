CREATE TABLE IF NOT EXISTS SecurityAssessmentProceduresRelatedTesting (
    SecurityAssessmentProcedureRelatedTesting_ID INTEGER PRIMARY KEY,
    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
    RelatedTesting_ID INTEGER NOT NULL,
    UNIQUE (SecurityAssessmentProcedure_ID, RelatedTesting_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
    FOREIGN KEY (RelatedTesting_ID) REFERENCES RelatedTesting(RelatedTesting_ID)
);