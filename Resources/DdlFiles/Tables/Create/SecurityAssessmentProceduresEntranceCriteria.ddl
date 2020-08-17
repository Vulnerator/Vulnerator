CREATE TABLE IF NOT EXISTS SecurityAssessmentProceduresEntranceCriteria (
    SecurityAssessmentProcedureEntranceCriteria_ID INTEGER PRIMARY KEY,
    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
    EntranceCriteria_ID INTEGER NOT NULL,
    UNIQUE (SecurityAssessmentProcedure_ID, EntranceCriteria_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
    FOREIGN KEY (EntranceCriteria_ID) REFERENCES EntranceCriteria(EntranceCriteria_ID)
);