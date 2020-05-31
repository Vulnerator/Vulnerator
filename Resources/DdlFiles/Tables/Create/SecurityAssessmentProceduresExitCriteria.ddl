CREATE TABLE IF NOT EXISTS SecurityAssessmentProceduresExitCriteria (
    SecurityAssessmentProcedureExitCriteria_ID INTEGER PRIMARY KEY,
    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
    ExitCriteria_ID INTEGER NOT NULL,
    UNIQUE (SecurityAssessmentProcedure_ID, ExitCriteria_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
    FOREIGN KEY (ExitCriteria_ID) REFERENCES ExitCriteria(ExitCriteria_ID)
);