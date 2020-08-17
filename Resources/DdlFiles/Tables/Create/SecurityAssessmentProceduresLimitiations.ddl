CREATE TABLE IF NOT EXISTS SecurityAssessmentProceduresLimitiations (
    SecurityAssessmentProcedureLimitation_ID INTEGER PRIMARY KEY,
    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
    Limitation_ID INTEGER NOT NULL,
    UNIQUE (SecurityAssessmentProcedure_ID, Limitation_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
    FOREIGN KEY (Limitation_ID) REFERENCES Limitations(Limitation_ID)
);