CREATE TABLE IF NOT EXISTS SecurityAssessmentProceduresAdditionalTestConsiderations (
    SecurityAssessmentProcedureAdditionalTestConsiderations_ID INTEGER PRIMARY KEY,
    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
    AdditionalTestConsideration_ID INTEGER NOT NULL,
    UNIQUE (SecurityAssessmentProcedure_ID, AdditionalTestConsideration_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
    FOREIGN KEY (AdditionalTestConsideration_ID) REFERENCES AdditionalTestConsiderations(AdditionalTestConsideration_ID)
);