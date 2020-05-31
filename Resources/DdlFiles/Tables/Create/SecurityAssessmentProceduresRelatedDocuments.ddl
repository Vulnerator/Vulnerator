CREATE TABLE IF NOT EXISTS SecurityAssessmentProceduresRelatedDocuments (
    SecurityAssessmentProcedureRelatedDocuments_ID INTEGER PRIMARY KEY,
    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
    RelatedDocument_ID INTEGER NOT NULL,
    UNIQUE (SecurityAssessmentProcedure_ID, RelatedDocument_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
    FOREIGN KEY (RelatedDocument_ID) REFERENCES RelatedDocuments(RelatedDocument_ID)
);