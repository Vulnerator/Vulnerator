CREATE TABLE IF NOT EXISTS AssessmentProceduresTestResultsPolicySupportingImages (
    AssessmentProceduresTestResultsPolicySupportingImage_ID     INTEGER PRIMARY KEY,
    AssessmentProcedureTestResult_ID                            INTEGER NOT NULL,
    PolicySupportingImage_ID                                    INTEGER NOT NULL,
    FOREIGN KEY (AssessmentProcedureTestResult_ID) REFERENCES AssessmentProcedureTestResults(AssessmentProcedureTestResult_ID),
    FOREIGN KEY (PolicySupportingImage_ID) REFERENCES PolicySupportingImages(PolicySupportingImage_ID)
);