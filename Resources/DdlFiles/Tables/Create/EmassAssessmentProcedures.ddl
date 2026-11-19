CREATE TABLE IF NOT EXISTS EmassAssessmentProcedures (
    CCI_Number          NVARCHAR (25) PRIMARY KEY,
    ControlNumber       NVARCHAR (25),
    AP_Acronym          NVARCHAR (50),
    AssessmentProcedure TEXT,
    AssessmentMethods   TEXT,
    ImportedOn          DATETIME
);
