CREATE TABLE IF NOT EXISTS InformationTypes (
    InformationType_ID INTEGER PRIMARY KEY,
    InfoTypeIdentifier NVARCHAR (25) NOT NULL,
    InfoTypeName NVARCHAR (50) NOT NULL,
    BaselineConfidentiality NVARCHAR (25),
    BaselineIntegrity NVARCHAR (25),
    BaselineAvailability NVARCHAR (25),
    EnhancedConfidentiality NVARCHAR (25),
    EnhancedIntegrity NVARCHAR (25),
    EnhancedAvailability NVARCHAR (25)
);