CREATE TABLE IF NOT EXISTS ExternalSecurityServices (
    ExternalSecurityServices_ID INTEGER PRIMARY KEY,
    ExternalSecurityService NVARCHAR (50) NOT NULL,
    ServiceDescription NVARCHAR (500) NOT NULL,
    SecurityRequirementsDescription NVARCHAR (500) NOT NULL,
    RiskDetermination NVARCHAR (100) NOT NULL
);