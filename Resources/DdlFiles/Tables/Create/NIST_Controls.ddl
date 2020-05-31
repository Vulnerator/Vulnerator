CREATE TABLE IF NOT EXISTS NIST_Controls (
    NIST_Control_ID INTEGER PRIMARY KEY,
    ControlFamily NVARCHAR (25) NOT NULL,
    ControlNumber INTEGER NOT NULL,
    ControlEnhancement INTEGER,
    ControlTitle NVARCHAR (50) NOT NULL,
    ControlText NVARCHAR (2000) NOT NULL,
    SupplementalGuidance NVARCHAR (2000) NOT NULL,
    MonitoringFrequency NVARCHAR (10)
);