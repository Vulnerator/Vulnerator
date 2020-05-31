CREATE TABLE IF NOT EXISTS IA_Controls (
    IA_Control_ID INTEGER PRIMARY KEY,
    IA_ControlNumber NVARCHAR (10) NOT NULL,
    Impact NVARCHAR (10) NOT NULL,
    IA_ControlSubjectArea NVARCHAR (50) NOT NULL,
    IA_ControlName NVARCHAR (100) NOT NULL,
    IA_ControlDescription NVARCHAR (250) NOT NULL,
    IA_ControlThreatVulnerabilityCountermeasures NVARCHAR (2000) NOT NULL,
    IA_ControlGeneralImplementationGuidance NVARCHAR (2000) NOT NULL,
    IA_ControlSystemSpecificGuidanceResources NVARCHAR (2000) NOT NULL
);