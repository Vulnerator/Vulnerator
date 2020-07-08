CREATE TABLE IF NOT EXISTS HardwareSoftwarePortsProtocolsServices
(
    HardwareSoftwarePortProtocolService_ID INTEGER PRIMARY KEY ,
    HardwarePortProtocolService_ID INTEGER NOT NULL,
    Software_ID                    INTEGER NOT NULL,
    ReportInAccreditation          NVARCHAR(5),
    Direction                      NVARCHAR(25),
    BoundariesCrossed              NVARCHAR(100),
    DOD_Compliant                  NVARCHAR(5),
    Classification                 NVARCHAR(100),
    UNIQUE (
            HardwarePortProtocolService_ID,
            Software_ID
        ) ON CONFLICT IGNORE,
    FOREIGN KEY (HardwarePortProtocolService_ID) REFERENCES HardwarePortsProtocolsServices (HardwarePortProtocolService_ID),
    FOREIGN KEY (Software_ID) REFERENCES Software (Software_ID)
);