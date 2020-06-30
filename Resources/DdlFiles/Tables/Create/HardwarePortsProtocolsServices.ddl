CREATE TABLE IF NOT EXISTS HardwarePortsProtocolsServices
(
    HardwarePortProtocolService_ID INTEGER PRIMARY KEY,
    Hardware_ID                    INTEGER NOT NULL,
    PortProtocolService_ID         INTEGER NOT NULL,
    ReportInAccreditation          NVARCHAR(5),
    Direction                      NVARCHAR(25),
    BoundariesCrossed              NVARCHAR(25),
    DOD_Compliant                  NVARCHAR(5),
    Classification                 NVARCHAR(25),
    UNIQUE (
            Hardware_ID,
            PortProtocolService_ID
        ) ON CONFLICT IGNORE,
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware (Hardware_ID),
    FOREIGN KEY (PortProtocolService_ID) REFERENCES PortsProtocolsServices (PortProtocolService_ID)
);