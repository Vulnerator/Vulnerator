CREATE TABLE IF NOT EXISTS HardwareSoftwarePortsProtocolsServicesBoundaries (
    HardwareSoftwarePortProtocolServiceBoundary_ID INTEGER PRIMARY KEY,
    HardwareSoftwarePortProtocolService_ID INTEGER NOT NULL,
    Boundary_ID INTEGER NOT NULL,
    CAL_Compliant NVARCHAR(5) NOT NULL,
    PPSM_Approved NVARCHAR(5) NOT NULL,
    UNIQUE (HardwareSoftwarePortProtocolService_ID, Boundary_ID ) ON CONFLICT IGNORE,
    FOREIGN KEY (HardwareSoftwarePortProtocolService_ID) REFERENCES HardwareSoftwarePortsProtocolsServices(HardwareSoftwarePortProtocolService_ID),
    FOREIGN KEY (Boundary_ID) REFERENCES Boundaries(Boundary_ID)
);