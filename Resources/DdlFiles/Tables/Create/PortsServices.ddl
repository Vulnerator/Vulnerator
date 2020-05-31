CREATE TABLE IF NOT EXISTS PortsServices (
    PortService_ID INTEGER PRIMARY KEY,
    ServiceName NVARCHAR (100) NOT NULL UNIQUE ON CONFLICT IGNORE,
    ServiceAcronym NVARCHAR (50),
    PortProtocol_ID INTEGER NOT NULL,
    UNIQUE (ServiceName, PortProtocol_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (PortProtocol_ID) REFERENCES PortsProtocols(PortProtocol_ID)
);