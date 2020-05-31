CREATE TABLE IF NOT EXISTS PortsServices (
    PortService_ID INTEGER PRIMARY KEY,
    DiscoveredServiceName NVARCHAR (500) NOT NULL,
    DisplayedServiceName NVARCHAR (500),
    ServiceAcronym NVARCHAR (100),
    PortProtocol_ID INTEGER NOT NULL,
    UNIQUE (DiscoveredServiceName, PortProtocol_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (PortProtocol_ID) REFERENCES PortsProtocols(PortProtocol_ID)
);