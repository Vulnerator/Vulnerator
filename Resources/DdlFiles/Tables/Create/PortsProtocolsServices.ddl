CREATE TABLE IF NOT EXISTS PortsProtocolsServices
(
    PortProtocolService_ID INTEGER PRIMARY KEY,
    Port                   INTEGER       NOT NULL,
    Protocol               NVARCHAR(25)  NOT NULL,
    DiscoveredServiceName  NVARCHAR(500) NOT NULL,
    DisplayedServiceName   NVARCHAR(500),
    ServiceAcronym         NVARCHAR(100),
    UNIQUE (Port, Protocol, DiscoveredServiceName) ON CONFLICT IGNORE
);