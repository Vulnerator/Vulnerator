CREATE TABLE IF NOT EXISTS PortProtocolServiceEvidence
(
    PortProtocolServiceEvidence_ID INTEGER PRIMARY KEY,
    HardwarePortProtocolService_ID INTEGER       NOT NULL,
    PluginId                       NVARCHAR(25)  NOT NULL,
    PluginName                     NVARCHAR(500),
    UNIQUE (HardwarePortProtocolService_ID, PluginId) ON CONFLICT IGNORE,
    FOREIGN KEY (HardwarePortProtocolService_ID) REFERENCES HardwarePortsProtocolsServices (HardwarePortProtocolService_ID)
);
