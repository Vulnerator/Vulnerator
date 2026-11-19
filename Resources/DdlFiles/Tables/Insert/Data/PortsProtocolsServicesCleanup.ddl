-- Nessus files host-level results under port 0 ("general/tcp", "general/icmp"); earlier versions stored those as
-- services. They are not ports, protocols or services: remove them (runs on every start; nothing to do once clean).
DELETE FROM PortProtocolServiceEvidence
WHERE HardwarePortProtocolService_ID IN (SELECT HardwarePortProtocolService_ID
                                         FROM HardwarePortsProtocolsServices
                                         WHERE PortProtocolService_ID IN (SELECT PortProtocolService_ID FROM PortsProtocolsServices WHERE Port = 0));
DELETE FROM HardwareSoftwarePortsProtocolsServices
WHERE HardwarePortProtocolService_ID IN (SELECT HardwarePortProtocolService_ID
                                         FROM HardwarePortsProtocolsServices
                                         WHERE PortProtocolService_ID IN (SELECT PortProtocolService_ID FROM PortsProtocolsServices WHERE Port = 0));
DELETE FROM HardwarePortsProtocolsServices
WHERE PortProtocolService_ID IN (SELECT PortProtocolService_ID FROM PortsProtocolsServices WHERE Port = 0);
DELETE FROM PortsProtocolsServices
WHERE Port = 0;
