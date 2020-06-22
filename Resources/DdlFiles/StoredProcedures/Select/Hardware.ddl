SELECT 
		DiscoveredHostName,
		FQDN,
		NetBIOS,
		ScanIP
FROM Hardware
WHERE Hardware_ID = @Hardware_ID;