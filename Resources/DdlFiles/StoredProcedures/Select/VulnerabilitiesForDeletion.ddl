SELECT
		Vulnerabilities.Vulnerability_ID
FROM
		Vulnerabilities
JOIN VulnerabilitiesVulnerabilitySources ON Vulnerabilities.Vulnerability_ID = VulnerabilitiesVulnerabilitySources.Vulnerability_ID
JOIN VulnerabilitySources ON VulnerabilitiesVulnerabilitySources.VulnerabilitySource_ID = VulnerabilitySources.VulnerabilitySource_ID
WHERE 
		PublishedDate IS NOT @PublishedDate
AND
		SourceName IS @SourceName