CREATE TABLE IF NOT EXISTS VulnerabilitiesResponsibilityRoles (
    VulnerabilityRoleResponsibility_ID INTEGER PRIMARY KEY,
    Vulnerability_ID INTEGER NOT NULL,
    Role_ID INTEGER NOT NULL,
    UNIQUE (Vulnerability_ID, Role_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
    FOREIGN KEY (Role_ID) REFERENCES ResponsibilityRoles(Role_ID)
);