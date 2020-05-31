CREATE TABLE IF NOT EXISTS SystemCategorizationJointAuthorizationOrganizations (
    SystemCategorizationJointOrganization_ID INTEGER PRIMARY KEY,
    SystemCategorization_ID INTEGER NOT NULL,
    JointAuthorizationOrganization_ID INTEGER NOT NULL,
    UNIQUE (SystemCategorization_ID, JointAuthorizationOrganization_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
    FOREIGN KEY (JointAuthorizationOrganization_ID) REFERENCES JointAuthorizationOrganizations(JointAuthorizationOrganization_ID)
);