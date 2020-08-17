CREATE TABLE IF NOT EXISTS ContactsCertifications (
    ContactsCertifications_ID INTEGER PRIMARY KEY,
    Contact_ID INTEGER NOT NULL,
    Certification_ID INTEGER NOT NULL,
    UNIQUE (Contact_ID, Certification_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID),
    FOREIGN KEY (Certification_ID) REFERENCES Certifications(Certification_ID)
);