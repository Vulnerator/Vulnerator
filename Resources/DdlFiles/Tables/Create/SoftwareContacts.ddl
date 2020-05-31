CREATE TABLE IF NOT EXISTS SoftwareContacts (
    SoftwareContact_ID INTEGER PRIMARY KEY,
    Software_ID INTEGER NOT NULL,
    Contact_ID INTEGER NOT NULL,
    UNIQUE (Software_ID, Contact_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
    FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID)
);