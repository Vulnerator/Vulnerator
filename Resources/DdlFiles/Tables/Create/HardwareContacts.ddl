CREATE TABLE IF NOT EXISTS HardwareContacts (
    HardwareContact_ID INTEGER PRIMARY KEY,
    Hardware_ID INTEGER NOT NULL,
    Contact_ID INTEGER NOT NULL,
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
    FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID)
);