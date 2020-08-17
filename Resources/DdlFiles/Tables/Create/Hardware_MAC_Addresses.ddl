CREATE TABLE IF NOT EXISTS Hardware_MAC_Addresses (
    Hardware_MAC_Address_ID INTEGER PRIMARY KEY,
    Hardware_ID INTEGER NOT NULL,
    MAC_Address_ID INTEGER NOT NULL,
    UNIQUE (Hardware_ID, MAC_Address_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
    FOREIGN KEY (MAC_Address_ID) REFERENCES MAC_Addresses(MAC_Address_ID)
);