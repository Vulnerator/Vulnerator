CREATE TABLE IF NOT EXISTS EncryptionTechniques (
    EncryptionTechnique_ID INTEGER PRIMARY KEY,
    EncryptionTechnique NVARCHAR (100) NOT NULL,
    KeyManagement NVARCHAR (500) NOT NULL
);