CREATE TABLE IF NOT EXISTS RelatedDocuments (
    RelatedDocument_ID INTEGER PRIMARY KEY,
    RelatedDocumentName NVARCHAR (50) NOT NULL,
    RelationshipDescription NVARCHAR (100) NOT NULL
);