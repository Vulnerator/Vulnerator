CREATE TABLE IF NOT EXISTS SystemCategorizationInformationTypesImpactAdjustments (
    SystemCategorizationInformationTypeImpactAdjustment_ID INTEGER NOT NULL,
    SystemCategorization_ID INTEGER NOT NULL,
    InformationType_ID INTEGER NOT NULL,
    ImpactAdjustment_ID INTEGER NOT NULL,
    UNIQUE (SystemCategorization_ID, InformationType_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
    FOREIGN KEY (InformationType_ID) REFERENCES InformationTypes(InformationType_ID),
    FOREIGN KEY (ImpactAdjustment_ID) REFERENCES ImpactAdjustments(ImpactAdjustment_ID)
);