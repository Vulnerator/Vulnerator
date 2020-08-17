CREATE TABLE IF NOT EXISTS StepOneQuestionnaireEncryptionTechniques (
    StepOneQuestionnaireExternalSecurityService_ID INTEGER PRIMARY KEY,
    StepOneQuestionnaire_ID INTEGER NOT NULL,
    EncryptionTechnique_ID INTEGER NOT NULL,
    UNIQUE (StepOneQuestionnaire_ID, EncryptionTechnique_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
    FOREIGN KEY (EncryptionTechnique_ID) REFERENCES EncryptionTechniques(EncryptionTechnique_ID)
);