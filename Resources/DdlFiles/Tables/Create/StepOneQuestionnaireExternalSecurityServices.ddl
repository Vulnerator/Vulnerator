CREATE TABLE IF NOT EXISTS StepOneQuestionnaireExternalSecurityServices (
    StepOneQuestionnaire_ID INTEGER NOT NULL,
    ExternalSecurityServices_ID INTEGER NOT NULL,
    FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
    FOREIGN KEY (ExternalSecurityServices_ID) REFERENCES ExternalSecurityServices(ExternalSecurityServices_ID)
);