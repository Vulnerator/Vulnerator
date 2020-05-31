CREATE TABLE IF NOT EXISTS StepOneQuestionnaireConnectivity (
    StepOneQuestionnaireConnectivity_ID INTEGER PRIMARY KEY,
    StepOneQuestionnaire_ID INTEGER NOT NULL,
    Connectivity_ID INTEGER NOT NULL,
    UNIQUE (StepOneQuestionnaire_ID, Connectivity_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
    FOREIGN KEY (Connectivity_ID) REFERENCES Connectivity(Connectivity_ID)
);