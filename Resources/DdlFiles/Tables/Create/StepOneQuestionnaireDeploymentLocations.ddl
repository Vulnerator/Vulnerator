CREATE TABLE IF NOT EXISTS StepOneQuestionnaireDeploymentLocations (
    StepOneQuestionnaireDeploymentLocation_ID INTEGER PRIMARY KEY,
    StepOneQuestionnaire_ID INTEGER NOT NULL,
    Location_ID INTEGER NOT NULL,
    UNIQUE (StepOneQuestionnaire_ID, Location_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
    FOREIGN KEY (Location_ID) REFERENCES Locations(Location_ID)
);