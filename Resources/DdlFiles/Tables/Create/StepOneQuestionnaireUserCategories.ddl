CREATE TABLE IF NOT EXISTS StepOneQuestionnaireUserCategories (
    StepOneQuestionnaireUserCategory_ID INTEGER PRIMARY KEY,
    StepOneQuestionnaire_ID INTEGER NOT NULL,
    UserCategory_ID INTEGER NOT NULL,
    UNIQUE (StepOneQuestionnaire_ID, UserCategory_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
    FOREIGN KEY (UserCategory_ID) REFERENCES UserCategories(UserCategory_ID)
);