CREATE TABLE IF NOT EXISTS StepOneQuestionnaireNetworkConnectionRules (
    StepOneQuestionnaireNetworkConnectionRule_ID INTEGER PRIMARY KEY,
    StepOneQuestionnaire_ID INTEGER NOT NULL,
    NetworkConnectionRule_ID INTEGER NOT NULL,
    UNIQUE (
          StepOneQuestionnaire_ID,
          NetworkConnectionRule_ID
      ) ON CONFLICT IGNORE,
    FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
    FOREIGN KEY (NetworkConnectionRule_ID) REFERENCES NetworkConnectionRules(NetworkConnectionRule_ID)
);