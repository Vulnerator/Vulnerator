using log4net;
using System;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    public class MitigationsTextParser
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public void ParseMitigation(string fileName, string status, string group, ObservableCollection<MitigationItem> mitList, ObservableCollection<SystemGroup> groupList)
        {
            try
            {
                log.Info("Begin parsing of " + fileName + " to mitigations database.");
                string mitigationDatabasePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Vulnerator";
                string mitigationDatabase = mitigationDatabasePath + @"\Mitigations.sdf";
                string mitigationDatabaseConnection = @"Data Source = " + mitigationDatabase;

                using (SQLiteConnection connection = new SQLiteConnection(mitigationDatabaseConnection))
                {
                    connection.Open();

                    foreach (string line in System.IO.File.ReadLines(fileName))
                    {
                        if (line.StartsWith("#"))
                        {
                            string newId;
                            string[] firstPass = line.Split('|');
                            string[] vulnIds = firstPass[0].Split(' ');
                            string mitText = firstPass[1].Trim();
                            string actualStatus;

                            foreach (string id in vulnIds)
                            {
                                id.Trim();
                                if (id.StartsWith("#"))
                                {
                                    newId = id.Replace("#", string.Empty);
                                }
                                else
                                {
                                    newId = id;
                                }
                                using (SQLiteCommand command = new SQLiteCommand(
                                    "INSERT INTO TheMitigations VALUES (@Id, @Status, @MitigationGroupName, @Text)", connection))
                                {
                                    command.Parameters.Add(new SQLiteParameter("Id", newId));
                                    if (mitText.StartsWith("Ongoing") || mitText.StartsWith("ONGOING") ||
                                        mitText.StartsWith("Open") || mitText.StartsWith("OPEN") ||
                                        mitText.StartsWith("Mitigation") || mitText.StartsWith("MITIGATION"))
                                    {
                                        actualStatus = "Ongoing (Open)";
                                    }

                                    else if (mitText.StartsWith("Closed") || mitText.StartsWith("CLOSED") ||
                                        mitText.StartsWith("Completed") || mitText.StartsWith("COMPLETED") ||
                                        mitText.StartsWith("Remediation") || mitText.StartsWith("REMEDIATION"))
                                    {
                                        actualStatus = "Completed (Closed)";
                                    }

                                    else if (mitText.StartsWith("False Positive") || mitText.StartsWith("FALSE POSITIVE"))
                                    {
                                        actualStatus = "False Positive";
                                    }

                                    else
                                    {
                                        actualStatus = status;
                                    }

                                    command.Parameters.Add(new SQLiteParameter("Status", actualStatus));
                                    command.Parameters.Add(new SQLiteParameter("MitigationGroupName", group));
                                    command.Parameters.Add(new SQLiteParameter("Text", mitText));
                                    command.ExecuteNonQuery();
                                }

                                mitList.Add(new MitigationItem(newId, group, actualStatus, mitText, false));
                            }
                        }
                    }

                    connection.Close();

                    if (groupList != null)
                    {
                        groupList.Add(new SystemGroup(group));
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse " + fileName + " to mitigations database.");
                log.Debug("Exception details: " + exception);
            }
        }
    }
}
