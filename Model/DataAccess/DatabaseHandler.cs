using log4net;
using System;
using System.Linq;
using Vulnerator.Model.Object;
using System.Collections.Generic;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseHandler
    {
        public static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public string SaveMitigation(MitigationCommandParameter mitigationCommandParameter, DatabaseContext databaseContext)
        {
            try
            {
                List<string> missingFields = VerifyRequiredMitigationFields(mitigationCommandParameter);
                if (missingFields.Count > 0)
                {
                    string returnValue = "The following fields are required: ";
                    for(int i = 0; i < missingFields.Count; i++)
                    {
                        if (i != missingFields.Count - 1)
                        { returnValue = returnValue + missingFields[i] + ", "; }
                        else
                        { returnValue = returnValue + missingFields[i]; }
                    }
                    return returnValue;
                }
                string outcome;
                if (mitigationCommandParameter.VulnId.Contains("\r\n"))
                {
                    int failedCount = 0;
                    int successCount = 0;
                    string[] delimiter = new string[] { "\r\n" };
                    List<string> vulnIdList = mitigationCommandParameter.VulnId.Split(delimiter, StringSplitOptions.None).ToList();
                    foreach (string id in vulnIdList)
                    {
                        mitigationCommandParameter.VulnId = id;
                        outcome = UpdateMitigation(databaseContext, mitigationCommandParameter);
                        if (outcome != "Success")
                        { failedCount++; }
                        else
                        { successCount++; }
                    }
                    return "Mitigations parsed; " + successCount + " added successfully, " + failedCount + " failures";
                }
                else
                {
                    outcome = UpdateMitigation(databaseContext, mitigationCommandParameter); 
                    if (outcome != "Success")
                    { return outcome; }
                    else
                    {
                        databaseContext.SaveChanges();
                        return "Mitigation added";
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to save Mitigation record");
                log.Debug("Exception Details: " + exception);
                return "Mitigation addition failed; see log for details";
            }
        }

        private List<string> VerifyRequiredMitigationFields(MitigationCommandParameter mitigationCommandParameter)
        {
            List<string> missingFields = new List<string>();
            if (string.IsNullOrWhiteSpace(mitigationCommandParameter.VulnId))
            { missingFields.Add("Vulnerability"); }
            if (string.IsNullOrWhiteSpace(mitigationCommandParameter.Text))
            { missingFields.Add("Mitigation Text"); }
            if (string.IsNullOrWhiteSpace(mitigationCommandParameter.DateEntered))
            { missingFields.Add("Date Entered"); }
            if (string.IsNullOrWhiteSpace(mitigationCommandParameter.DateExpires))
            { missingFields.Add("Date Expires"); }
            if (string.IsNullOrWhiteSpace(mitigationCommandParameter.Status))
            { missingFields.Add("Status"); }
            return missingFields;
        }

        private string UpdateMitigation(DatabaseContext databaseContext, MitigationCommandParameter mitigationCommandParameter)
        {
            try
            {
                bool isUpdate = true;
                Mitigation mitigation = null;
                if (mitigationCommandParameter.Index != null && !mitigationCommandParameter.Index.Contains("Dependency"))
                {
                    mitigation = databaseContext.Mitigations
                                .FirstOrDefault(x => x.MitigationIndex == int.Parse(mitigationCommandParameter.Index));
                }
                if (mitigation == null)
                {
                    isUpdate = false;
                    mitigation = new Mitigation();
                }
                mitigation.VulnId = mitigationCommandParameter.VulnId;
                mitigation.Text = mitigationCommandParameter.Text;
                mitigation.FindingStatus = SelectStatus(databaseContext, mitigationCommandParameter);
                mitigation.StatusIndex = mitigation.FindingStatus.StatusIndex;
                DateTime dateEntered = DateTime.Parse(mitigationCommandParameter.DateEntered);
                DateTime dateExpires = DateTime.Parse(mitigationCommandParameter.DateExpires);
                if (dateExpires < dateEntered)
                { return "Expiration date must be after entry date"; }
                mitigation.DateEntered = dateEntered.ToLongDateString();
                mitigation.DateExpires = dateExpires.ToLongDateString();
                if (mitigationCommandParameter.SingleAsset || mitigationCommandParameter.SingleGroup)
                {
                    if (mitigationCommandParameter.SingleGroup)
                    {
                        bool? groupIsSet = ProjectAndAccredtationAreSet(mitigationCommandParameter);
                        if (groupIsSet == false)
                        { return "The project field is required when specifying an accreditation"; }
                        else
                        {
                            mitigation.Group = SelectGroup(databaseContext, mitigationCommandParameter);
                            mitigation.GroupIndex = mitigation.Group.GroupIndex;
                        }
                    }
                    if (mitigationCommandParameter.SingleAsset)
                    {
                        if (!mitigationCommandParameter.SingleGroup)
                        {
                            mitigation.Group = databaseContext.Groups.FirstOrDefault(x => x.GroupIndex == 1);
                            mitigation.GroupIndex = mitigation.Group.GroupIndex;
                        }
                        bool? assetIsSet = HostNameAndIpAddressAreSet(mitigationCommandParameter);
                        if (assetIsSet == false)
                        { return "The IP Address field is required when specifying an asset"; }
                        else if (assetIsSet == null)
                        { return "The Host Name field is required when specifying an asset"; }
                        else
                        {
                            mitigation.Asset = SelectAsset(databaseContext, mitigationCommandParameter);
                            mitigation.AssetIndex = mitigation.Asset.AssetIndex;
                        }
                    }
                }
                else if (mitigationCommandParameter.AllInstances)
                {
                    mitigation.Group = databaseContext.Groups.FirstOrDefault(x => x.GroupIndex == 1);
                    mitigation.GroupIndex = mitigation.Group.GroupIndex;
                    mitigation.Asset = databaseContext.Assets.FirstOrDefault(x => x.AssetIndex == 1);
                    mitigation.AssetIndex = mitigation.Asset.AssetIndex;
                }
                else
                {
                    mitigation.Group = databaseContext.Groups.FirstOrDefault(x => x.GroupIndex == 1);
                    mitigation.GroupIndex = mitigation.Group.GroupIndex;
                    mitigation.Asset = databaseContext.Assets.FirstOrDefault(x => x.AssetIndex == 1);
                    mitigation.AssetIndex = mitigation.Asset.AssetIndex;
                }
                if (!isUpdate)
                { databaseContext.Mitigations.Add(mitigation); }
                return "Success";
            }
            catch (Exception exception)
            {
                log.Error("Unable to update Mitigation record");
                throw exception;
            }
        }

        private FindingStatus SelectStatus(DatabaseContext databaseContext, MitigationCommandParameter mitigationCommandParameter)
        {
            try
            {
                string status = mitigationCommandParameter.Status;
                FindingStatus findingStatus = databaseContext.FindingStatuses
                        .FirstOrDefault(x => x.Status == status);
                if (findingStatus == null)
                {
                    databaseContext.FindingStatuses.Add(new FindingStatus { Status = status });
                    databaseContext.SaveChanges();
                    findingStatus = databaseContext.FindingStatuses
                        .FirstOrDefault(x => x.Status == status);
                }
                return findingStatus;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain FindingStatus record");
                log.Debug("Exception Details: " + exception);
                return null;
            }
        }

        private Group SelectGroup(DatabaseContext databaseContext, MitigationCommandParameter mitigationCommandParameter)
        {
            try
            {
                string project = mitigationCommandParameter.Project;
                string accreditation = mitigationCommandParameter.Accreditation;
                Group group = databaseContext.Groups
                    .FirstOrDefault(x => x.ProjectName == project && x.AccreditationName == accreditation);
                if (group == null)
                { group = InsertGroup(databaseContext, project, accreditation); }
                return group;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain Group record");
                throw exception;
            }
        }

        private Group InsertGroup(DatabaseContext databaseContext, string project, string accreditation)
        {
            try
            {
                databaseContext.Groups.Add(new Group { ProjectName = project, AccreditationName = accreditation });
                databaseContext.SaveChanges();
                Group group = databaseContext.Groups
                    .FirstOrDefault(x => x.ProjectName == project && x.AccreditationName == accreditation);
                return group;
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert Group record");
                throw exception;
            }
        }

        private Asset SelectAsset(DatabaseContext databaseContext, MitigationCommandParameter mitigationCommandParameter)
        {
            try
            {
                string hostName = mitigationCommandParameter.HostName;
                string ipAddress = mitigationCommandParameter.IpAddress;
                Group group = SelectGroup(databaseContext, mitigationCommandParameter);
                Asset asset = databaseContext.Assets
                    .FirstOrDefault(x => x.HostName == hostName && x.IpAddress == ipAddress && x.GroupIndex == group.GroupIndex);
                if (asset == null)
                { asset = InsertAsset(databaseContext, mitigationCommandParameter, group); }
                return asset;
            }
            catch(Exception exception)
            {
                log.Error("Unable to obtain Asset record");
                throw exception;
            }
        }

        private Asset InsertAsset(DatabaseContext databaseContext, MitigationCommandParameter mitigationCommandParameter, Group group)
        {
            try
            {
                string hostName = mitigationCommandParameter.HostName;
                string ipAddress = mitigationCommandParameter.IpAddress;
                databaseContext.Assets.Add(new Asset
                {
                    HostName = hostName,
                    IpAddress = ipAddress,
                    Group = group,
                    GroupIndex = group.GroupIndex
                });
                databaseContext.SaveChanges();
                Asset asset = databaseContext.Assets
                    .FirstOrDefault(x => x.HostName == hostName && x.IpAddress == ipAddress && x.GroupIndex == group.GroupIndex);
                return asset;
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert Asset record");
                throw exception;
            }
        }

        private bool? ProjectAndAccredtationAreSet(MitigationCommandParameter mitigationCommandParameter)
        {
            if (!string.IsNullOrWhiteSpace(mitigationCommandParameter.Accreditation))
            {
                if (!string.IsNullOrWhiteSpace(mitigationCommandParameter.Project))
                { return true; }
                else
                { return false; }
            }
            else if (!string.IsNullOrWhiteSpace(mitigationCommandParameter.Project))
            { return true; }
            else
            { return null; }
        }

        private bool? HostNameAndIpAddressAreSet(MitigationCommandParameter mitigationCommandParameter)
        {
            string hostName = mitigationCommandParameter.HostName;
            string ipAddress = mitigationCommandParameter.IpAddress;
            if (!string.IsNullOrWhiteSpace(hostName) && string.IsNullOrWhiteSpace(ipAddress))
            { return false; }
            else if (!string.IsNullOrWhiteSpace(ipAddress) && string.IsNullOrWhiteSpace(hostName))
            { return null; }
            else
            { return true; }
        }
    }
}
