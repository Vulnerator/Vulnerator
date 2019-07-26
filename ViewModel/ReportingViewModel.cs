using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GalaSoft.MvvmLight;
using Vulnerator.Model.Entity;
using log4net;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using GalaSoft.MvvmLight.Messaging;

namespace Vulnerator.ViewModel
{
    public class ReportingViewModel : ViewModelBase
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        private List<Group> _groups { get; set; }
        public List<Group> Groups
        {
            get { return _groups; }
            set
            {
                if (_groups != value)
                {
                    _groups = value;
                    RaisePropertyChanged("Groups");
                }
            }
        }

        private List<RequiredReport> _vulnerabilityReports;
        public List<RequiredReport> VulnerabilityReports
        {
            get { return _vulnerabilityReports; }
            set
            {
                if (_vulnerabilityReports != value)
                {
                    _vulnerabilityReports = value;
                    RaisePropertyChanged("Reports");
                }
            }
        }

        public ReportingViewModel()
        {
            try
            {
                PopulateGui();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated, (msg) => HandleModelUpdate(msg.Notification));
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to instantiate ReportingViewModel."));
                log.Debug("Exception details:", exception);
            }
        }

        private void HandleModelUpdate(string modelUpdated)
        { 
            try
            {
                if (modelUpdated.Equals("AllModels") || modelUpdated.Equals("ReportingModel"))
                { PopulateGui(); }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to update ReportingViewModel."));
                log.Debug("Exception details:", exception);
            }
        }

        private void PopulateGui()
        {
            using (DatabaseContext databaseContext = new DatabaseContext())
            {
                PopulateReports(databaseContext);
                Groups = databaseContext.Groups.AsNoTracking().ToList();
            }
        }

        private void PopulateReports(DatabaseContext databaseContext)
        {
            try
            {
                VulnerabilityReports = databaseContext.RequiredReports
                    .Include(r => r.ReportCategory)
                    .Where(r => r.ReportCategory.Report_Category_Name.Equals("Vulnerability Management") && !r.Is_Report_Enabled.Equals("False"))
                    .OrderBy(r => r.ReportCategory.Report_Category_Name)
                    .ThenBy(r => r.Displayed_Report_Name)
                    .AsNoTracking()
                    .ToList();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to populate required reports"));
                log.Debug("Exception details:", exception);
            }
        }
    }
}
