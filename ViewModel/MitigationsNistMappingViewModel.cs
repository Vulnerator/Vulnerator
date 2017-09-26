using GalaSoft.MvvmLight;
using log4net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;
using Vulnerator.Model.Object;

namespace Vulnerator.ViewModel
{
    public class MitigationsNistMappingViewModel : ViewModelBase
    {
        private DatabaseContext databaseContext;
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        private List<MitigationsOrCondition> _projectMitigations { get; set; }
        public List<MitigationsOrCondition> ProjectMitigations
        {
            get { return _projectMitigations; }
            set
            {
                if (_projectMitigations != value)
                {
                    _projectMitigations = value;
                    RaisePropertyChanged("ProjectMitigations");
                }
            }
        }

        private List<MitigationsOrCondition> _assetMitigations { get; set; }
        public List<MitigationsOrCondition> AssetMitigations
        {
            get { return _assetMitigations; }
            set
            {
                if (_assetMitigations != value)
                {
                    _assetMitigations = value;
                    RaisePropertyChanged("AssetMitigations");
                }
            }
        }

        private List<Vulnerability> _vulnerabilities { get; set; }
        public List<Vulnerability> Vulnerabilities
        {
            get { return _vulnerabilities; }
            set
            {
                if (_vulnerabilities != value)
                {
                    _vulnerabilities = value;
                    RaisePropertyChanged("Vulnerabilities");
                }
            }
        }

        private List<NistControlsCCI> _nistControlsCcis { get; set; }
        public List<NistControlsCCI> NistControlsCcis
        {
            get { return _nistControlsCcis; }
            set
            {
                if (_nistControlsCcis != value)
                {
                    _nistControlsCcis = value;
                    RaisePropertyChanged("NistControlsCcis");
                }
            }
        }


        public MitigationsNistMappingViewModel()
        {
            try
            {
                log.Info("Begin instantiation of MitigationsNistMappingViewModel.");
                using (databaseContext = new DatabaseContext())
                {
                    ProjectMitigations = new List<MitigationsOrCondition>();
                    AssetMitigations = new List<MitigationsOrCondition>();
                    Vulnerabilities = new List<Vulnerability>();
                    NistControlsCcis = databaseContext.NistControlsCCIs.AsNoTracking().ToList();
                }
                    
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to instantiate MitigationsNistMappingViewModel."));
                log.Debug("Exception details:", exception);
            }
        }
    }
}
