using GalaSoft.MvvmLight;
using log4net;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using Vulnerator.Model.Entity;

namespace Vulnerator.ViewModel
{
    public class MitigationsNistMappingViewModel : ViewModelBase
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        private List<MitigationsOrCondition> _mitigations { get; set; }
        public List<MitigationsOrCondition> Mitigations
        {
            get { return _mitigations; }
            set
            {
                if (_mitigations != value)
                {
                    _mitigations = value;
                    RaisePropertyChanged("Mitigations");
                }
            }
        }

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

        public MitigationsNistMappingViewModel()
        {
            try
            {
                using (DatabaseContext databaseContext = new DatabaseContext())
                {
                    Mitigations = databaseContext.MitigationsOrConditions
                        .Include(m => m.Hardwares)
                        .Include(m => m.Groups)
                        .AsNoTracking().ToList();
                    Groups = databaseContext.Groups.AsNoTracking().ToList();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to instantiate Mitigations / NIST Mapping ViewModel.");
                log.Debug("Exception details:", exception);
            }
        }
    }
}
