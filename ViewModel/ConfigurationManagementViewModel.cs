using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;

namespace Vulnerator.ViewModel
{
    public class ConfigurationManagementViewModel : ViewModelBase
    {
        private DatabaseContext databaseContext;

        private List<Hardware> _hardwares;
        public List<Hardware> Hardwares
        {
            get { return _hardwares; }
            set
            {
                if (_hardwares != value)
                {
                    _hardwares = value;
                    RaisePropertyChanged("Hardwares");
                }
            }
        }

        private List<Software> _softwares;
        public List<Software> Softwares
        {
            get { return _softwares; }
            set
            {
                if (_softwares != value)
                {
                    _softwares = value;
                    RaisePropertyChanged("Softwares");
                }
            }
        }

        private List<SoftwareHardware> _softwareHardwares;
        public List<SoftwareHardware> SoftwareHardwares
        {
            get { return _softwareHardwares; }
            set
            {
                if (_softwareHardwares != value)
                {
                    _softwareHardwares = value;
                    RaisePropertyChanged("SoftwareHardwares");
                }
            }
        }

        public ConfigurationManagementViewModel()
        {
            databaseContext = new DatabaseContext();
            Hardwares = databaseContext.Hardwares.ToList();
        }
    }
}
