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

        private List<Contact> _contacts;
        public List<Contact> Contacts
        {
            get { return _contacts; }
            set
            {
                if (_contacts != value)
                {
                    _contacts = value;
                    RaisePropertyChanged("Contacts");
                }
            }
        }

        private List<Group> _groups;
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

        private List<Accreditation> _accreditations;
        public List<Accreditation> Accreditations
        {
            get { return _accreditations; }
            set
            {
                if (_accreditations != value)
                {
                    _accreditations = value;
                    RaisePropertyChanged("Accreditations");
                }
            }
        }

        private List<PP> _pps;
        public List<PP> PPS
        {
            get { return _pps; }
            set
            {
                if (_pps != value)
                {
                    _pps = value;
                    RaisePropertyChanged("PPS");
                }
            }
        }

        public ConfigurationManagementViewModel()
        {
            databaseContext = new DatabaseContext();
            Hardwares = databaseContext.Hardwares.ToList();
            Softwares = databaseContext.Softwares.ToList();
            Contacts = databaseContext.Contacts.ToList();
            PPS = databaseContext.PPS.ToList();
            Groups = databaseContext.Groups.ToList();
            Accreditations = databaseContext.Accreditations.ToList();
        }
    }
}
