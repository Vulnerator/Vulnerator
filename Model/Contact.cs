using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class to store contact information for display on the GUI via an AsyncObservableCollection
    /// </summary>
    public class Contact : BaseInpc
    {
        private string _contactName
        {
            get;
            set;
        }
        /// <summary>
        /// Personnel name for the created Contact
        /// </summary>
        public string ContactName
        {
            get { return _contactName; }
            set
            {
                if (_contactName != value)
                {
                    _contactName = value;
                    OnPropertyChanged("ContactName");
                }
            }
        }

        private string _contactTitle
        {
            get;
            set;
        }
        /// <summary>
        /// Title of the created Contact
        /// </summary>
        public string ContactTitle
        {
            get { return _contactTitle; }
            set
            {
                if (_contactTitle != value)
                {
                    _contactTitle = value;
                    OnPropertyChanged("ContactTitle");
                }
            }
        }

        private string _contactEmail
        {
            get;
            set;
        }
        /// <summary>
        /// Email of the created Contact
        /// </summary>
        public string ContactEmail
        {
            get { return _contactEmail; }
            set
            {
                if (_contactEmail != value)
                {
                    _contactEmail = value;
                    OnPropertyChanged("ContactEmail");
                }
            }
        }

        private string _contactGroupName
        {
            get;
            set;
        }
        /// <summary>
        /// System group that the created Contact is to be associated with
        /// </summary>
        public string ContactGroupName
        {
            get { return _contactGroupName; }
            set
            {
                if (_contactGroupName != value)
                {
                    _contactGroupName = value;
                    OnPropertyChanged("ContactGroupName");
                }
            }
        }

        private string _contactSystemIp
        {
            get;
            set;
        }
        /// <summary>
        /// IP address of the system that the created Contact is to be associated with
        /// </summary>
        public string ContactSystemIp
        {
            get { return _contactSystemIp; }
            set
            {
                if (_contactSystemIp != value)
                {
                    _contactSystemIp = value;
                    OnPropertyChanged("ContactSystemIp");
                }
            }
        }

        private string _contactSystemName
        {
            get;
            set;
        }
        /// <summary>
        /// Host name of the system that the created Contact is to be associated with
        /// </summary>
        public string ContactSystemName
        {
            get { return _contactSystemName; }
            set
            {
                if (_contactSystemName != value)
                {
                    _contactSystemName = value;
                    OnPropertyChanged("ContactSystemName");
                }
            }
        }

        private bool _isChecked
        {
            get;
            set;
        }
        /// <summary>
        /// Boolean value determining whether the Contact is checked in the GUI DataGrid
        /// </summary>
        public bool IsChecked
        {
            get { return _isChecked; }
            set
            {
                if (_isChecked != value)
                {
                    _isChecked = value;
                    OnPropertyChanged("IsChecked");
                }
            }
        }

        /// <summary>
        /// Class to store contact information for display on the GUI via an AsyncObservableCollection
        /// </summary>
        /// <param name="ContactName">Personnel name for the created Contact</param>
        /// <param name="contactGroupName">System group that the created Contact is to be associated with</param>
        /// <param name="contactGroupMacLevel">MAC level of the system group that the created Contact is to be associated with</param>
        /// <param name="ContactEmail">Email of the created Contact</param>
        /// <param name="contactTitle">Title of the created Contact</param>
        /// <param name="contactSystemIp">IP address of the system that the created Contact is to be associated with</param>
        /// <param name="contactSystemName">Host name of the system that the created Contact is to be associated with</param>
        /// <param name="isChecked">Boolean value determining whether the Contact is checked in the GUI DataGrid</param>
        public Contact(string contactName, string contactGroupName, string contactEmail, string contactTitle, 
            string contactSystemIp, string contactSystemName, bool isChecked)
        {
            this._contactName = contactName;
            this._contactGroupName = contactGroupName;
            this._contactEmail = contactEmail;
            this._contactTitle = contactTitle;
            this._contactSystemIp = contactSystemIp;
            this._contactSystemName = contactSystemName;
            this._isChecked = isChecked;
        }
    }
}
