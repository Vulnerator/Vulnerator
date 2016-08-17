using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class UpdateContactParameters : BaseInpc
    {
        private string _currentName;
        public string CurrentName
        {
            get { return _currentName; }
            set
            {
                if (_currentName != value)
                {
                    _currentName = value;
                    OnPropertyChanged("CurrentName");
                }
            }
        }

        private string _currentGroup;
        public string CurrentGroup
        {
            get { return _currentGroup; }
            set
            {
                if (_currentGroup != value)
                {
                    _currentGroup = value;
                    OnPropertyChanged("CurrentGroup");
                }
            }
        }

        private string _currentSystemName;
        public string CurrentSystemName
        {
            get { return _currentSystemName; }
            set
            {
                if (_currentSystemName != value)
                {
                    _currentSystemName = value;
                    OnPropertyChanged("CurrentSystemName");
                }
            }
        }

        private string _newName;
        public string NewName
        {
            get { return _newName; }
            set
            {
                if (_newName != value)
                {
                    _newName = value;
                    OnPropertyChanged("NewName");
                }
            }
        }

        private string _newTitle;
        public string NewTitle
        {
            get { return _newTitle; }
            set
            {
                if (_newTitle != value)
                {
                    _newTitle = value;
                    OnPropertyChanged("NewTitle");
                }
            }
        }

        private string _newEmail;
        public string NewEmail
        {
            get { return _newEmail; }
            set
            {
                if (_newEmail != value)
                {
                    _newEmail = value;
                    OnPropertyChanged("NewEmail");
                }
            }
        }

        private string _newGroupName;
        public string NewGroupName
        {
            get { return _newGroupName; }
            set
            {
                if (_newGroupName != value)
                {
                    _newGroupName = value;
                    OnPropertyChanged("NewGroupName");
                }
            }
        }

        private string _newSystemIp;
        public string NewSystemIp
        {
            get { return _newSystemIp; }
            set
            {
                if (_newSystemIp != value)
                {
                    _newSystemIp = value;
                    OnPropertyChanged("NewSystemIp");
                }
            }
        }

        private string _newSystemName;
        public string NewSystemName
        {
            get { return _newSystemName; }
            set
            {
                if (_newSystemName != value)
                {
                    _newSystemName = value;
                    OnPropertyChanged("NewSystemName");
                }
            }
        }
    }
}
