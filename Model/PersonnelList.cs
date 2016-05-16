using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class PersonnelList : BaseInpc
    {
        private string _personnelGroup
        {
            get;
            set;
        }
        public string PersonnelGroup
        {
            get { return _personnelGroup; }
            set
            {
                if (_personnelGroup != value)
                {
                    _personnelGroup = value;
                    OnPropertyChanged("PersonnelGroup");
                }
            }
        }

        private string _is30Selected
        {
            get;
            set;
        }
        public string Is30Selected
        {
            get { return _is30Selected; }
            set
            {
                if (_is30Selected != value)
                {
                    _is30Selected = value;
                    OnPropertyChanged("Is30Selected");
                }
            }
        }

        private string _is60Selected
        {
            get;
            set;
        }
        public string Is60Selected
        {
            get { return _is60Selected; }
            set
            {
                if (_is60Selected != value)
                {
                    _is60Selected = value;
                    OnPropertyChanged("Is60Selected");
                }
            }
        }

        private string _is90Selected
        {
            get;
            set;
        }
        public string Is90Selected
        {
            get { return _is90Selected; }
            set
            {
                if (_is90Selected != value)
                {
                    _is90Selected = value;
                    OnPropertyChanged("Is90Selected");
                }
            }
        }

        private string _is120Selected
        {
            get;
            set;
        }
        public string Is120Selected
        {
            get { return _is120Selected; }
            set
            {
                if (_is120Selected != value)
                {
                    _is120Selected = value;
                    OnPropertyChanged("Is120Selected");
                }
            }
        }

        public PersonnelList(string personnelGroup, string is30Selected, string is60Selected, string is90Selected, string is120Selected)
        {
            this._personnelGroup = personnelGroup;
            this._is30Selected = is30Selected;
            this._is60Selected = is60Selected;
            this._is90Selected = is90Selected;
            this._is120Selected = is120Selected;
        }
    }
}
