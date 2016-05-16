using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class to store contact title for display on the GUI via an AsyncObservableCollection
    /// </summary>
    public class ContactTitle : BaseInpc
    {
        private string _contactTitleName
        {
            get;
            set;
        }
        /// <summary>
        /// Title name for the created ContactTitle
        /// </summary>
        public string ContactTitleName
        {
            get { return _contactTitleName; }
            set
            {
                if (_contactTitleName != value)
                {
                    _contactTitleName = value;
                    OnPropertyChanged("ContactTitleName");
                }
            }
        }

        /// <summary>
        /// Class to store contact title for display on the GUI via an AsyncObservableCollection
        /// </summary>
        /// <param name="contactTitleName">Title name for the created ContactTitle</param>
        public ContactTitle(string contactTitleName)
        {
            this._contactTitleName = contactTitleName;
        }
    }
}
