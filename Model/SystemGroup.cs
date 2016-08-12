using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class to store system group name and MAC level for display on the GUI via an AsyncObservableCollection
    /// </summary>
    public class SystemGroup : BaseInpc
    {
        private string _groupName
        {
            get;
            set;
        }
        /// <summary>
        /// Name and MAC level of the SystemGroup to be created
        /// </summary>
        public string GroupName
        {
            get { return _groupName; }
            set
            {
                if (_groupName != value)
                {
                    _groupName = value;
                    OnPropertyChanged("GroupName");
                }
            }
        }

        /// <summary>
        /// Class to store system group name and MAC level for display on the GUI via an AsyncObservableCollection
        /// </summary>
        /// <param name="groupName">Name and MAC level of the SystemGroup to be created</param>
        public SystemGroup(string groupName)
        {
            this._groupName = groupName;
        }
    }
}
