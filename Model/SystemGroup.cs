using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class to store system group name and MAC level for display on the GUI via an AsyncObservableCollection
    /// </summary>
    public class SystemGroup : BaseInpc
    {
        private string _groupNameAndMacLevel
        {
            get;
            set;
        }
        /// <summary>
        /// Name and MAC level of the SystemGroup to be created
        /// </summary>
        public string GroupNameAndMacLevel
        {
            get { return _groupNameAndMacLevel; }
            set
            {
                if (_groupNameAndMacLevel != value)
                {
                    _groupNameAndMacLevel = value;
                    OnPropertyChanged("GroupNameAndMacLevel");
                }
            }
        }

        /// <summary>
        /// Class to store system group name and MAC level for display on the GUI via an AsyncObservableCollection
        /// </summary>
        /// <param name="groupNameAndMacLevel">Name and MAC level of the SystemGroup to be created</param>
        public SystemGroup(string groupNameAndMacLevel)
        {
            this._groupNameAndMacLevel = groupNameAndMacLevel;
        }
    }
}
