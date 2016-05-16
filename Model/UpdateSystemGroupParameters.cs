using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class UpdateSystemGroupParameters : BaseInpc
    {
        private string _updatedSystemGroupName;
        public string UpdatedSystemGroupName
        {
            get { return _updatedSystemGroupName; }
            set
            {
                if (_updatedSystemGroupName != value)
                {
                    _updatedSystemGroupName = value;
                    OnPropertyChanged("UpdatedSystemGroupName");
                }
            }
        }

        private string _updatedSystemGroupMacLevel;
        public string UpdatedSystemGroupMacLevel
        {
            get { return _updatedSystemGroupMacLevel; }
            set
            {
                if (_updatedSystemGroupMacLevel != value)
                {
                    _updatedSystemGroupMacLevel = value;
                    OnPropertyChanged("UpdatedSystemGroupMacLevel");
                }
            }
        }
    }
}
