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
    }
}
