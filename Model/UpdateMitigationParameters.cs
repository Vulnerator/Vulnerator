using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class UpdateMitigationParameters : BaseInpc
    {
        private string _currentGroupName;
        public string CurrentGroupName
        {
            get { return _currentGroupName; }
            set
            {
                if (_currentGroupName != value)
                {
                    _currentGroupName = value;
                    OnPropertyChanged("CurrentGroupName");
                }
            }
        }

        private string _vulnerabilityId;
        public string VulnerabilityId
        {
            get { return _vulnerabilityId; }
            set
            {
                if (_vulnerabilityId != value)
                {
                    _vulnerabilityId = value;
                    OnPropertyChanged("VulnerabilityId");
                }
            }
        }
    }
}
