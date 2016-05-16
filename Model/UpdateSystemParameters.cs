using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class UpdateSystemParameters : BaseInpc
    {
        private string _updatedSystemGroup;
        public string UpdatedSystemGroup
        {
            get { return _updatedSystemGroup; }
            set
            {
                if (_updatedSystemGroup != value)
                {
                    _updatedSystemGroup = value;
                    OnPropertyChanged("UpdatedSystemGroup");
                }
            }
        }
        
        private string _updatedSystemName;
        public string UpdatedSystemName
        {
            get { return _updatedSystemName; }
            set
            {
                if (_updatedSystemName != value)
                {
                    _updatedSystemName = value;
                    OnPropertyChanged("UpdatedSystemName");
                }
            }
        }

        private string _updatedSystemIp;
        public string UpdatedSystemIP
        {
            get { return _updatedSystemIp; }
            set
            {
                if (_updatedSystemIp != value)
                {
                    _updatedSystemIp = value;
                    OnPropertyChanged("UpdatedSystemIP");
                }
            }
        }
    }
}
