using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class MacLevel : BaseInpc
    {
        private string _macLevelNumber
        {
            get;
            set;
        }
        public string MacLevelNumber
        {
            get { return _macLevelNumber; }
            set
            {
                if (_macLevelNumber != value)
                {
                    _macLevelNumber = value;
                    OnPropertyChanged("MacLevelNumber");
                }
            }
        }

        public MacLevel(string macLevelNumber)
        {
            this._macLevelNumber = macLevelNumber;
        }
    }
}
