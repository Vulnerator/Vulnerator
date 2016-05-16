
namespace Vulnerator.Model
{
    public class CommandParameters : ViewModel.BaseInpc
    {
        public string _controlName;
        public string controlName 
        {
            get { return _controlName; } 
            set
            {
                _controlName = value;
                OnPropertyChanged("controlName");
            }
        }

        public string _controlValue;
        public string controlValue 
        {
            get { return _controlValue; } 
            set
            {
                _controlValue = value;
                OnPropertyChanged("controlValue");
            }
        }
    }
}
