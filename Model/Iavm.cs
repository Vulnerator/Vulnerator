using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class Iavm : BaseInpc
    {
        private bool _isChecked
        {
            get;
            set;
        }
        public bool IsChecked
        {
            get { return _isChecked; }
            set
            {
                if (_isChecked != value)
                {
                    _isChecked = value;
                    OnPropertyChanged("IsChecked");
                }
            }
        }

        public string IavmNumber { get; set; }

        public string PluginNumber { get; set; }

        public string PluginTitle { get; set; }

        public string AffectedAsset { get; set; }

        public string Age { get; set; }

        public string SystemGroupName { get; set; }

        public Iavm(bool isChecked, string iavmNumber, string pluginNumber, string pluginTitle, string affectedAsset, string age, string systemGroupName)
        {
            this._isChecked = isChecked;
            this.IavmNumber = iavmNumber;
            this.PluginNumber = pluginNumber;
            this.PluginTitle = pluginTitle;
            this.AffectedAsset = affectedAsset;
            this.Age = age;
            this.SystemGroupName = systemGroupName;
        }
    }
}
