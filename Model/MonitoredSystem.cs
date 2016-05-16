using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class to store user-provided system for display on the GUI via an AsyncObservableCollection
    /// </summary>
    public class MonitoredSystem : BaseInpc
    {
        private string _systemNameAndIp
        {
            get;
            set;
        }
        /// <summary>
        /// Name and IP address of the MonitoredSystem to be created
        /// </summary>
        public string SystemNameAndIp
        {
            get { return _systemNameAndIp; }
            set
            {
                if (_systemNameAndIp != value)
                {
                    _systemNameAndIp = value;
                    OnPropertyChanged("SystemNameAndIp");
                }
            }
        }

        /// <summary>
        /// Class to store user-provided system for display on the GUI via an AsyncObservableCollection
        /// </summary>
        /// <param name="systemNameAndIp">Name and IP address of the MonitoredSystem to be created</param>
        public MonitoredSystem(string systemNameAndIp)
        {
            this._systemNameAndIp = systemNameAndIp;
        }
    }
}
