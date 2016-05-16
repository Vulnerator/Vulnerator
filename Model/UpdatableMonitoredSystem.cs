using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class to store user-provided system for display on the "Update System" portion of the GUI via an AsyncObservableCollection
    /// </summary>
    public class UpdatableMonitoredSystem : BaseInpc
    {
        private string _systemGroupAndNameAndIp;
        /// <summary>
        /// System group, host name, and IP address of the system to be created
        /// </summary>
        public string SystemGroupAndNameAndIp
        {
            get { return _systemGroupAndNameAndIp; }
            set
            {
                if (_systemGroupAndNameAndIp != value)
                {
                    _systemGroupAndNameAndIp = value;
                    OnPropertyChanged("SystemGroupAndNameAndIp");
                }
            }
        }

        /// <summary>
        /// Class to store user-provided system for display on the "Update System" portion of the GUI via an AsyncObservableCollection
        /// </summary>
        /// <param name="systemGroupAndNameAndIp">System group, host name, and IP address of the system to be created</param>
        public UpdatableMonitoredSystem(string systemGroupAndNameAndIp)
        {
            this._systemGroupAndNameAndIp = systemGroupAndNameAndIp;
        }
    }
}
