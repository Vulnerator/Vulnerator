using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class to store group name for display on the "Update Group" portion of the GUI via an AsyncObservableCollection
    /// </summary>
    public class UpdatableSystemGroup : BaseInpc
    {
        private string _groupName;
        /// <summary>
        /// Name of the system group to be created
        /// </summary>
        public string GroupName
        {
            get { return _groupName; }
            set
            {
                if (_groupName != value)
                {
                    _groupName = value;
                    OnPropertyChanged("GroupName");
                }
            }
        }

        /// <summary>
        /// Class to store group name for display on the "Update Group" portion of the GUI via an AsyncObservableCollection
        /// </summary>
        /// <param name="groupName">Name of the system group to be created</param>
        public UpdatableSystemGroup(string groupName)
        {
            this._groupName = groupName;
        }
    }
}
