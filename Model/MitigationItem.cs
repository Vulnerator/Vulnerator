using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class to store user-provided mitigations for display on the GUI via an AsyncObservableCollection
    /// </summary>
    public class MitigationItem : BaseInpc
    {
        private string _mitigationVulnerabilityId
        {
            get;
            set;
        }
        /// <summary>
        /// Vulnerability ID associated with the to be created MitigationItem
        /// </summary>
        public string MitigationVulnerabilityId
        {
            get { return _mitigationVulnerabilityId; }
            set
            {
                if (_mitigationVulnerabilityId != value)
                {
                    _mitigationVulnerabilityId = value;
                    OnPropertyChanged("MitigationVulnerabilityId");
                }
            }
        }

        private string _mitigationGroupName
        {
            get;
            set;
        }
        /// <summary>
        /// System group associated with the to be created MitigationItem
        /// </summary>
        public string MitigationGroupName
        {
            get { return _mitigationGroupName; }
            set
            {
                if (_mitigationGroupName != value)
                {
                    _mitigationGroupName = value;
                    OnPropertyChanged("MitigationGroupName");
                }
            }
        }

        private string _mitigationStatus
        {
            get;
            set;
        }
        /// <summary>
        /// Mitigation status associated with the to be created MitigationItem
        /// </summary>
        public string MitigationStatus
        {
            get { return _mitigationStatus; }
            set
            {
                if (_mitigationStatus != value)
                {
                    _mitigationStatus = value;
                    OnPropertyChanged("MitigationStatus");
                }
            }
        }

        private string _mitigationText
        {
            get;
            set;
        }
        /// <summary>
        /// Mitigation text associated with the to be created MitigationItem
        /// </summary>
        public string MitigationText
        {
            get { return _mitigationText; }
            set
            {
                if (_mitigationText != value)
                {
                    _mitigationText = value;
                    OnPropertyChanged("MitigationText");
                }
            }
        }

        private bool _isChecked;
        /// <summary>
        /// Boolean value determining whether the MitigationItem is checked in the GUI DataGrid
        /// </summary>
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

        /// <summary>
        /// Class to store user-provided mitigations for display on the GUI via an AsyncObservableCollection
        /// </summary>
        /// <param name="mitigationVulnerabilityId">Vulnerability ID associated with the to be created MitigationItem</param>
        /// <param name="mitigationGroupName">System group associated with the to be created MitigationItem</param>
        /// <param name="mitigationStatus">Mitigation status associated with the to be created MitigationItem</param>
        /// <param name="mitigationText">Mitigation text associated with the to be created MitigationItem</param>
        /// <param name="isChecked">Boolean value determining whether the MitigationItem is checked in the GUI DataGrid</param>
        public MitigationItem(string mitigationVulnerabilityId, string mitigationGroupName, string mitigationStatus, string mitigationText, bool isChecked)
        {
            this._mitigationVulnerabilityId = mitigationVulnerabilityId;
            this._mitigationGroupName = mitigationGroupName;
            this._mitigationStatus = mitigationStatus;
            this._mitigationText = mitigationText;
            this._isChecked = isChecked;
        }
    }
}
