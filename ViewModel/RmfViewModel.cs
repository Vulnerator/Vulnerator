using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using System;

namespace Vulnerator.ViewModel
{
    public class RmfViewModel : ViewModelBase
    {
        private bool _isBackgroundPaneOpen = false;
        public bool IsBackgroundPaneOpen
        {
            get => _isBackgroundPaneOpen;
            set
            {
                if (_isBackgroundPaneOpen != value)
                {
                    _isBackgroundPaneOpen = value;
                    RaisePropertyChanged("IsBackgroundPaneOpen");
                }
            }
        }

        public RelayCommand<object> TogglePaneCommand
        { get { return new RelayCommand<object>((p) => TogglePane(p)); } }
        private void TogglePane(object parameter)
        {
            switch (parameter.ToString())
            {
                case "backgroundButton":
                    {
                        IsBackgroundPaneOpen = !IsBackgroundPaneOpen;
                        break;
                    }
                default:
                    { break; }
            }
        }
    }
}
