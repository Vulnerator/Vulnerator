using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Messaging;
using Vulnerator.Helper;

namespace Vulnerator.ViewModel
{
    public class LoadingViewModel : ViewModelBase
    {
        private string _loadingActionText = string.Empty;
        public string LoadingActionText
        {
            get => _loadingActionText;
            set
            {
                if (_loadingActionText != value)
                {
                    _loadingActionText = value;
                    RaisePropertyChanged("LoadingActionText");
                }
            }
        }

        public LoadingViewModel()
        {
            try
            {
                
                Messenger.Default.Register<string>(this, MessengerToken.LoadingTextUpdated, SetLoadingActionText);
                LogWriter.LogStatusUpdate("'InstantiateNewDatabase' Messenger registered.");
                LogWriter.LogStatusUpdate("'MainViewModel' successfully initialized.");
            }
            catch (Exception exception)
            {
                string error = "Unable to initialize 'LoadingViewModel'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetLoadingActionText(string loadingActionText)
        {
            try
            {
                LoadingActionText = loadingActionText;
            }
            catch (Exception exception)
            {
                string error = "Unable to set loading action text.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }
    }
}
