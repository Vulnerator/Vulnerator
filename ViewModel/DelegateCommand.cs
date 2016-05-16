using System;
using System.Windows.Input;

namespace Vulnerator.ViewModel
{
    class DelegateCommand : ICommand
    {
        private readonly Action _action;
        private readonly Action<object> _parameterizedAction;

        #region DelegateCommand, No Parameters

        public DelegateCommand(Action action)
        {
            _action = action;
        }

        #endregion

        #region DelegateCommand, One Parameter

        public DelegateCommand(Action<object> parameterizedAction)
        {
            _parameterizedAction = parameterizedAction;
        }

        #endregion

        #region Execute

        public void Execute (object param)
        {
            Action theAction = _action;
            Action<object> theParameterizedAction = _parameterizedAction;
            if (theAction != null)
            {
                theAction();
            }
            else if (theParameterizedAction != null)
            {
                theParameterizedAction(param);
            }
        }

        #endregion

        #region CanExecute

        public bool CanExecute(object parameter)
        {
            return true;
        }

        #endregion

        public event EventHandler CanExecuteChanged;
    }
}
