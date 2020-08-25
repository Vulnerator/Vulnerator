using System.Windows;
using System.Windows.Input;
using Microsoft.Xaml.Behaviors;

namespace Vulnerator.ViewModel
{
    public sealed class EventCommand : TriggerAction<DependencyObject>
    {

        public static readonly DependencyProperty CommandParameterProperty =
            DependencyProperty.Register("CommandParameter", typeof(object), typeof(EventCommand), null);


        public static readonly DependencyProperty CommandProperty = DependencyProperty.Register(
            "Command", typeof(ICommand), typeof(EventCommand), null);


        public static readonly DependencyProperty InvokeParameterProperty = DependencyProperty.Register(
            "InvokeParameter", typeof(object), typeof(EventCommand), null);

        private string commandName;

        public object InvokeParameter
        {
            get => GetValue(InvokeParameterProperty);
            set => SetValue(InvokeParameterProperty, value);
        }


        public ICommand Command
        {
            get => (ICommand)GetValue(CommandProperty);
            set => SetValue(CommandProperty, value);
        }

        public string CommandName
        {
            get => commandName;
            set
            {
                if (CommandName != value)
                {
                    commandName = value;
                }
            }
        }

        public object CommandParameter
        {
            get => GetValue(CommandParameterProperty);

            set => SetValue(CommandParameterProperty, value);
        }

        public object Sender { get; set; }

        protected override void Invoke(object parameter)
        {
            InvokeParameter = parameter;
            if (AssociatedObject != null)
            {
                ICommand command = Command;
                if ((command != null) && command.CanExecute(CommandParameter))
                {
                    command.Execute(CommandParameter);
                }
            }
        }
    }
}
