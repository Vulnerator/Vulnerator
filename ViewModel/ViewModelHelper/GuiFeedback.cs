using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Vulnerator.ViewModel.ViewModelHelper
{
    public class GuiFeedback
    {
        public string ProgressLabelText { get; set; }
        public string ProgressRingVisibility { get; set; }
        public bool IsEnabled { get; set; }

        public GuiFeedback()
        { }

        public void SetFields(string progressLabelText, string progressRingVisibility, bool isEnabled)
        {
            ProgressLabelText = progressLabelText;
            ProgressRingVisibility = progressRingVisibility;
            IsEnabled = isEnabled;
        }
    }
}
