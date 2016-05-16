using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class RssItem : BaseInpc
    {
        private string _title
        { get; set; }
        public string Title
        {
            get { return _title; }
            set
            {
                if (_title != value)
                {
                    _title = value;
                    OnPropertyChanged("Title");
                }
            }
        }
    }
}
