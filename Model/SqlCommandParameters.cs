using System.Collections.Generic;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class SqlCommandParameters : BaseInpc
    {
        private List<string> _sqlParameters;
        public List<string> SqlParameters
        {
            get { return _sqlParameters; }
            set
            {
                if (_sqlParameters != value)
                {
                    _sqlParameters = value;
                    OnPropertyChanged("SqlParameters");
                }
            }
        }
    }
}
