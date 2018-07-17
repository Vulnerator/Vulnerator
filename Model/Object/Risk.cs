using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Vulnerator.Model.Object
{
    public class Risk
    { 
        public string Likelihood { get; set; }
        public string Impact { get; set; }
        public string CalculatedRisk { get; set; }
        public Risk()
        { }
    }
}
