using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Vulnerator.Model.Object
{
    public class Likelihood
    {
        public string SeverityOrPervasiveness { get; set; }
        public string Relevance { get; set; }
        public string CalculatedLikelihood { get; set; }
        public Likelihood()
        { }
    }
}
