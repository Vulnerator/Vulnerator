using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Vulnerator.Model
{
    public class AssetOverviewLineItem
    {
        public string AssetToReport = string.Empty;
        public string HostName = string.Empty;
        public string IpAddress = string.Empty;
        public string FileName = string.Empty;
        public string Credentialed = string.Empty;
        public string OperatingSystem = string.Empty;
        public string GroupName = string.Empty;
        public int CatI = 0;
        public int CatII = 0;
        public int CatIII = 0;
        public int CatIV = 0;
        public int Total = 0;
        public int ScapScore = 0;
        public bool plugin21745Found = false;
        public bool plugin26917Found = false;

        public AssetOverviewLineItem(string assetToReport)
        { this.AssetToReport = assetToReport; }

        public void IncreaseCatIAndTotalCounts()
        { 
            this.CatI++;
            this.Total++;
        }

        public void IncreaseCatIIAndTotalCounts()
        {
            this.CatII++;
            this.Total++;
        }
        public void IncreaseCatIIIAndTotalCounts()
        {
            this.CatIII++;
            this.Total++;
        }
        public void IncreaseCatIVAndTotalCounts()
        {
            this.CatIV++;
            this.Total++;
        }
    }
}
