using GalaSoft.MvvmLight;

namespace Vulnerator.Model.Object
{
    public class File : ViewModelBase
    {
        private string _fileName;
        public string FileName
        {
            get { return _fileName; }
            set
            {
                if (_fileName != value)
                {
                    _fileName = value;
                    RaisePropertyChanged("FileName");
                }
            }
        }

        private string _fileType;
        public string FileType
        {
            get { return _fileType; }
            set
            {
                if (_fileType != value)
                {
                    _fileType = value;
                    RaisePropertyChanged("FileType");
                }
            }
        }

        private string _status;
        public string Status
        {
            get { return _status; }
            set
            {
                if (_status != value)
                {
                    _status = value;
                    RaisePropertyChanged("Status");
                }
            }
        }

        private string _filePath;
        public string FilePath
        {
            get { return _filePath; }
            set
            {
                if (_filePath != value)
                {
                    _filePath = value;
                    RaisePropertyChanged("FilePath");
                }
            }
        }

        private string _identifiersProvided;
        public string IdentifiersProvided
        {
            get { return _identifiersProvided; }
            set
            {
                if (_identifiersProvided != value)
                {
                    _identifiersProvided = value;
                    RaisePropertyChanged("IdentifiersProvided");
                }
            }
        }

        private string _fileHostName;
        public string FileHostName
        {
            get { return _fileHostName; }
            set
            {
                if (_fileHostName != value)
                {
                    _fileHostName = value;
                    RaisePropertyChanged("FileHostName");
                }
            }
        }

        private string _fileIpAddress;
        public string FileIpAddress
        {
            get { return _fileIpAddress; }
            set
            {
                if (_fileIpAddress != value)
                {
                    _fileIpAddress = value;
                    RaisePropertyChanged("FileIpAddress");
                }
            }
        }

        private string _fileMacAddress;
        public string FileMacAddress
        {
            get { return _fileMacAddress; }
            set
            {
                if (_fileMacAddress != value)
                {
                    _fileMacAddress = value;
                    RaisePropertyChanged("FileMacAddress");
                }
            }
        }


        public File(string fileName, string fileType, string status, string filePath, string hostNameProvided)
        {
            _fileName = fileName;
            _fileType = fileType;
            _status = status;
            _filePath = filePath;
            _identifiersProvided = hostNameProvided;
        }

        public void SetFileHostName(string hostName)
        { _fileHostName = hostName; }

        public void SetFileIpAddress(string ipAddress)
        { _fileIpAddress = ipAddress; }

        public void SetFileMacAddress(string macAddress)
        { _fileMacAddress = macAddress; }
    }
}
