/*
  In App.xaml:
  <Application.Resources>
      <vm:ViewModelLocator xmlns:vm="clr-namespace:Vulnerator"
                           x:Key="Locator" />
  </Application.Resources>
  
  In the View:
  DataContext="{Binding Source={StaticResource Locator}, Path=ViewModelName}"

  You can also use Blend to do all this with the tool's support.
  See http://www.galasoft.ch/mvvm
*/

using GalaSoft.MvvmLight.Ioc;
//using Microsoft.Practices.ServiceLocation;

namespace Vulnerator.ViewModel
{
    /// <summary>
    /// This class contains static references to all the view models in the
    /// application and provides an entry point for the bindings.
    /// </summary>
    public class ViewModelLocator
    {
        /// <summary>
        /// Initializes a new instance of the ViewModelLocator class.
        /// </summary>
        public ViewModelLocator()
        {
            SimpleIoc.Default.Register<MainViewModel>();
            SimpleIoc.Default.Register<VulnerabilityViewModel>();
            SimpleIoc.Default.Register<UserGuideViewModel>();
            SimpleIoc.Default.Register<AboutViewModel>();
            SimpleIoc.Default.Register<NewsViewModel>();
            SimpleIoc.Default.Register<ThemeViewModel>();
            SimpleIoc.Default.Register<RmfViewModel>();
            SimpleIoc.Default.Register<SplashViewModel>();
            SimpleIoc.Default.Register<SettingsViewModel>();
            SimpleIoc.Default.Register<ConfigurationManagementViewModel>();
            SimpleIoc.Default.Register<MitigationsNistMappingViewModel>();
        }

        public AboutViewModel About
        { get { return SimpleIoc.Default.GetInstance<AboutViewModel>(); } }

        public MainViewModel Main
        { get { return SimpleIoc.Default.GetInstance<MainViewModel>(); } }

        public NewsViewModel News
        { get { return SimpleIoc.Default.GetInstance<NewsViewModel>(); } }

        public RmfViewModel Rmf
        { get { return SimpleIoc.Default.GetInstance<RmfViewModel>(); } }

        public SettingsViewModel Settings
        { get { return SimpleIoc.Default.GetInstance<SettingsViewModel>(); } }

        public SplashViewModel Splash
        { get { return SimpleIoc.Default.GetInstance<SplashViewModel>(); } }

        public ThemeViewModel Theme
        { get { return SimpleIoc.Default.GetInstance<ThemeViewModel>(); } }

        public UserGuideViewModel UserGuide
        { get { return SimpleIoc.Default.GetInstance<UserGuideViewModel>(); } }

        public VulnerabilityViewModel Vulnerability
        { get { return SimpleIoc.Default.GetInstance<VulnerabilityViewModel>(); } }

        public ConfigurationManagementViewModel ConfigurationManagement
        { get { return SimpleIoc.Default.GetInstance<ConfigurationManagementViewModel>(); } }

        public MitigationsNistMappingViewModel MitigationsNist
        { get { return SimpleIoc.Default.GetInstance<MitigationsNistMappingViewModel>(); } }

        public static void Cleanup()
        { }
    }
}