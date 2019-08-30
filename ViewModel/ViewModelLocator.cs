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
            SimpleIoc.Default.Register<ReportingViewModel>();
            SimpleIoc.Default.Register<RmfViewModel>();
            SimpleIoc.Default.Register<SplashViewModel>();
            SimpleIoc.Default.Register<SettingsViewModel>();
            SimpleIoc.Default.Register<ConfigurationManagementViewModel>();
        }

        public AboutViewModel About => SimpleIoc.Default.GetInstance<AboutViewModel>();

        public MainViewModel Main => SimpleIoc.Default.GetInstance<MainViewModel>();

        public NewsViewModel News => SimpleIoc.Default.GetInstance<NewsViewModel>();

        public ReportingViewModel Reporting => SimpleIoc.Default.GetInstance<ReportingViewModel>();

        public RmfViewModel Rmf => SimpleIoc.Default.GetInstance<RmfViewModel>();

        public SettingsViewModel Settings => SimpleIoc.Default.GetInstance<SettingsViewModel>();

        public SplashViewModel Splash => SimpleIoc.Default.GetInstance<SplashViewModel>();

        public ThemeViewModel Theme => SimpleIoc.Default.GetInstance<ThemeViewModel>();

        public UserGuideViewModel UserGuide => SimpleIoc.Default.GetInstance<UserGuideViewModel>();

        public VulnerabilityViewModel Vulnerability => SimpleIoc.Default.GetInstance<VulnerabilityViewModel>();

        public ConfigurationManagementViewModel ConfigurationManagement => SimpleIoc.Default.GetInstance<ConfigurationManagementViewModel>();

        public static void Cleanup()
        { }
    }
}