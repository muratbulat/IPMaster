using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
using IPMaster.Desktop.ViewModels;
using IPMaster.Desktop.Views;
using IPMaster.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IPMaster.Desktop;

public partial class App : Application
{
    private ServiceProvider? _services;

    /// <summary>Null follows the operating system (ThemeVariant.Default tracks OS changes live).</summary>
    public static void ApplyTheme(bool? dark)
    {
        if (Current is { } app) app.RequestedThemeVariant = dark is null ? ThemeVariant.Default : dark.Value ? ThemeVariant.Dark : ThemeVariant.Light;
    }

    public static bool IsDark => Current?.ActualThemeVariant == ThemeVariant.Dark;

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
        Styling.TrimmedTextTips.Register(); // full values for shortened table cells
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            _services = new ServiceCollection()
                .AddLogging(b => b.SetMinimumLevel(LogLevel.Warning))
                .AddIPMaster()
                .AddSingleton<MainWindowViewModel>()
                .BuildServiceProvider();
            var vm = _services.GetRequiredService<MainWindowViewModel>();
            var args = desktop.Args ?? [];
            vm.IsSecondaryWindow = args.Contains("--new-window", StringComparer.Ordinal);
            var ranges = new List<RangeEntryViewModel>();
            for (var i = 0; i + 1 < args.Length; i++)
            {
                if (args[i] == "--range") ranges.Add(RangeEntryViewModel.From(new Core.Configuration.RangeEntry { Target = args[++i] }));
            }

            if (ranges.Count > 0) vm.SetRanges(ranges, append: false);
            var window = new MainWindow { DataContext = vm };
            vm.Dialogs = window;
            desktop.MainWindow = window;
            desktop.Exit += (_, _) => _services.Dispose();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
