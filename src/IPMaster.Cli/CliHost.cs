using IPMaster.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IPMaster.Cli;

/// <summary>
/// Command-line mode of the single IPMaster executable (D-103): services, Ctrl+C cancellation and exit codes around
/// <see cref="CliApp"/>. Never references Avalonia, so the CLI runs on servers without a display.
/// </summary>
public static class CliHost
{
    public static async Task<int> RunAsync(string[] args)
    {
        var services = new ServiceCollection()
            .AddLogging(b => b.AddSimpleConsole(o => o.SingleLine = true)
                .AddFilter(level => level >= (Environment.GetEnvironmentVariable("IPMASTER_LOG") == "debug" ? LogLevel.Debug : LogLevel.Warning)))
            .AddIPMaster();

        // Console logs go to stderr so stdout stays machine-readable.
        services.Configure<Microsoft.Extensions.Logging.Console.ConsoleLoggerOptions>(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

        await using var provider = services.BuildServiceProvider();
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            if (cts.IsCancellationRequested) return; // second Ctrl+C terminates immediately
            e.Cancel = true;
            Console.Error.WriteLine();
            Console.Error.WriteLine("Stopping (press Ctrl+C again to abort)...");
            cts.Cancel();
        };

        var app = new CliApp(provider, Console.Out, Console.Error);
        try
        {
            return await app.RunAsync(args, cts.Token);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            await Console.Error.WriteLineAsync("Cancelled.");
            return ExitCodes.Cancelled;
        }
    }
}
