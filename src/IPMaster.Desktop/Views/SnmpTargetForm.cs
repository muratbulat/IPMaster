using System.Net;
using Avalonia;
using Avalonia.Controls;
using IPMaster.Core.Queries;
using IPMaster.Infrastructure.Queries;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Agent, version and credentials of an SNMP request (v1/v2c community, v3 user/auth/priv), shared by the SNMP Tester and
/// the SNMP Interface Monitor (D-091). Secrets are masked and live only in these boxes.
/// </summary>
internal sealed class SnmpTargetForm
{
    public SnmpTargetForm(string? target = null)
    {
        Host = ToolKit.Text("Agent", "host or IP", 170, target ?? "");
        Port = ToolKit.Number(161, 1, 65535, "Port", 70);
        Version = ToolKit.Combo("SNMP version", ["v1", "v2c", "v3"], 1, 80);
        Community = ToolKit.Text("Community", "community", 130);
        Community.PasswordChar = '•';
        User = ToolKit.Text("User name", "user", 110);
        Level = ToolKit.Combo("Security level", ["noAuthNoPriv", "authNoPriv", "authPriv"], 2, 130);
        Auth = ToolKit.Combo("Authentication protocol", ["MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"], 3, 100);
        AuthPassword = ToolKit.Text("Authentication password", "auth password", 120);
        AuthPassword.PasswordChar = '•';
        Priv = ToolKit.Combo("Privacy protocol", ["DES", "3DES", "AES-128", "AES-192", "AES-256", "AES-192 (Blumenthal)", "AES-256 (Blumenthal)"], 2, 120);
        PrivPassword = ToolKit.Text("Privacy password", "priv password", 120);
        PrivPassword.PasswordChar = '•';

        var communityPair = Pair("Community", Community);
        var userPair = Pair("User", User, Level);
        var authPair = Pair("Auth", Auth, AuthPassword);
        var privPair = Pair("Priv", Priv, PrivPassword);
        Row = new WrapPanel { Children = { Pair("Agent", Host, Port), Pair("Version", Version), communityPair, userPair, authPair, privPair } };
        void Visibility()
        {
            var v3 = Version.SelectedIndex == 2;
            communityPair.IsVisible = !v3;
            userPair.IsVisible = v3;
            authPair.IsVisible = v3 && Level.SelectedIndex >= 1;
            privPair.IsVisible = v3 && Level.SelectedIndex == 2;
        }

        Version.SelectionChanged += (_, _) => Visibility();
        Level.SelectionChanged += (_, _) => Visibility();
        Visibility();
    }

    public TextBox Host { get; }

    public NumericUpDown Port { get; }

    public ComboBox Version { get; }

    public TextBox Community { get; }

    public TextBox User { get; }

    public ComboBox Level { get; }

    public ComboBox Auth { get; }

    public TextBox AuthPassword { get; }

    public ComboBox Priv { get; }

    public TextBox PrivPassword { get; }

    /// <summary>The agent row (wraps on narrow windows).</summary>
    public WrapPanel Row { get; }

    public SnmpVersion SelectedVersion => (SnmpVersion)Version.SelectedIndex;

    /// <summary>Compact inline label + controls.</summary>
    public static Control Pair(string label, params Control[] controls)
    {
        var p = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, Spacing = 4, Margin = new Thickness(0, 0, 12, 4) };
        p.Children.Add(new TextBlock { Text = label, VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center, Classes = { "label" } });
        foreach (var c in controls) p.Children.Add(c);
        return p;
    }

    /// <summary>Checks the inputs on the UI thread; null when complete, else what is missing.</summary>
    public string? Validate()
    {
        if ((Host.Text?.Trim() ?? "").Length == 0) return "Enter the agent.";
        if (SelectedVersion != SnmpVersion.V3 && string.IsNullOrEmpty(Community.Text)) return "Enter the community.";
        if (SelectedVersion == SnmpVersion.V3 && string.IsNullOrWhiteSpace(User.Text)) return "Enter the user.";
        return null;
    }

    /// <summary>The same port and credentials for any address (topology exploration); read on the UI thread.</summary>
    public Func<IPAddress, SnmpTarget> For()
    {
        var port = (int)(Port.Value ?? 161);
        var version = SelectedVersion;
        var (community, user, level, auth, authPassword, priv, privPassword) = (Community.Text ?? "", User.Text?.Trim() ?? "", (SnmpSecurity)Level.SelectedIndex,
            (SnmpAuth)Auth.SelectedIndex, AuthPassword.Text ?? "", (SnmpPriv)Priv.SelectedIndex, PrivPassword.Text ?? "");
        return address => new SnmpTarget(new IPEndPoint(address, port), version, version == SnmpVersion.V3 ? [] : [community], user, level, auth, authPassword, priv, privPassword);
    }

    /// <summary>Reads the inputs (call on the UI thread) and returns a resolver that builds the target off the UI thread.</summary>
    public Func<CancellationToken, Task<(SnmpTarget? Target, string? Error)>> Snapshot()
    {
        var name = Host.Text?.Trim() ?? "";
        var port = (int)(Port.Value ?? 161);
        var version = SelectedVersion;
        var community = Community.Text ?? "";
        var user = User.Text?.Trim() ?? "";
        var level = (SnmpSecurity)Level.SelectedIndex;
        var auth = (SnmpAuth)Auth.SelectedIndex;
        var authPassword = AuthPassword.Text ?? "";
        var priv = (SnmpPriv)Priv.SelectedIndex;
        var privPassword = PrivPassword.Text ?? "";
        return async ct =>
        {
            if (!IPAddress.TryParse(name, out var address))
            {
                try
                {
                    address = (await Dns.GetHostAddressesAsync(name, ct)).OrderBy(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 0 : 1).First();
                }
                catch (Exception ex) when (ex is System.Net.Sockets.SocketException or InvalidOperationException)
                {
                    return (null, "Agent not found. Check the name.");
                }
            }

            return (new SnmpTarget(new IPEndPoint(address, port), version, version == SnmpVersion.V3 ? [] : [community], user, level, auth, authPassword, priv, privPassword), null);
        };
    }
}
