using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using IPMaster.Core.Configuration;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Desktop.ViewModels;

/// <summary>One address-bar entry.</summary>
public sealed partial class RangeEntryViewModel : ObservableObject
{
    [ObservableProperty]
    public partial string Target { get; set; } = "";

    [ObservableProperty]
    public partial bool Enabled { get; set; } = true;

    [ObservableProperty]
    public partial bool OctetMode { get; set; }

    [ObservableProperty]
    public partial string Comment { get; set; } = "";

    [ObservableProperty]
    public partial string? Error { get; set; }

    public static RangeEntryViewModel From(RangeEntry e) => new()
    {
        Target = e.Target,
        Enabled = e.Enabled,
        OctetMode = e.OctetMode,
        Comment = e.Comment,
    };

    public RangeEntry ToModel() => new() { Target = Target.Trim(), Enabled = Enabled, OctetMode = OctetMode, Comment = Comment.Trim() };

    partial void OnTargetChanged(string value) => Validate();

    partial void OnOctetModeChanged(bool value) => Validate();

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Target))
        {
            Error = null;
            return;
        }

        foreach (var part in Target.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TargetParser.TryParse(part, OctetMode, out _, out var error))
            {
                Error = error;
                return;
            }
        }

        Error = null;
    }
}

