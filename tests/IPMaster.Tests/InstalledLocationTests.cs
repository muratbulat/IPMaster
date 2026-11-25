using IPMaster.Infrastructure.Configuration;

namespace IPMaster.Tests;

/// <summary>D-105: a copy installed by the MSI keeps settings and history in the user profile, never next to the executable.</summary>
public class InstalledLocationTests
{
    [Fact]
    public void Installed_marker_moves_user_data_out_of_a_writable_program_folder()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-install-").FullName;
        try
        {
            var profile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "IPMaster");
            Assert.Equal(dir, SettingsStore.ResolveDefaultDirectory(dir, null)); // portable: writable folder
            File.WriteAllText(Path.Combine(dir, SettingsStore.InstalledMarker), "");
            Assert.Equal(profile, SettingsStore.ResolveDefaultDirectory(dir, null)); // installed, even when writable (elevated run)
            Assert.Equal("X:\\override", SettingsStore.ResolveDefaultDirectory(dir, "X:\\override"));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
