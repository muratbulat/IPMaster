using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.VisualTree;
using IPMaster.Desktop.ViewModels;
using IPMaster.Desktop.Views;

namespace IPMaster.Tests;

/// <summary>Address bar: IP field about 500 px and comment about 280 px at full width, both shrink, buttons follow, nothing overflows.</summary>
[Collection("Headless UI")]
public class AddressBarLayoutTests
{
    private static Rect Bounds(Control c, Visual root) => new(c.TranslatePoint(new Point(0, 0), root)!.Value, c.Bounds.Size);

    [Theory]
    [InlineData(1800)]
    [InlineData(1180)]
    [InlineData(900)]
    [InlineData(680)]
    public Task Fields_are_capped_shrink_and_never_overflow(double width) => HeadlessUi.Run(() =>
    {
        var vm = HeadlessUi.Vm;
        var saved = vm.Ranges.ToList();
        vm.SetRanges([new RangeEntryViewModel { Target = "192.0.2.1-192.0.2.254" }, new RangeEntryViewModel { Target = "198.51.100.0/24", Comment = "Lab" }], append: false);
        var w = new MainWindow { DataContext = vm, Width = width, Height = 700 };
        w.Show();
        try
        {
            w.Width = width;
            UiDesignSystemTests.Dispatch();
            var ips = w.GetVisualDescendants().OfType<TextBox>().Where(t => AutomationProperties.GetName(t) == "IP range").ToList();
            var comments = w.GetVisualDescendants().OfType<TextBox>().Where(t => AutomationProperties.GetName(t) == "Range comment").ToList();
            var add = w.GetVisualDescendants().OfType<Button>().Single(b => AutomationProperties.GetName(b) == "Add a range");
            Assert.Equal(2, ips.Count);
            HeadlessUi.Snapshot(w, $"Address bar {width}");
            var ip = Bounds(ips[0], w);
            var comment = Bounds(comments[0], w);
            var addBox = Bounds(add, w);
            var remove = Bounds(w.GetVisualDescendants().OfType<Button>().First(b => AutomationProperties.GetName(b) == "Remove this range"), w);
            TestContext.Current.TestOutputHelper?.WriteLine($"{width}: ip {ip.Width:0} comment {comment.Width:0} add.Left {addBox.Left:0} comment.Right {comment.Right:0} window {w.ClientSize.Width:0}");
            Assert.InRange(ip.Width, 1, 500.5);
            Assert.InRange(comment.Width, 1, 280.5);
            if (width >= 1180)
            {
                Assert.InRange(ip.Width, 495, 500.5);
                Assert.InRange(comment.Width, 275, 280.5);
            }
            else
            {
                Assert.True(ip.Width > comment.Width, "the IP field stays the wider one");
            }

            Assert.InRange(addBox.Left - remove.Right, 0, 12); // buttons follow the fields: no wide empty gap
            Assert.True(addBox.Right <= w.ClientSize.Width + 0.5, "buttons are not clipped");
            foreach (var pair in ips.Zip(comments)) Assert.Equal(Bounds(pair.First, w).Width, Bounds(ips[0], w).Width, 0.5); // rows aligned
            foreach (var c in comments) Assert.Equal(comment.Left, Bounds(c, w).Left, 0.5);
        }
        finally
        {
            w.Close();
            vm.SetRanges(saved, append: false);
        }
    });
}
