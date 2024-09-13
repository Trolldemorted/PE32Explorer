using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using PE32Explorer.PE32;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace PE32Explorer
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainWindow : Window
    {
        private readonly PE32Parser parser;

        public MainWindow()
        {
            this.InitializeComponent();
            this.parser = App.Services.GetRequiredService<PE32Parser>();
            this.Test();
        }

        private void myButton_Click(object sender, RoutedEventArgs e)
        {
            myButton.Content = "Clicked";
        }

        private async void Test()
        {
            try
            {
                var buf = await File.ReadAllBytesAsync(@"C:\Program Files (x86)\GOG Galaxy\Games\Patrician 3\Patrician3.exe");
                var pe32File = parser.ReadPE32File(buf);
                using var outputFile = File.OpenWrite(@"C:\Program Files (x86)\GOG Galaxy\Games\Patrician 3\Patrician3_patched.exe");
                await parser.WritePE32File(pe32File, outputFile, CancellationToken.None);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }

        }
    }
}
