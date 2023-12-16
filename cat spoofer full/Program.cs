using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using cat_spoofer_full.Properties;
using KeyAuth;

namespace cat_spoofer_full
{
    internal static class Program
    {
        public static string keylogin = "";
        public static api auth = new api(
            name: "cat spoofer",
            ownerid: "Gl3ijxUyLM",
            secret: "ad3a7e8ffbb6d936a3b90670682b18b0f78f40945c867967d4884f0f9f8ffcad",
            version: "1.0"
        );
        [DllImport("user32.dll")]
        static extern int SetWindowText(IntPtr hWnd, string text);
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            CleanUpFiles();
            if (args.Length > 0 && args[0] == "check")
            {
                CheckHwid();
            }
            if (args.Length == 0 || (args.Length > 0 && args[0] != "renamed"))
            {
                StartSpoofer();
            }
            else
            {
                StartSpoofer();
            }
        }
        public static void CleanUpFiles()
        {
            if (Directory.Exists("C:\\ProgramData\\SoftwareDistribution\\catspooferfiles"))
            {
                Directory.Delete("C:\\ProgramData\\SoftwareDistribution\\catspooferfiles", true);
            }
        }

        static string GenerateRandomCode()
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, 1)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        static void CopyRenameModifyAndLaunch()
        {
            string currentExecutable = Assembly.GetEntryAssembly().Location;
            string newFileName = GenerateRandomName();

            try
            {
                File.Copy(currentExecutable, newFileName, true);
                ModifyFile(newFileName);
                Process p = Process.Start(newFileName, "renamed");
                SetWindowText(p.MainWindowHandle, newFileName.Replace(".exe", ""));
                Process.Start(new ProcessStartInfo("cmd.exe", $"/c start cmd /C \"del \"{Process.GetCurrentProcess().MainModule.FileName}\"\"")
                {
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                });
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                Program.print("Error: " + ex.Message);
            }
        }

        static string GenerateRandomName()
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, 10)
                .Select(s => s[random.Next(s.Length)]).ToArray()) + ".exe";
        }

        static void ModifyFile(string fileName)
        {
            try
            {
                string randomCode = GenerateRandomCode();
                byte[] fileContent = File.ReadAllBytes(fileName);
                byte[] modifiedContent = Combine(fileContent, Encoding.UTF8.GetBytes(randomCode));
                File.WriteAllBytes(fileName, modifiedContent);
            }
            catch (Exception ex)
            {
                Program.print("Error: " + ex.Message);
            }
        }

        static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        public static void print(string text, int delayMilliseconds = 10)
        {
            foreach (char c in text)
            {
                Console.Write(c);
                Thread.Sleep(delayMilliseconds);
            }
            Console.WriteLine();
        }

        public static string input(string prompt, int delayMilliseconds = 10)
        {
            Console.Write(prompt);

            string input = "";
            foreach (char c in Console.ReadLine())
            {
                Thread.Sleep(delayMilliseconds);
                input += c;
            }
            return input;
        }

        private static void SaveKeyToFile(string key)
        {
            string filePath = "key.kitty"; // Change this to your desired file path
            try
            {
                File.WriteAllText(filePath, key);
            }
            catch (Exception e)
            {
                Program.print("Error saving key to file: " + e.Message);
            }
        }
        public static void StartSpoofer()
        {
            Console.Clear();
            string savedKey = ReadKeyFromFile();
            try
            {
                print("Initializing authentication...");
                auth.init();
                Console.Clear();
                keylogin = savedKey != null ? savedKey : input("Key: ");
                auth.license(keylogin);
                if (auth.response.success)
                {
                    SaveKeyToFile(keylogin);
                    Console.Clear();
                    print("[1] One click Apex Legends unban");
                    print("[2] Permanent spoof");
                    print("[3] One click Apex Legends unban (TEMP)");
                    print("[4] Temp spoof");
                    Program.print("----------------------------------------------------------------");
                    print("[9] Restore serials from a seed");
                    print("[0] Save current serials");
                    string sel = input("Selection: ");

                    switch (sel)
                    {
                        case "1":
                            Console.Clear();
                            string sure = input("Are you sure you want to proceed with spoofing process?, Please don't touch anything until the process finishes.    !! We dont take responsibility if anything breaks, have a usb with windows on it just incase. !!\n\n(Y/N): ", 5);
                            if (sure.ToLower() == "yes" || sure.ToLower() == "y")
                            {
                                Console.Clear();
                                if (!SpoofUtils.Spoof.CompareDisks())
                                {
                                    MessageBox.Show("Not all of your disks are initialized.", "!", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                    return;
                                }
                                SpoofUtils.Spoof.StartApexSpoof();
                            }
                            else
                            {
                                Application.Exit();
                            }
                            break;

                        case "2":
                            Console.Clear();
                            string sure1 = input("Are you sure you want to proceed with spoofing process?, Please don't touch anything until the process finishes.    !! We dont take responsibility if anything breaks, have a usb with windows on it just incase. !!\n\n(Y/N): ", 5);
                            if (sure1.ToLower() == "yes" || sure1.ToLower() == "y")
                            {
                                Console.Clear();
                                if (!SpoofUtils.Spoof.CompareDisks())
                                {
                                    MessageBox.Show("Not all of your disks are initialized.", "!", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                    return;
                                }
                                SpoofUtils.Spoof.StartSpoof();
                            }
                            else
                            {
                                Application.Exit();
                            }
                            break;
                        case "3":
                            Console.Clear();
                            string sure2 = input("Are you sure you want to proceed with spoofing process?, Please don't touch anything until the process finishes.    !! We dont take responsibility if anything breaks, have a usb with windows on it just incase. !!\n\n(Y/N): ", 5);
                            if (sure2.ToLower() == "yes" || sure2.ToLower() == "y")
                            {
                                Console.Clear();
                                if (!SpoofUtils.Spoof.CompareDisks())
                                {
                                    MessageBox.Show("Not all of your disks are initialized.", "!", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                    return;
                                }
                                SpoofUtils.Spoof.TempApexSpoof();
                            }
                            else
                            {
                                Application.Exit();
                            }
                            break;
                        case "4":
                            Console.Clear();
                            string sure3 = input("Are you sure you want to proceed with spoofing process?, Please don't touch anything until the process finishes.    !! We dont take responsibility if anything breaks, have a usb with windows on it just incase. !!\n\n(Y/N): ", 5);
                            if (sure3.ToLower() == "yes" || sure3.ToLower() == "y")
                            {
                                Console.Clear();
                                if (!SpoofUtils.Spoof.CompareDisks())
                                {
                                    MessageBox.Show("Not all of your disks are initialized.", "!", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                    return;
                                }
                                SpoofUtils.Spoof.TempSpoof();
                            }
                            else
                            {
                                Application.Exit();
                            }
                            break;
                        case "9":
                            string seed = input("Serial Seed: ");
                            SpoofUtils.Spoof.RestoreSerials(seed);
                            break;
                        case "0":
                            SpoofUtils.Spoof.SaveSerials();
                            break;
                        default:
                            print("Invalid selection");
                            break;
                    }
                }
                else
                {
                    Console.Clear();
                    print(auth.response.message);
                    Thread.Sleep(2500);
                    Application.Exit();
                }
            }
            catch (Exception e)
            {
                MessageBox.Show(e.ToString());
                CleanUpFiles();
            }
            finally
            {
                CleanUpFiles();
            }
        }
        public static byte[] Generate256BitKey()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[32]; // 256 bits = 32 bytes
                rng.GetBytes(key);
                return key;
            }
        }

        private static string ReadKeyFromFile()
        {
            string filePath = "key.kitty"; // Change this to your key file path
            if (File.Exists(filePath))
            {
                try
                {
                    return File.ReadAllText(filePath);
                }
                catch (Exception e)
                {
                    Program.print("Error reading key from file: " + e.Message);
                }
            }
            return null;
        }
        private static void CheckHwid()
        {
            Dictionary<string, string> originalInfo = new Dictionary<string, string>();

            StringCollection stringCollection = Settings.Default.serials;

            foreach (string item in stringCollection)
            {
                string[] parts = item.Split(':');
                if (parts.Length == 2)
                {
                    originalInfo.Add(parts[0], parts[1]);
                }
            }

            Dictionary<string, string> spoofedInfo = SpoofUtils.Spoof.GetHardwareInfo();

            int diffs = SpoofUtils.Spoof.CompareHardwareInfo(originalInfo, spoofedInfo);
            int totalComponents = 5; // Assuming you are checking five components

            if (diffs == totalComponents)
            {
                MessageBox.Show($"All {totalComponents} components of your HWID were spoofed.");
            }
            else if (diffs < totalComponents && diffs > 0)
            {
                MessageBox.Show($"There are only {diffs} differences in your HWID. This might indicate some problems.");
            }
            else if (diffs == 0)
            {
                MessageBox.Show($"There are no differences in your HWID. This indicates problems.");
            }
            SpoofUtils.StartupManager.UnregisterProgram();
            Process.Start(new ProcessStartInfo("cmd.exe", $"/c start cmd /C \"del \"{Process.GetCurrentProcess().MainModule.FileName}\"\"")
            {
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            });
            Environment.Exit(0);
        }
    }
}
