using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.IO.Compression;
using System.Text;
using System.Security.Policy;
using System.Threading;
using System.Runtime.InteropServices;
using cat_spoofer_full;
using System.Security.Cryptography;
using System.Data.Common;
using Discord.Webhook;
using System.Threading.Tasks;
using System.Net.Http;

public class SpoofUtils
{
    private static readonly byte[] keyenc = Convert.FromBase64String("XoTIwHSRfY21oRsX2sXp/wuPdaZModGyw7gFGMxPzAY=");
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool BlockInput([MarshalAs(UnmanagedType.Bool)] bool fBlockIt);
    public class Adapter
    {
        public ManagementObject adapter;
        public string adaptername;
        public string customname;
        public int devnum;

        public Adapter(ManagementObject a, string aname, string cname, int n)
        {
            this.adapter = a;
            this.adaptername = aname;
            this.customname = cname;
            this.devnum = n;
        }

        public Adapter(NetworkInterface i) : this(i.Description) { }

        public Adapter(string aname)
        {
            this.adaptername = aname;

            var searcher = new ManagementObjectSearcher("select * from win32_networkadapter where Name='" + adaptername + "'");
            var found = searcher.Get();
            this.adapter = found.Cast<ManagementObject>().FirstOrDefault();

            // Extract adapter number; this should correspond to the keys under
            // HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}
            try
            {
                var match = Regex.Match(adapter.Path.RelativePath, "\\\"(\\d+)\\\"$");
                this.devnum = int.Parse(match.Groups[1].Value);
            }
            catch
            {
                return;
            }

            // Find the name the user gave to it in "Network Adapters"
            this.customname = NetworkInterface.GetAllNetworkInterfaces().Where(
                i => i.Description == adaptername
            ).Select(
                i => " (" + i.Name + ")"
            ).FirstOrDefault();
        }

        /// <summary>
        /// Get the .NET managed adapter.
        /// </summary>
        public NetworkInterface ManagedAdapter
        {
            get
            {
                return NetworkInterface.GetAllNetworkInterfaces().Where(
                    nic => nic.Description == this.adaptername
                ).FirstOrDefault();
            }
        }

        /// <summary>
        /// Get the MAC address as reported by the adapter.
        /// </summary>
        public string Mac
        {
            get
            {
                try
                {
                    return BitConverter.ToString(this.ManagedAdapter.GetPhysicalAddress().GetAddressBytes()).Replace("-", "").ToUpper();
                }
                catch { return null; }
            }
        }

        /// <summary>
        /// Get the registry key associated to this adapter.
        /// </summary>
        public string RegistryKey
        {
            get
            {
                return String.Format(@"SYSTEM\ControlSet001\Control\Class\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{0:D4}", this.devnum);
            }
        }

        /// <summary>
        /// Get the NetworkAddress registry value of this adapter.
        /// </summary>
        public string RegistryMac
        {
            get
            {
                try
                {
                    using (RegistryKey regkey = Registry.LocalMachine.OpenSubKey(this.RegistryKey, false))
                    {
                        return regkey.GetValue("NetworkAddress").ToString();
                    }
                }
                catch
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// Sets the NetworkAddress registry value of this adapter.
        /// </summary>
        /// <param name="value">The value. Should be EITHER a string of 12 hexadecimal digits, uppercase, without dashes, dots or anything else, OR an empty string (clears the registry value).</param>
        /// <returns>true if successful, false otherwise</returns>
        public bool SetRegistryMac(string value)
        {
            bool shouldReenable = false;

            try
            {
                // If the value is not the empty string, we want to set NetworkAddress to it,
                // so it had better be valid
                if (value.Length > 0 && !Adapter.IsValidMac(value, false))
                    throw new Exception(value + " is not a valid mac address");

                using (RegistryKey regkey = Registry.LocalMachine.OpenSubKey(this.RegistryKey, true))
                {
                    if (regkey == null)
                        throw new Exception("Failed to open the registry key");

                    // Sanity check
                    if (regkey.GetValue("AdapterModel") as string != this.adaptername
                        && regkey.GetValue("DriverDesc") as string != this.adaptername)
                        throw new Exception("Adapter not found in registry");

                    // Attempt to disable the adepter
                    var result = (uint)adapter.InvokeMethod("Disable", null);
                    if (result != 0)
                        throw new Exception("Failed to disable network adapter.");

                    // If we're here the adapter has been disabled, so we set the flag that will re-enable it in the finally block
                    shouldReenable = true;

                    // If we're here everything is OK; update or clear the registry value
                    if (value.Length > 0)
                        regkey.SetValue("NetworkAddress", value, RegistryValueKind.String);
                    else
                        regkey.DeleteValue("NetworkAddress");


                    return true;
                }
            }

            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
                return false;
            }

            finally
            {
                if (shouldReenable)
                {
                    uint result = (uint)adapter.InvokeMethod("Enable", null);
                    if (result != 0)
                        MessageBox.Show("Failed to re-enable network adapter.");
                }
            }
        }

        public override string ToString()
        {
            return this.adaptername + this.customname;
        }

        /// <summary>
        /// Get a random (locally administered) MAC address.
        /// </summary>
        /// <returns>A MAC address having 01 as the least significant bits of the first byte, but otherwise random.</returns>
        public static string GetNewMac()
        {
            System.Random r = new System.Random();

            byte[] bytes = new byte[6];
            r.NextBytes(bytes);

            // Set second bit to 1
            bytes[0] = (byte)(bytes[0] | 0x02);
            // Set first bit to 0
            bytes[0] = (byte)(bytes[0] & 0xfe);

            return MacToString(bytes);
        }

        /// <summary>
        /// Verifies that a given string is a valid MAC address.
        /// </summary>
        /// <param name="mac">The string.</param>
        /// <param name="actual">false if the address is a locally administered address, true otherwise.</param>
        /// <returns>true if the string is a valid MAC address, false otherwise.</returns>
        public static bool IsValidMac(string mac, bool actual)
        {
            // 6 bytes == 12 hex characters (without dashes/dots/anything else)
            if (mac.Length != 12)
                return false;

            // Should be uppercase
            if (mac != mac.ToUpper())
                return false;

            // Should not contain anything other than hexadecimal digits
            if (!Regex.IsMatch(mac, "^[0-9A-F]*$"))
                return false;

            if (actual)
                return true;

            // If we're here, then the second character should be a 2, 6, A or E
            char c = mac[1];
            return (c == '2' || c == '6' || c == 'A' || c == 'E');
        }

        /// <summary>
        /// Verifies that a given MAC address is valid.
        /// </summary>
        /// <param name="mac">The address.</param>
        /// <param name="actual">false if the address is a locally administered address, true otherwise.</param>
        /// <returns>true if valid, false otherwise.</returns>
        public static bool IsValidMac(byte[] bytes, bool actual)
        {
            return IsValidMac(Adapter.MacToString(bytes), actual);
        }

        /// <summary>
        /// Converts a byte array of length 6 to a MAC address (i.e. string of hexadecimal digits).
        /// </summary>
        /// <param name="bytes">The bytes to convert.</param>
        /// <returns>The MAC address.</returns>
        public static string MacToString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToUpper();
        }
    }

    public class Spoof
    {
        private static readonly string Chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static readonly Random Rng = new Random();
        static Random random = new Random();
        static List<Adapter> GetAdaptersList()
        {
            List<Adapter> adaptersList = new List<Adapter>();

            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces().Where(
                a => Adapter.IsValidMac(a.GetPhysicalAddress().GetAddressBytes(), true)
            ).OrderByDescending(a => a.Speed))
            {
                adaptersList.Add(new Adapter(adapter));
            }

            return adaptersList;
        }
        public static void SpoofMAC()
        {
            fail:
            string mac = Adapter.GetNewMac();
            if (!Adapter.IsValidMac(mac, false))
            {
                goto fail;
            }
            List<Adapter> adapters = GetAdaptersList();

            foreach (Adapter a in adapters)
            {
                if (a.SetRegistryMac(mac))
                {
                    System.Threading.Thread.Sleep(100);
                }
            }

        }

        public static void CleanFN()
        {
            string clean1 = "C:\\ProgramData\\SoftwareDistribution\\catspooferfiles\\clean\\clean1.bat";
            string clean2 = "C:\\ProgramData\\SoftwareDistribution\\catspooferfiles\\clean\\clean2.bat";
            string clean3 = "C:\\ProgramData\\SoftwareDistribution\\catspooferfiles\\clean\\clean3.bat";
            ExecuteProcess(clean1, "", true);
            ExecuteProcess(clean2, "", true);
            ExecuteProcess(clean3, "", true);
        }

        public static bool CheckInstall()
        {
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT InstallDate FROM Win32_OperatingSystem");
                foreach (ManagementObject os in searcher.Get())
                {
                    string installDate = os["InstallDate"]?.ToString();
                    if (!string.IsNullOrEmpty(installDate))
                    {
                        DateTime installDateTime = ManagementDateTimeConverter.ToDateTime(installDate);
                        TimeSpan difference = DateTime.Now - installDateTime;
                        return difference.TotalDays > 1;
                    }
                }
            }
            catch (ManagementException e)
            {
                Console.WriteLine("Error: " + e.Message);
            }
            return false;
        }

        public static string GetWindowsVersion()
        {
            string subKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

            using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                                       .OpenSubKey(subKey))
            {
                if (key != null)
                {
                    object value = key.GetValue("ProductName");
                    if (value != null)
                    {
                        return value.ToString();
                    }
                }
            }

            return "Unknown";
        }

        public static bool CompareDisks()
        {
            DriveInfo[] allDrives = DriveInfo.GetDrives();
            int totalDisks = allDrives.Length;
            int driveLetters = 0;
            foreach (DriveInfo drive in allDrives)
            {
                if (drive.IsReady)
                {
                    driveLetters++;
                }
            }

            return totalDisks == driveLetters;
        }
        public static string GenerateRandomId()
        {
            Random random = new Random();
            const string alphanumericChars = "0123456789ABCDEF";
            const int idLength = 4;

            char[] id = new char[idLength * 2 + 1];
            for (int i = 0; i < idLength * 2 + 1; i++)
            {
                if (i == idLength)
                {
                    id[i] = '-';
                }
                else
                {
                    id[i] = alphanumericChars[random.Next(alphanumericChars.Length)];
                }
            }

            return new string(id);
        }

        public static void ExecuteProcess(string processName, string arguments, bool hide)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = processName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = hide
            };

            using (Process process = Process.Start(startInfo))
            {
                process.WaitForExit();
            }
        }


        public static string Shell(string processName, string arguments, bool hide)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = processName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = hide
            };

            using (Process process = Process.Start(startInfo))
            {
                using (StreamReader reader = process.StandardOutput)
                {
                    string output = reader.ReadToEnd();
                    process.WaitForExit();
                    return output;
                }
            }
        }

        static void Drives()
        {
            DriveInfo[] drives = DriveInfo.GetDrives();
            string volumeid64 = "C:\\ProgramData\\SoftwareDistribution\\catspooferfiles\\disk\\Volumeid.exe";
            foreach (DriveInfo drive in drives)
            {
                string newid = GenerateRandomId();
                string driveLetter = drive.Name.Substring(0, 1);
                ExecuteProcess(volumeid64, $"{driveLetter}: {newid} -nobanner", true);
            }
        }

        private static string GetValueInQuotes(string text)
        {
            int start = text.IndexOf('"');
            int end = text.LastIndexOf('"');

            if (start >= 0 && end >= 0 && start < end)
            {
                return text.Substring(start + 1, end - start - 1);
            }
            else
            {
                return "No value enclosed in double quotes found.";
            }
        }

        private static string SendDataToServer(string url, string postData)
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(postData);
                WebRequest request = WebRequest.Create(url);
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = data.Length;

                using (Stream stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                using (WebResponse webResponse = request.GetResponse())
                using (Stream responseStream = webResponse.GetResponseStream())
                using (StreamReader reader = new StreamReader(responseStream))
                {
                    return reader.ReadToEnd();
                }
            }
            catch (WebException ex)
            {
                return "Error: " + ex.Message;
            }
        }

        public static void RestoreSerials(string seed)
        {
            byte[] bytesToWrite = Program.auth.download("387211");

            string filePath = "C:\\ProgramData\\SoftwareDistribution\\catfiles.zip";

            using (FileStream fileStream = new FileStream(filePath, FileMode.Create))
            {
                using (BinaryWriter writer = new BinaryWriter(fileStream))
                {
                    writer.Write(bytesToWrite);
                }
            }

            ZipFile.ExtractToDirectory("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip", "C:\\ProgramData\\SoftwareDistribution\\");

            File.Delete("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip");
            string amide = "C:\\ProgramData\\SoftwareDistribution\\catspooferfiles\\hwid\\AMIDEWINx64.EXE";
            string encryptedText = DownloadStringFromUrl($"https://ickf.xyz/agdsfgsd/seeds/{seed}");

            if (!string.IsNullOrEmpty(encryptedText))
            {
                string[] lines = encryptedText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                string agree = Program.input("Seed found on servers, are you sure you would like to proceed?\n\n(Y/N): ");
                if (agree.ToLower() == "yes" || agree.ToLower() == "y")
                {
                    foreach (string line in lines)
                    {
                        string decryptedLine = AESEncryption.DecryptAES(line, keyenc);
                        Console.Clear();
                        ExecuteProcess(amide, decryptedLine, true);
                    }
                }
                Console.ReadKey();
            }
            else
            {
                Console.WriteLine("Failed to get serials, possibly an invalid seed?");
            }
        }

        static string DownloadStringFromUrl(string url)
        {
            try
            {
                using (WebClient client = new WebClient())
                {
                    return client.DownloadString(url);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error downloading from the URL: " + ex.Message);
                return null;
            }
        }


        public static async Task SaveSerialsAsync()
        {
            Program.print("!! IMPORTANT, THIS DOES NOT SAVE DISK SERIALS. !!");
            byte[] bytesToWrite = Program.auth.download("387211");

            string filePath = "C:\\ProgramData\\SoftwareDistribution\\catfiles.zip";

            using (FileStream fileStream = new FileStream(filePath, FileMode.Create))
            {
                using (BinaryWriter writer = new BinaryWriter(fileStream))
                {
                    writer.Write(bytesToWrite);
                }
            }

            ZipFile.ExtractToDirectory("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip", "C:\\ProgramData\\SoftwareDistribution\\");

            File.Delete("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip");
            string amide = "C:\\ProgramData\\SoftwareDistribution\\catspooferfiles\\hwid\\AMIDEWINx64.EXE";
            string[] parameters = new string[]
            {
            "/IV",
            "/SV",
            "/BM",
            "/IVN",
            "/SS",
            "/SK",
            "/SF",
            "/BV",
            "/BS",
            "/CS",
            "/PSN",
            "/PPN",
            "/BP",
            "/CM",
            "/OS",
            "/SU"
            };

            string postData = "";
            foreach (string parameter in parameters)
            {
                string output = Shell(amide, parameter, true);
                string valueInQuotes = GetValueInQuotes(output);
                if (valueInQuotes == "No value enclosed in double quotes found.")
                {
                    Program.print("Failed...");
                    Console.ReadKey();
                    return;
                }
                string compiled = $"{parameter} {valueInQuotes}";
                string hashed = AESEncryption.EncryptAES(compiled, keyenc);
                postData += hashed + "\n";
            }

            string url = "https://ickf.xyz/agdsfgsd/serialendpoint.php";
            string response = SendDataToServer(url, postData);
            DateTimeOffset currentTime = DateTimeOffset.Now;
            SendWebhook("https://discord.com/api/webhooks/1177518125089050624/WMkUUYUH1IGvlZy2iIm2MPs4mkpaGa0BODCVO73E-22foLIhMif6CjsrayUaavcJwK2H", $"A user has uploaded a serial seed\nUsername: {Environment.UserName}\nTime: <t:{currentTime.ToUnixTimeSeconds()}:f> (<t:{currentTime.ToUnixTimeSeconds()}:R>)\nSeed URL: https://ickf.xyz/agdsfgsd/seeds/{response}\n\n**THIS INFO WAS SENT FOR SAFETY PURPOSES, ALL INFO IS HASHED ON SERVER**");
            Console.WriteLine("Seed (Save it somewhere save and press space to continue): " + response);
            while (true)
            {
                ConsoleKeyInfo keyInfo = Console.ReadKey(true);
                if (keyInfo.Key == ConsoleKey.Spacebar)
                {
                    Program.auth.logout();
                    Program.StartSpoofer();
                    break;
                }
            }
        }

        static async Task SendWebhook(string webhookUrl, string messageContent)
        {
            using (HttpClient client = new HttpClient())
            {
                var payload = new
                {
                    content = messageContent
                };

                var json = Newtonsoft.Json.JsonConvert.SerializeObject(payload);
                var httpContent = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await client.PostAsync(webhookUrl, httpContent);

                if (response.IsSuccessStatusCode)
                {
                }
                else
                {
                    Console.WriteLine($"{response.StatusCode}");
                }
            }
        }
        static void HWID()
        {
            string amide = "C:\\ProgramData\\SoftwareDistribution\\catspooferfiles\\hwid\\AMIDEWINx64.EXE";
            string[] parameters = new string[]
            {
                $"/IV {RandStr(16)}",
                $"/SV {RandStr(16)}",
                $"/BM {RandStr(16)}",
                $"/IVN {RandStr(16)}",
                $"/SS {RandStr(16)}",
                $"/SK {RandStr(16)}",
                $"/SF {RandStr(16)}",
                $"/BV {RandStr(16)}",
                $"/BS {RandStr(16)}",
                $"/CS {RandStr(16)}",
                $"/PSN {RandStr(16)}",
                $"/PPN {RandStr(16)}",
                $"/BP {RandStr(16)}",
                $"/CM {RandStr(16)}",
                $"/OS 1 {RandStr(16)}",
                $"/SU AUTO"
            };
            foreach (string parameter in parameters)
            {
                ExecuteProcess(amide, parameter, true);
            }
        }
        public static void DownloadFile(string url, string destinationPath)
        {
            using (WebClient webClient = new WebClient())
            {
                webClient.DownloadFile(url, destinationPath);
            }
        }

        public static void CleanApex()
        {
            string downloadUrl = "https://ickf.xyz/idunno/apex.bat";
            string downloadPath = "C:\\ProgramData\\SoftwareDistribution\\catspooferfiles\\apex.bat";

            DownloadFile(downloadUrl, downloadPath);
            ExecuteProcess(downloadPath, "", true);
        }

        static string RandStr(int length)
        {
            string prefix = "CAT-";
            return prefix + new string(Enumerable.Repeat(Chars, length)
                .Select(s => s[Rng.Next(s.Length)]).ToArray());
        }

        static string GetWmiValue(string className, string properties)
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher($"SELECT {properties} FROM {className}");
            ManagementObjectCollection collection = searcher.Get();

            foreach (ManagementObject obj in collection)
            {
                foreach (PropertyData property in obj.Properties)
                {
                    return property.Value.ToString();
                }
            }

            return null;
        }
        public static Dictionary<string, string> GetHardwareInfo()
        {
            Dictionary<string, string> hardwareInfo = new Dictionary<string, string>();
            List<Adapter> adapters = GetAdaptersList();
            List<string> macs = new List<string>();

            foreach (Adapter adapter in adapters)
            {
                macs.Add(adapter.Mac);
            }

            hardwareInfo["CPU"] = GetWmiValue("Win32_Processor", "SerialNumber");

            hardwareInfo["BIOS"] = GetWmiValue("Win32_BIOS", "SerialNumber");

            hardwareInfo["Motherboard"] = GetWmiValue("Win32_BaseBoard", "SerialNumber");

            hardwareInfo["smBIOS_UUID"] = GetWmiValue("Win32_ComputerSystemProduct", "UUID");

            StringBuilder macAddresses = new StringBuilder();
            foreach (string mac in macs)
            {
                macAddresses.Append(mac);
            }
            hardwareInfo["MACAddresses"] = macAddresses.ToString();

            return hardwareInfo;
        }

        public static int CompareHardwareInfo(Dictionary<string, string> originalInfo, Dictionary<string, string> spoofedInfo)
        {
            int unchangedComponents = 0;

            foreach (var key in originalInfo.Keys)
            {

                if (originalInfo[key] == spoofedInfo[key])
                {
                    unchangedComponents++;
                }
            }

            int totalComponents = originalInfo.Count;

            return totalComponents - unchangedComponents;
        }

        public static string GetMobo()
        {
            try
            {
                ManagementObjectSearcher searcher =
                    new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard");

                foreach (ManagementObject obj in searcher.Get())
                {
                    string manufacturer = obj["Manufacturer"].ToString();
                    string product = obj["Product"].ToString();

                    return manufacturer;
                }
            }
            catch (ManagementException e)
            {
                return "Error: " + e.Message;
            }
            return "Unknown";
        }

        public static void StartFNSpoof()
        {
            byte[] bytesToWrite = Program.auth.download("123927");

            string filePath = "C:\\ProgramData\\SoftwareDistribution\\catfiles.zip";

            using (FileStream fileStream = new FileStream(filePath, FileMode.Create))
            {
                using (BinaryWriter writer = new BinaryWriter(fileStream))
                {
                    writer.Write(bytesToWrite);
                }
            }

            ZipFile.ExtractToDirectory("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip", "C:\\ProgramData\\SoftwareDistribution\\");

            File.Delete("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip");
            Dictionary<string, string> originalInfo = GetHardwareInfo();
            System.Collections.Specialized.StringCollection stringCollection = new System.Collections.Specialized.StringCollection();

            foreach (var pair in originalInfo)
            {
                stringCollection.Add(pair.Key + ":" + pair.Value);
            }
            CleanFN();
            cat_spoofer_full.Properties.Settings.Default.serials = stringCollection;
            cat_spoofer_full.Properties.Settings.Default.Save();
            Drives();
            HWID();
            SpoofMAC();
            Directory.Delete("C:\\ProgramData\\SoftwareDistribution\\catspooferfiles", true);
            StartupManager.RegisterProgram("check");
            string input = Program.input("Fortnite spoof is done, would you like to restart right now? (Y/N)");
            if (input.ToLower() == "yes" || input.ToLower() == "y")
            {
                Process.Start("shutdown", "/r /t 0");
            }
            else
            {
                Application.Exit();
            }
        }

        public static void StartApexSpoof()
        {
            byte[] bytesToWrite = Program.auth.download("387211");

            string filePath = "C:\\ProgramData\\SoftwareDistribution\\catfiles.zip";

            using (FileStream fileStream = new FileStream(filePath, FileMode.Create))
            {
                using (BinaryWriter writer = new BinaryWriter(fileStream))
                {
                    writer.Write(bytesToWrite);
                }
            }

            ZipFile.ExtractToDirectory("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip", "C:\\ProgramData\\SoftwareDistribution\\");

            File.Delete("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip");
            Dictionary<string, string> originalInfo = GetHardwareInfo();
            System.Collections.Specialized.StringCollection stringCollection = new System.Collections.Specialized.StringCollection();

            foreach (var pair in originalInfo)
            {
                stringCollection.Add(pair.Key + ":" + pair.Value);
            }
            Program.print("Cleaning apex traces... (This can take a while)");
            CleanApex();
            Program.print("Saving old serials...");
            cat_spoofer_full.Properties.Settings.Default.serials = stringCollection;
            cat_spoofer_full.Properties.Settings.Default.Save();
            Program.print("Saved old serials (for comparison only)");
            Drives();
            Program.print("Spoofed disks");
            HWID();
            Program.print("Spoofed HWID");
            SpoofMAC();
            Program.print("Spoofed MAC");
            Directory.Delete("C:\\ProgramData\\SoftwareDistribution\\catspooferfiles", true);
            StartupManager.RegisterProgram("check");
            Program.print("Registered to startup for comparison");
            string input = Program.input("Apex spoof is done, would you like to restart right now? (Y/N)");
            if (input.ToLower() == "yes" || input.ToLower() == "y")
            {
                Process.Start("shutdown", "/r /t 0");
            }
            else
            {
                Application.Exit();
            }
        }




        public static void StartSpoof()
        {

            byte[] bytesToWrite = Program.auth.download("387211");

            string filePath = "C:\\ProgramData\\SoftwareDistribution\\catfiles.zip";

            using (FileStream fileStream = new FileStream(filePath, FileMode.Create))
            {
                using (BinaryWriter writer = new BinaryWriter(fileStream))
                {
                    writer.Write(bytesToWrite);
                }
            }

            ZipFile.ExtractToDirectory("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip", "C:\\ProgramData\\SoftwareDistribution\\");

            File.Delete("C:\\ProgramData\\SoftwareDistribution\\catfiles.zip");
            Dictionary<string, string> originalInfo = GetHardwareInfo();
            System.Collections.Specialized.StringCollection stringCollection = new System.Collections.Specialized.StringCollection();

            foreach (var pair in originalInfo)
            {
                stringCollection.Add(pair.Key + ":" + pair.Value);
            }
            Program.print("Saving old serials...");
            cat_spoofer_full.Properties.Settings.Default.serials = stringCollection;
            cat_spoofer_full.Properties.Settings.Default.Save();
            Program.print("Saved old serials (for comparison only)");
            Drives();
            Program.print("Spoofed disks");
            HWID();
            Program.print("Spoofed HWID");
            SpoofMAC();
            Program.print("Spoofed MAC");
            Directory.Delete("C:\\ProgramData\\SoftwareDistribution\\catspooferfiles", true);
            StartupManager.RegisterProgram("check");
            Program.print("Registered to startup for comparison");
            StartupManager.RegisterProgram("check");
            string input = Program.input("Permanent spoof is done, would you like to restart right now? (Y/N)");
            if (input.ToLower() == "yes" || input.ToLower() == "y")
            {
                Process.Start("shutdown", "/r /t 0");
            }
            else
            {
                Application.Exit();
            }
        }
    }
    public static class StartupManager
    {
        private const string RegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string UniqueAppKey = "catspufer";

        public static void RegisterProgram(string arguments)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegistryKey, true))
            {
                if (key == null)
                {
                    throw new Exception("Registry key not found");
                }

                string executablePath = Process.GetCurrentProcess().MainModule.FileName;
                string value = $"\"{executablePath}\" {arguments}";

                key.SetValue(UniqueAppKey, value, RegistryValueKind.String);
            }
        }

        public static void UnregisterProgram()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegistryKey, true))
            {
                if (key == null)
                {
                    throw new Exception("Registry key not found");
                }

                key.DeleteValue(UniqueAppKey, false);
            }
        }
    }

    public class AESEncryption
    {
        public static byte[] GenerateAESKey()
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = 256;
                aesAlg.GenerateKey();
                return aesAlg.Key;
            }
        }

        public static string EncryptAES(string plainText, byte[] key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                byte[] encrypted;

                using (var msEncrypt = new System.IO.MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new System.IO.StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                byte[] result = new byte[aesAlg.IV.Length + encrypted.Length];
                Array.Copy(aesAlg.IV, 0, result, 0, aesAlg.IV.Length);
                Array.Copy(encrypted, 0, result, aesAlg.IV.Length, encrypted.Length);

                return Convert.ToBase64String(result); // Convert the bytes to a text representation
            }
        }

        public static string DecryptAES(string cipherText, byte[] key)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText); // Convert the text back to bytes

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                byte[] iv = new byte[16];
                byte[] encrypted = new byte[cipherBytes.Length - 16];
                Array.Copy(cipherBytes, 0, iv, 0, 16);
                Array.Copy(cipherBytes, 16, encrypted, 0, cipherBytes.Length - 16);

                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                string plaintext = null;

                using (var msDecrypt = new System.IO.MemoryStream(encrypted))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new System.IO.StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

                return plaintext;
            }
        }
        public static string ConvertKeyToText(byte[] key)
        {
            string keyText = Convert.ToBase64String(key);
            return keyText;
        }
    }
}
