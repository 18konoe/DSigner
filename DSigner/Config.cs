/*
  LICENSE
  -------
  Copyright (C) 2018 Juhachi Konoe

  This source code is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this source code or the software it produces.

  Permission is granted to anyone to use this source code for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this source code must not be misrepresented; you must not
     claim that you wrote the original source code.  If you use this source code
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original source code.
  3. This notice may not be removed or altered from any source distribution.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Newtonsoft.Json;

namespace DSigner
{
    public sealed class Config
    {
        #region Fields

        private static readonly string DefaultConfigurationFileName = Directory.GetParent(Assembly.GetExecutingAssembly().Location) + @"\config.json";

        #endregion

        public CertificateSettings CertificateSettings { get; set; }
        public SigningSettings SigningSettings { get; set; }
        public static Config Instance { get; private set; } = ImportConfig();

        private static Config ImportConfig()
        {
            return ImportConfig(DefaultConfigurationFileName);
        }
        private static Config ImportConfig(string filePath)
        {
            Config config = new Config();

            try
            {
                if (File.Exists(filePath))
                {
                    string configString = File.ReadAllText(filePath);
                    config = JsonConvert.DeserializeObject<Config>(configString);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return config;
        }

        private Config()
        {
            CertificateSettings = new CertificateSettings();
            CertificateSettings.SHA1 = new CertificateInformation();
            CertificateSettings.SHA2 = new CertificateInformation();
            SigningSettings = new SigningSettings();
            SigningSettings.SignExtensions = new List<string>();
            SigningSettings.KernelModeExtensions = new List<string>();
        }

        public static void SetConfig(string filePath)
        {
            Instance = ImportConfig(filePath);
        }
        public CertificateInformation CertInfo(SigningType signingType)
        {
            if (signingType == SigningType.SHA1)
            {
                return CertificateSettings.SHA1;
            }

            if (signingType == SigningType.SHA2)
            {
                return CertificateSettings.SHA2;
            }

            return null;
        }
    }

    public class CertificateSettings
    {
        public CertificateInformation SHA1 { get; set; }
        public CertificateInformation SHA2 { get; set; }
    }

    public class CertificateInformation
    {
        public string StoreName { get; set; }
        public string SubjectName { get; set; }
        public string Thumbprint { get; set; }
        public string TimestampURL { get; set; }
        public string CrossCertPath { get; set; }
        public string PfxPath { get; set; }
        public string PfxKey { get; set; }
    }

    public class SigningSettings
    {
        public string SignToolPath { get; set; } = "signtool.exe";
        public List<string> SignExtensions { get; set; }
        public List<string> KernelModeExtensions { get; set; }
        public int TrialLimit { get; set; } = 1;
        public int SigntoolProcessTimeoutMilliseconds { get; set; } = 10000;
    }
}