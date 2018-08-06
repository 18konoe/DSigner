using System;
using System.Collections.Generic;
using System.Diagnostics;
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

using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace DSigner
{
    class Program
    {
        private static Signer _signer;
        static void Main(string[] args)
        {
            Run(args);
        }

        private static bool Run(params string[] args)
        {
            if (args == null) return false;

            ArgsMapper map = new ArgsMapper(args);

            if (map.SwitchList.Contains("-h") || map.SwitchList.Contains("--help"))
            {
                ShowUsage();
                return false;
            }

            if (map.ArgsList.Count == 0)
            {
                ShowUsage();
                return false;
            }

            switch (map.ArgsList[0].ToLower())
            {
                case "sha1":
                    _signer = new Signer(SigningType.SHA1);
                    break;
                case "sha2":
                    _signer = new Signer(SigningType.SHA2);
                    break;
                case "dual":
                    _signer = new Signer(SigningType.Dual);
                    break;
                default:
                    ShowUsage();
                    return false;
            }

            if (map.GetOption("-c") != null)
            {
                Config.SetConfig(map.GetOption("-c"));
            }

                List<string> signFileList = new List<string>();
            if (map.GetOption("-d") != null)
            {
                signFileList = ListUpFilePath(map.GetOption("-d"), Config.Instance.SigningSettings.SignExtensions.ToArray());
                Console.WriteLine($"Listed files: {signFileList.Count}");
            }

            if (map.GetOption("-f") != null)
            {
                if (File.Exists(map.GetOption("-f")))
                {
                    signFileList.Add(map.GetOption("-f"));
                }
            }

            if (map.GetOption("-w") != null)
            {
                signFileList = WhiteListFilter(signFileList, map.GetOption("-w"));
                Console.WriteLine($"Filtered WhiteList, Remaining: {signFileList.Count}");
            }

            if (map.GetOption("-b") != null)
            {
                signFileList = BlackListFilter(signFileList, map.GetOption("-b"));
                Console.WriteLine($"Filtered BlackList, Remaining: {signFileList.Count}");
            }

            var errorList = _signer.SignAll(signFileList);

            if (errorList.Count != 0)
            {
                return false;
            }

            return true;
        }
        private static List<string> BlackListFilter(List<string> fileList, string blackListJsonPath)
        {
            List<string> blackList;
            if (File.Exists(blackListJsonPath))
            {
                string configString = File.ReadAllText(blackListJsonPath);
                blackList = JsonConvert.DeserializeObject<List<string>>(configString);
            }
            else
            {
                Console.WriteLine($"Black list file is not found. {blackListJsonPath}");
                return fileList;
            }

            if (blackList == null || blackList.Count == 0)
            {
                Console.WriteLine($"Black list file is empty or illegal. {blackListJsonPath}");
                return fileList;
            }

            try
            {
                List<string> result = fileList.Where(filePath => !blackList.Any(expression => System.Text.RegularExpressions.Regex.IsMatch(filePath, expression))).ToList();
                return result;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return fileList;
            }
        }

        private static List<string> WhiteListFilter(List<string> fileList, string whiteListJsonPath)
        {
            List<string> whiteList;
            if (File.Exists(whiteListJsonPath))
            {
                string configString = File.ReadAllText(whiteListJsonPath);
                whiteList = JsonConvert.DeserializeObject<List<string>>(configString);
            }
            else
            {
                Console.WriteLine($"White list file is not found. {whiteListJsonPath}");
                return fileList;
            }

            if (whiteList == null || whiteList.Count == 0)
            {
                Console.WriteLine($"White list file is empty or illegal. {whiteListJsonPath}");
                return fileList;
            }

            try
            {
                List<string> result = fileList.Where(filePath => whiteList.Any(expression => Regex.IsMatch(filePath, expression))).ToList();
                return result;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return fileList;
            }
        }

        

        private static List<string> ListUpFilePath(string folderPath, string[] extensions)
        {
            if (!Directory.Exists(folderPath))
            {
                Console.WriteLine($"{folderPath} is not found.");
                return null;
            }

            List<string> list = Directory.EnumerateFiles(folderPath).Where(fileName => extensions.Any(fileName.EndsWith)).ToList();

            var contentFolders = Directory.EnumerateDirectories(folderPath);

            foreach (var contentFolder in contentFolders)
            {
                var contentList = ListUpFilePath(contentFolder, extensions);
                if (contentList != null)
                {
                    list.AddRange(contentList);
                }
            }

            return list;
        }
        private static void ShowUsage()
        {
            Console.WriteLine($"Usage: DSigner <command> <-f|-d target> [options...]                     {Environment.NewLine}" +
                              $"                                                                         {Environment.NewLine}" +
                              $"command:                                                                 {Environment.NewLine}" +
                              $"  SHA1                 Only SHA-1 signing                                {Environment.NewLine}" +
                              $"  SHA2                 Only SHA-2 signing                                {Environment.NewLine}" +
                              $"  Dual                 SHA-1 + SHA-2 signing                             {Environment.NewLine}" +
                              $"                                                                         {Environment.NewLine}" +
                              $"target:                                                                  {Environment.NewLine}" +
                              $"  -f <file path>       Only 1 file signing                               {Environment.NewLine}" +
                              $"  -d <directory path>  All files signed in specified directory           {Environment.NewLine}" +
                              $"                                                                         {Environment.NewLine}" +
                              $"option:                                                                  {Environment.NewLine}" +
                              $"  -w <whitelist(json)> Use white list if match listed regular expressions{Environment.NewLine}" +
                              $"  -b <blacklist(json)> Use black list if match listed regular expressions{Environment.NewLine}");
        }

        
    }
}
