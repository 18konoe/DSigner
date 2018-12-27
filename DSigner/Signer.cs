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
using System.Diagnostics;
using System.IO;

namespace DSigner
{
    public enum SigningType
    {
        None,
        SHA1,
        SHA2,
        Dual
    }
    public class Signer
    {
        private SigningType _signingType = SigningType.None;

        public Signer(SigningType signingType)
        {
            _signingType = signingType;
        }
        public List<string> SignAll(List<string> signFileList)
        {
            List<string> errorFileList = new List<string>();

            foreach (var signFile in signFileList)
            {
                if (!IsTrustedFile(signFile))
                {
                    var trialCount = 0;

                    var isSign = false;
                    do
                    {
                        trialCount++;
                        Console.WriteLine($"Signing trial[{trialCount}]: {signFile}");
                        isSign = SigningFile(signFile, _signingType);
                    } while (!isSign && trialCount < Config.Instance.SigningSettings.TrialLimit);

                    if (!isSign)
                    {
                        errorFileList.Add(signFile);
                        Console.WriteLine($"Signing error: {signFile}");
                    }
                }
                else
                {
                    Console.WriteLine($"{signFile} is already signed.");
                }
            }

            return errorFileList;
        }

        private bool SigningFile(string signFile, SigningType signingType)
        {
            bool result = false;
            Process singleSigningProcess = new Process();
            
            switch (signingType)
            {
                case SigningType.SHA1:
                    singleSigningProcess.StartInfo = GenerateProcessStartInfo(SigningType.SHA1, signFile);
                    break;
                case SigningType.SHA2:
                    singleSigningProcess.StartInfo = GenerateProcessStartInfo(SigningType.SHA2, signFile);
                    break;
                case SigningType.Dual:
                    singleSigningProcess.StartInfo = GenerateProcessStartInfo(SigningType.SHA1, signFile);
                    break;
                default:
                    break;
            }

            Console.WriteLine($"Signing command: \"{singleSigningProcess.StartInfo.FileName}\" {singleSigningProcess.StartInfo.Arguments}");
            if (!singleSigningProcess.Start())
            {
                Console.WriteLine("Failed to start signing process");
            }

            if (!singleSigningProcess.WaitForExit(Config.Instance.SigningSettings.SigntoolProcessTimeoutMilliseconds))
            {
                singleSigningProcess.Kill();
                Console.WriteLine("Failed to exit signing process");
            }

            string output = singleSigningProcess.StandardOutput.ReadToEnd();
            output = output.Replace("\r\r\n", "\n");
            Console.Write(output);

            result = IsTrustedFile(signFile);

            if (signingType == SigningType.Dual && result)
            {
                Process appendSigningProcess = new Process();
                appendSigningProcess.StartInfo = GenerateProcessStartInfo(SigningType.SHA2, signFile, true);

                Console.WriteLine($"Signing command: \"{appendSigningProcess.StartInfo.FileName}\" {appendSigningProcess.StartInfo.Arguments}");
                if (!appendSigningProcess.Start())
                {
                    Console.Write("Failed to start signing process");
                }

                if (!appendSigningProcess.WaitForExit(Config.Instance.SigningSettings.SigntoolProcessTimeoutMilliseconds))
                {
                    appendSigningProcess.Kill();
                    Console.Write("Failed to exit signing process");
                }

                output = appendSigningProcess.StandardOutput.ReadToEnd();
                output = output.Replace("\r\r\n", "\n");
                Console.Write(output);

                result = IsTrustedFile(signFile);
            }
            else if (signingType == SigningType.Dual && !result)
            {
                Console.WriteLine("Failed to first signing");
            }

            return result;
        }

        private ProcessStartInfo GenerateProcessStartInfo(SigningType signingType, string signFile, bool isAppend = false)
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo
            {
                FileName = Config.Instance.SigningSettings.SignToolPath,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                Arguments = $"sign /v /s \"{Config.Instance.CertInfo(signingType).StoreName}\" /n \"{Config.Instance.CertInfo(signingType).SubjectName}\" /sha1 \"{Config.Instance.CertInfo(signingType).Thumbprint}\""
            };


            if (signingType == SigningType.SHA1)
            {
                processStartInfo.Arguments += $" /t \"{Config.Instance.CertInfo(signingType).TimestampURL}\"";
            }

            if (signingType == SigningType.SHA2)
            {
                processStartInfo.Arguments += $" /tr \"{Config.Instance.CertInfo(signingType).TimestampURL}\" /fd sha256 /td sha256";
            }

            if (Config.Instance.SigningSettings.KernelModeExtensions.Contains(Path.GetExtension(signFile)))
            {
                if (File.Exists(Config.Instance.CertInfo(signingType).CrossCertPath))
                {
                    processStartInfo.Arguments += $" /ac \"{Config.Instance.CertInfo(signingType).CrossCertPath}\"";
                }
                else
                {
                    Console.WriteLine($"Cross Cert file is not exist: {Config.Instance.CertInfo(signingType).CrossCertPath}");
                }
            }

            if (isAppend)
            {
                processStartInfo.Arguments += $" /as";
            }

            if (Path.GetExtension(signFile) == ".msi")
            {
                processStartInfo.Arguments += $" /d {Path.GetFileName(signFile)}";
            }

            processStartInfo.Arguments += $" {signFile}";

            return processStartInfo;
        }

        private static bool IsTrustedFile(string filename)
        {
            //WinVerifyTrust cannot work when "" exists in filename
            string file = filename;
            if (string.IsNullOrEmpty(file))
            {
                return false;
            }
            if (file.StartsWith("\""))
            {
                file = filename.Substring(1);
            }
            if (file.EndsWith("\""))
            {
                file = file.Substring(0, file.Length - 1);
            }

            NativeMethods.WinTrust.WINTRUST_FILE_INFO fileInfo = new NativeMethods.WinTrust.WINTRUST_FILE_INFO(file);
            NativeMethods.WinTrust.WinTrustData sWintrustData = new NativeMethods.WinTrust.WinTrustData(
                NativeMethods.WinTrust.WinTrustDataUIChoice.None,
                NativeMethods.WinTrust.WinTrustDataRevocationChecks.None,
                NativeMethods.WinTrust.WinTrustDataChoice.File,
                NativeMethods.WinTrust.WinTrustDataStateAction.Verify,
                0,
                NativeMethods.WinTrust.WinTrustDataUIContext.Execute,
                fileInfo
            );

            NativeMethods.WinTrust.WinTrustErrorCode ret = NativeMethods.WinTrust.WinVerifyTrust(
                IntPtr.Zero,
                NativeMethods.WinTrust.WINTRUST_ACTION_GENERIC_VERIFY_V2
                , sWintrustData);

            sWintrustData.Dispose();
            fileInfo.Dispose();

            if (ret != NativeMethods.WinTrust.WinTrustErrorCode.SUCCESS)
            {
                return false;
            }
            return true;
        }
    }
}