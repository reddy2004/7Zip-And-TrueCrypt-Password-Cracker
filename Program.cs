using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace _7Zip_And_TrueCrypt_Password_Cracker
{
    class Program
    {
        private const string archiveType = "--type";
        private const string hintsFolder = "--hints";
        private const string archiveFile = "--file";
        private const string dummyRun = "--dummy";
        private const string passwordLength = "--minmax";

        static void Main(string[] args)
        {
            Console.WriteLine("Hello World 4a!");
            String hintsFolderPath = "<empty>";
            int minPasswordLength = 5;
            int maxPasswordLength = 200;
            int dummyShowKthPassword = 100;
            bool isDummyFlag = false;
            String archiveFileType = "<empty>";
            String fileToProcess = "";
            /*
            ZipFilePasswordChecker zfpc = new ZipFilePasswordChecker(null);
            zfpc.PreprocessFile(@"C:\Users\91998\Desktop\passwordChecker\7zipArchive.7z");
            zfpc.CheckPassword(@"C:\Users\91998\Desktop\passwordChecker\7zipArchive.7z", "coronavirus");

            TrueCryptPasswordChecker tcpc = new TrueCryptPasswordChecker(null);
            tcpc.PreprocessFile(@"C:\Users\91998\Desktop\passwordChecker\truecryptVol.dat");
            tcpc.CheckPassword("coronavirus");
            */
            try
            {
                var arguments = args
                   .Select(x => x.Split(new char[] { '=' }, 2, StringSplitOptions.RemoveEmptyEntries))
                   .ToDictionary(x => x[0], x => x.Length > 1 ? x[1] as object : true, StringComparer.OrdinalIgnoreCase);

                var isDummy = arguments.ContainsKey(dummyRun)
                   ? arguments[dummyRun] as string
                   : @"undefined";

                
                //Just run the passwords in a loop. Dont actually try to test passwords on anything.
                if (isDummy != @"undefined")
                {
                    Console.WriteLine("This will simply print passwords, and not check the password on any input. Dummy is for testing");
                    Console.WriteLine("Ex. C:\\7Zip-And-TrueCrypt-Password-Cracker.exe --dummy=100");
                    Console.WriteLine("The above command with print every 100th password that is generated");
                    dummyShowKthPassword = int.Parse(isDummy);
                    isDummyFlag = true;
                }

                var type = arguments.ContainsKey(archiveType)
                   ? arguments[archiveType] as string
                   : @"undefined";

                if (type == @"undefined")
                {
                    Console.WriteLine("You have to provide --type. Either 'truecrypt' or '7zip'");
                    Console.WriteLine("Ex. C:\\7Zip-And-TrueCrypt-Password-Cracker.exe --type=truecrypt --hints=C:\\myhintsfolder\\ --file=encfile.vol");
                    return;
                } 
                else
                {
                    if (type != @"truecrypt" && type != @"7zip")
                    {
                        Console.WriteLine("Provided type " + type + " is not valid. Please specify either 'truecrypt' or '7zip'");
                        return;
                    }
                    archiveFileType = type;
                } 

                var hints = arguments.ContainsKey(hintsFolder)
                   ? arguments[hintsFolder] as string
                   : @"undefined";

                if (hints == @"undefined")
                {
                    Console.WriteLine("You have to provide --hints=<Path to folder>");
                    Console.WriteLine("Ex. C:\\7Zip-And-TrueCrypt-Password-Cracker.exe --type=truecrypt --hints=C:\\myhintsfolder\\ --file=encfile.vol");
                    Console.WriteLine("And, C:\\myhintsfolder\\ folder must contain another C:\\myhintsfolder\\hintsFolder, and a codeMap.txt and patterns.txt file");
                    return;
                }
                Console.WriteLine(hints);
                hintsFolderPath = hints;

                if (hints == @"undefined")
                {
                    Console.WriteLine("You have to provide --hints=<Path to folder>");
                    Console.WriteLine("Ex. C:\\7Zip-And-TrueCrypt-Password-Cracker.exe --type=truecrypt --hints=C:\\myhintsfolder\\ --file=encfile.vol");
                    Console.WriteLine("And, C:\\myhintsfolder\\ folder must contain another C:\\myhintsfolder\\hintsFolder, and a codeMap.txt and patterns.txt file");
                    return;
                }

                var filepath = arguments.ContainsKey(archiveFile)
                   ? arguments[archiveFile] as string
                   : @"undefined";

                if (filepath == @"undefined")
                {
                    Console.WriteLine("You have to provide --file=<Path to your archive file>");
                    Console.WriteLine("Ex. C:\\7Zip-And-TrueCrypt-Password-Cracker.exe --type=truecrypt --hints=C:\\myhintsfolder\\ --file=encfile.vol");
                    return;
                }

                fileToProcess = filepath;

                var minmax = arguments.ContainsKey(passwordLength)
                   ? arguments[passwordLength] as string
                   : @"undefined";

                if (minmax != @"undefined")
                {
                    String[] values = minmax.Split(',');
                    if (values.Length != 2)
                    {
                        Console.WriteLine("Given input for --minmax is not in proper format");
                        return;
                    }
                    minPasswordLength = Int32.Parse(values[0]);
                    maxPasswordLength = Int32.Parse(values[1]);
                    Console.WriteLine("Passwords lengths are " + minPasswordLength + " and " + maxPasswordLength);
                }
                else
                {
                    Console.WriteLine("Assuming password lengths to be between " + minPasswordLength + " and " + maxPasswordLength +
                        ". You can edit that by using --minmax=10,20 in the command line input");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(@"Error: " + ex.Message);
                return;
            }
            RunPasswordChecker(isDummyFlag, archiveFileType, fileToProcess, hintsFolderPath, minPasswordLength, maxPasswordLength, dummyShowKthPassword);// @"C:\Users\91998\Desktop\passwordChecker");
        }

        static void RunPasswordChecker(bool isDummy, String archiveFileType, String fileToProcess, String passWordHintDirectory, int minPasswordLength, int maxPasswordLength, int kthPasswordToPrint) 
        {
            PasswordTemplate ptemplate = new PasswordTemplate(passWordHintDirectory + "\\hintsFolder",
                            passWordHintDirectory + "\\codeMap.txt",
                            passWordHintDirectory + "\\patterns.txt", minPasswordLength, maxPasswordLength, kthPasswordToPrint);
            ptemplate.Initialize(true);

            if (archiveFileType == @"7zip") 
            {
                Console.WriteLine("Provided file type is 7Zip");
                ZipFilePasswordChecker zfpc = new ZipFilePasswordChecker(ptemplate);
                zfpc.startEvaluation(fileToProcess);
            } 
            else if (archiveFileType == @"truecrypt")
            {
                Console.WriteLine("Provided file type is truecrypt");
                TrueCryptPasswordChecker tcpc = new TrueCryptPasswordChecker(ptemplate);
                tcpc.startEvaluation(fileToProcess);
            }
            else
            {
                Console.WriteLine("Unsupported file type given. Returning.");
                return;
            }
        }
    }
}
