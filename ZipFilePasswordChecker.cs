using System;
using System.Collections.Generic;
using System.Text;
using SevenZip;

namespace _7Zip_And_TrueCrypt_Password_Cracker
{
    class ZipFilePasswordChecker
    {
        PasswordTemplate passwordTemplate;

        String extractTo = "";
        ulong smallFileSize = 0;
        int smallFileIndex = 0;
        String smallFileName = "";

        public ZipFilePasswordChecker(PasswordTemplate pt)
        {
            passwordTemplate = pt;
            SevenZipExtractor.SetLibraryPath(@"C:\Program Files\7-Zip\7z.dll");
        }

        public static String GetExtractionFolderLocation(String filepath)
        {
            int idx = filepath.LastIndexOf(@"\");
            if (idx == -1)
            {
                return "";
            } 
            else 
            {
                return filepath.Substring(0, idx + 1);
            }
        }

        /* 
         * Just iterate over the password generated and print a summary
         */
        public void SelfTest()
        {
            for (int i = 0; i < passwordTemplate.GetNumPatterns(); i++)
            {
                passwordTemplate.LoadPatternAtIndex(i);
                while(passwordTemplate.TestPrintPasswordAndIncrementCounters()) { }
            }
        }

        public void PreprocessFile(String file)
        {
            Console.WriteLine("Starting pre-processing routine. This will identify a target file that we will try to extract for each password permutation");

            using (var extractor = new SevenZipExtractor(file, "SomeDummyPassword"))
            {
                extractTo = ZipFilePasswordChecker.GetExtractionFolderLocation(file);

                Console.WriteLine("Trying password: '" + extractor.Password + "'");
                Console.WriteLine("Total file in archive " + extractor.ArchiveFileNames.Count);

                Console.WriteLine("Trying to figure the smallest file in the archive to extract...");
                foreach (ArchiveFileInfo entry in extractor.ArchiveFileData)
                {
                    if (smallFileSize == 0 || smallFileSize > entry.Size)
                    {
                        try
                        {
                            extractor.ExtractFiles(extractTo, entry.Index);
                        }
                        catch (Exception e)
                        {
                            //Failed extraction, this is a good test file. Mostly like with throw exceptions
                            //for all incorrect passwords.
                            smallFileSize = entry.Size;
                            smallFileIndex = entry.Index;
                            smallFileName = entry.FileName;
                        }
                    }
                }
            }
            Console.WriteLine("Finished preProcessing");
            Console.WriteLine("Extraction Folder: " + extractTo);
            Console.WriteLine("File that will be attempted to extract: " + smallFileName);
            Console.WriteLine("Size and index of that file: " + smallFileSize + " & " + smallFileIndex);

        }

        public Boolean CheckPassword(String file, String password)
        {
            using (var extractor = new SevenZipExtractor(file, password))
            {
                try
                {
                    /*
                     * Try to extract, if there is no exception, then we are able to decrypt correctly
                     */
                    extractor.ExtractFiles(extractTo, smallFileIndex);
                    Console.WriteLine("***** PASSWORD (7ZIP): '" + password + "' is valid ***************");
                    return true;
                }
                catch (Exception e)
                {
                    return false;
                }
            }
        }

        public void startEvaluation(String file)
        {
            PreprocessFile(file);

            for (int i = 0; i < passwordTemplate.GetNumPatterns(); i++)
            {
                passwordTemplate.LoadPatternAtIndex(i);
                String password;

                while (true)
                {
                    password = passwordTemplate.next();
                    if (password == null)
                    {
                        Console.WriteLine("Finished evaluating pattern @ index: " + i + "(" + passwordTemplate.GetPatternAtIndex(i) + ")");
                        passwordTemplate.PrintCheckpoint();
                        break;
                    } 
                    else if (!String.IsNullOrEmpty(password))
                    {
                        bool returnValue = CheckPassword(file, password);
                        if (returnValue)
                        {
                            Console.WriteLine("Found Password : \"" + password + "\" for file " + file);
                            return;
                        }
                    }
                }
            }

            passwordTemplate.PrintCheckpoint();
        }
    }
}
