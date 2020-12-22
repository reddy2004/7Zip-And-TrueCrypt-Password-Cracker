using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace _7Zip_And_TrueCrypt_Password_Cracker
{
    class TrueCryptPasswordChecker
    {
        PasswordTemplate passwordTemplate;
        byte[] volumeHeaderSector;

        public TrueCryptPasswordChecker(PasswordTemplate pt)
        {
            passwordTemplate = pt;
        }

        /* 
         * Just iterate over the password generated and print a summary
         */
        public void SelfTest()
        {
            for (int i = 0; i < passwordTemplate.GetNumPatterns(); i++)
            {
                passwordTemplate.LoadPatternAtIndex(i);
                while (passwordTemplate.TestPrintPasswordAndIncrementCounters()) { }
            }
        }

        public void PreprocessFile(String file)
        {
            //Extract the volume header and store in memory
            Console.WriteLine("Extracting header sector from given true crypt volume");

            FileStream volumeHeaderFile = null;
            volumeHeaderFile = File.Open(file, FileMode.Open, FileAccess.Read);
            volumeHeaderSector = Utils.ReadSector(volumeHeaderFile, 0);
            volumeHeaderFile.Close();
        }

        public Boolean CheckPassword(String password)
        {
            if (UntrueProgram.CheckPasswordOnHeader(volumeHeaderSector, password))
            {
                Console.WriteLine("***** PASSWORD(TRUECRYPT): '" + password + "' is valid ***************");
                return true;
            }
            return false;
        }

        public void startEvaluation(String file)
        {
            Console.WriteLine("Given truecrypt volume (file) : " + file);
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
                        if (CheckPassword(password))
                        {
                            Console.WriteLine("Found Password : \"" + password + "\" for truecrypt volume");
                            return;
                        }
                    }
                }
            }

            passwordTemplate.PrintCheckpoint();
        }
    }
}
