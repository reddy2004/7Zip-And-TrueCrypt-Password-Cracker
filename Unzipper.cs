using SevenZip;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

/*
 * Contains check routines for both 7-zip files and trueCrypt.
 * Truecrypt runs in 4 threads, as we just need the header to be kept incore once.
 */
namespace _7Zip_And_TrueCrypt_Password_Cracker
{
    class ThreadRunner {

        PasswordGenerator pg = null;
        byte[] volumeHeaderSector = null;
        public ThreadRunner(byte[] hdr, PasswordGenerator p)
        {
            pg = p;
            volumeHeaderSector = hdr;
        }

        public void looper() {
            String currentPassword = "";
            while ((currentPassword = pg.next()) != null)
            {
                if (pg.passwordFoundTerminationFlag) {
                    break;
                }
                if (currentPassword.Length > 0)
                {
                    Console.WriteLine("[" + pg.generatedPasswordCount + "/" + pg.totalPasswordsCreated + "] " + currentPassword);
                    if (pg.totalPasswordsCreated % 1000 == 0)
                    {
                        pg.Checkpoint();
                        Console.WriteLine("[" + pg.generatedPasswordCount + "/" + pg.totalPasswordsCreated + "] " + currentPassword);
                    }

                    bool returnValue = UntrueProgram.CheckPasswordOnHeader(volumeHeaderSector, currentPassword);

                    if (returnValue)
                    {
                        pg.passwordFoundTerminationFlag = true;
                        Console.WriteLine("Found Password : \"" + currentPassword + "\" for file");
                        break;
                    }
                }

            }
        }
    }

    class Unzipper
    {
        public Unzipper()
        {
            SevenZipExtractor.SetLibraryPath(@"C:\Program Files\7-Zip\7z.dll");
        }

        /* 
         * True crypt volume header can be stored in memory, so we create 4 threads
         */
        public void TrueCryptChecker(String file, String pwhintsFile)
        {
            Console.WriteLine("Checking for file " + file);
            PasswordGenerator pg = new PasswordGenerator(5, pwhintsFile); //todo make it variable
            
            Console.WriteLine("wordCount = " + pg.wordCount);

            FileStream volumeHeaderFile = null;
            volumeHeaderFile = File.Open(file, FileMode.Open, FileAccess.Read);
            byte[] volumeHeaderSector = Utils.ReadSector(volumeHeaderFile, 0);
            volumeHeaderFile.Close();

            ThreadRunner tr1 = new ThreadRunner(volumeHeaderSector, pg);
            ThreadRunner tr2 = new ThreadRunner(volumeHeaderSector, pg);
            ThreadRunner tr3 = new ThreadRunner(volumeHeaderSector, pg);
            ThreadRunner tr4 = new ThreadRunner(volumeHeaderSector, pg);

            Thread thr1 = new Thread(new ThreadStart(tr1.looper));
            Thread thr2 = new Thread(new ThreadStart(tr2.looper));
            Thread thr3 = new Thread(new ThreadStart(tr3.looper));
            Thread thr4 = new Thread(new ThreadStart(tr4.looper));

            thr1.Start();
            thr2.Start();
            thr3.Start();
            thr4.Start();
        }

        public Boolean FileCheckerFor7Zip(String file, String pwhintsFile)
        {
            PasswordGenerator pg = new PasswordGenerator(4, pwhintsFile);
            String currentPassword = "";
            Console.WriteLine("wordCount = " + pg.wordCount);

            while ((currentPassword = pg.next()) != null)
            {
                if (currentPassword.Length > 0)
                {
                    Console.WriteLine("[" + pg.generatedPasswordCount + "/" + pg.totalPasswordsCreated + "] " + currentPassword);
                    if (pg.generatedPasswordCount % 100 == 0)
                    {
                        pg.Checkpoint();
                        Console.WriteLine("[" + pg.generatedPasswordCount + "/" + pg.totalPasswordsCreated + "] " + currentPassword);
                    }
                    bool returnValue = CheckPassword(file, currentPassword);
                    if (returnValue)
                    {
                        Console.WriteLine("Found Password : \"" + currentPassword  + "\" for file " + file);
                        return true;
                    }
                }

            }
           
            Console.WriteLine(">>> Total Passwords tested (7Zip) >>> " + pg.generatedPasswordCount);
            return false;
        }

        public Boolean CheckPassword(String file, String password)
        {
            using (var extractor = new SevenZipExtractor(file, password))
            {
                Console.WriteLine(extractor.Password);
                Console.WriteLine(extractor.ArchiveFileNames.Count);

                foreach (ArchiveFileInfo entry in extractor.ArchiveFileData)
                {
                    Console.WriteLine("-->" + entry.FileName + "," + entry.Size);

                }
                try
                {
                    /*
                     * Try to extract, if there is no exception, then we are able to decrypt correctly
                     */ 
                    extractor.ExtractFiles(@"C:\Users\91998\Desktop\DELETE", @"7Zip-And-TrueCrypt-Password-Cracker\lib");
                    return true;
                }
                catch (Exception e) {
                    Console.WriteLine(e.StackTrace);
                    Console.WriteLine(e.Message);
                    return false;
                }
            }
        }
    }
}
