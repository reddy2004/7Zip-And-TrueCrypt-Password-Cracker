# 7Zip-And-TrueCrypt-Password-Cracker
A password checking tool for finding out forgotten passwords for 7Zip files and TrueCrypt volumes.

Note: This is a password checking tool and not a cracker. This tool takes password patterns and tries out all the permutations and combinations of the password Hints provided by you. The program terminates after all the passwords are exhausted or if it finds a valid password.

This tool uses http://www.github.com/nccgroup/untrue & https://github.com/adoconnection/SevenZipExtractor for verifying passwords.

This tool needs 3 inputs.

(1) A folder containing all the hints partitioned into files, with each line carrying a portion of the password as hint. Ex. animals.txt, numbers.txt etc

(2) A codemap.txt file that uses a code for each file. Ex. {ANIMAL} -> animals.txt, {NUM}->numbers.txt

(3) A pattern file that containts patterns to check. Each pattern must appear in a new line. Ex. {ANIMAL}#{NUM}, or {ANIMAL}{NUM}{NUM}{NUM} etc

I wrote this code to find out forgotten passwords for some very old archived files I had on my home Server.

You must try to break down the password patterns with good guesses. Attempting to brute force will take lot of time as this program simply tries all of the password permutations. Try to break down the input patterns to smaller chunks so that this tool can finish off in a few hours or days. If you feel the tools will take weeks, then your inputs are basically bad as it tends towards a lot of brute force work. Usually its not worth trying if you think the best patterns you can provide is taking months to solve, You might as well explore other options.
Please use mainline branch

You have to download NuGet packages:

https://www.nuget.org/packages/SevenZipSharp.Interop/19.0.1?_src=template

https://www.nuget.org/packages/SharpCompress/0.26.0?_src=template

https://www.nuget.org/packages/Microsoft.NETCore.App/2.1.0?_src=template

https://www.nuget.org/packages/System.Configuration.ConfigurationManager/5.0.0?_src=template

You must also add BouncyCastle.CryptoExt and NDesk.Options to your project, these are located in the lib/ folder

