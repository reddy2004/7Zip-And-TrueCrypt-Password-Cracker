# 7Zip-And-TrueCrypt-Password-Cracker
A password checking tool for finding out forgotten passwords for 7Zip files and TrueCrypt volumes.

Note: This is a password checking tool and not a cracker. The tools takes password patterns and tries out all the permutations and combinations of the password Hints provided by you. The program terminates after all the passwords are exhausted or if it finds a valid password.

This tool uses http://www.github.com/nccgroup/untrue & https://github.com/adoconnection/SevenZipExtractor for verifying passwords.

This tool needs 3 inputs.

(1) A folder containing all the hints partitioned into files, with each line carrying a portion of the password as hint. Ex. animals.txt, numbers.txt etc

(2) A codemap file that uses a code for each file. Ex. {ANIMAL} -> animals.txt, {NUM}->numbers.txt

(3) A pattern file that containts patterns to check. Each pattern must appear in a new line. Ex. {ANIMAL}#{NUM}, or {ANIMAL}{NUM}{NUM}{NUM} etc

I wrote this code to find out forgotten passwords for some very old archived files I had on my home Server.

You must try to break down the password patterns with good guesses. Attempting to brute force will take lot of time as this till simply tries of all permutations. Try to break down the input patterns to smaller chunks so that this tool can finish off in a few hours or days. If you feel the tools will take weeks, then your inputs are basically bad as it tends towards brute force. Usually its not worth trying if you think the best patterns you can provide is taking months to solve.
