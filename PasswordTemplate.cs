using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace _7Zip_And_TrueCrypt_Password_Cracker
{
    class PasswordTemplate
    {
        String passwordHintsFolder;
        String codeMappingFilepath;
        String queryPatternsFilePath;

        Dictionary<String, String>  codesForFiles;
        LinkedList<String>          checkPatterns;
        LinkedList<String>          hintFilesList = new LinkedList<string>();

        int minPasswordLength;
        int maxPasswordLength;
        int kthPasswordToPrint;

        Dictionary<String, String[]>    wordList = new Dictionary<String, String[]>();
        Dictionary<String, int>         wordListCount = new Dictionary<string, int>();
        Dictionary<String, int[][]>     wordExclusionLists = new Dictionary<String, int[][]>();
        Dictionary<String, String[]>    preferedWordPositiosn = new Dictionary<String, String[]>();
        Dictionary<String, int[]>       numExclusionsGroupsForWords = new Dictionary<string, int[]>();

        //lock object and exit function
        static readonly object _object = new object();
        public Boolean passwordFoundTerminationFlag = false;

        //For each pattern, these data is refreshed.
        private Boolean     isPatternLoaded = false;
        private String      currentEvaluatingPattern;
        private int         currentPatternMaxSegments;
        private int[]       currentPatternSegmentIterator;

        private String[]    stringAttachSegments;
        private Boolean[]   isStringAttachSegmentACode;
        private int         stringComponentsInPattern;
        private String[]    codeAtSegmentPosition;

        //Track overall progress
        public long     generatedPasswordCount = 0;
        public long     totalPasswordsCreated = 0;
        public String   currentPassword = "";
        public long     bruteForcePasswordCount = 0;

        /*
         * Print the current values in memory for debugging
         */
        public void PrintCheckpoint()
        {
            Console.WriteLine("----------------------------------- checkpoint ---------------------------------------");
            Console.WriteLine("Evaluated passwords: " + generatedPasswordCount + "/" + totalPasswordsCreated);
            Console.WriteLine("currentPassword : " + currentPassword);
            Console.WriteLine("Ispatternloaded:" + isPatternLoaded + ", [" + currentEvaluatingPattern + "]");
            Console.WriteLine("currentPatternMaxSegments:" + currentPatternMaxSegments);
            StringBuilder sb = new StringBuilder();
            for (int i = currentPatternMaxSegments - 1; i >= 0; i--)
            {
                sb.Append(currentPatternSegmentIterator[i] + ":");
            }
            Console.WriteLine("currentPatternSegmentIterator: " + sb.ToString());
            sb = new StringBuilder();
            for (int i = 0; i < stringComponentsInPattern; i++)
            {
                if (isStringAttachSegmentACode[i])
                    sb.Append("{" + stringAttachSegments[i] + "}");
                else
                    sb.Append(stringAttachSegments[i]);
            }
            Console.WriteLine("stringAttachSegments : " + sb.ToString());
            sb = new StringBuilder();
            for (int i = currentPatternMaxSegments - 1; i >= 0; i--)
            {
                String code = codeAtSegmentPosition[i];
                String[] wl = wordList[code];
                sb.Append(code + "[" + currentPatternSegmentIterator[i] + "/" + wordListCount[code] + ",'" + wl[currentPatternSegmentIterator[i]] + "']:");

            }
            Console.WriteLine("codeAtSegmentPosition : " + sb.ToString());
            Console.WriteLine("----------------------------------- <end> ---------------------------------------");
        }
        public PasswordTemplate(String templateFolderPath, String codeMappingFile, String queryPatterns, int min, int max, int kth)
        {
            passwordHintsFolder = templateFolderPath;
            codeMappingFilepath = codeMappingFile;
            queryPatternsFilePath = queryPatterns;
            minPasswordLength = min;
            maxPasswordLength = max;
            kthPasswordToPrint = kth;
        }

        public Boolean Initialize(bool verbose)
        {
            if (verbose)
            {
                Console.WriteLine("Password hints data given is:");
                Console.WriteLine(codeMappingFilepath);
                Console.WriteLine(queryPatternsFilePath);
            }
            codesForFiles = ReadCodeMappingFile(codeMappingFilepath);
            if (codesForFiles == null)
            {
                Console.WriteLine("Failed to read " + codeMappingFilepath + ". Aborting init");
                return false;
            }
            checkPatterns = ReadQueryPatternsFile(queryPatternsFilePath);
            if (checkPatterns == null)
            {
                Console.WriteLine("Failed to read " + queryPatternsFilePath + ". Aborting init");
                return false;
            }
            if (VerifyPasswordTemplate() == false)
            {
                Console.WriteLine("Failed to verify the password template settings. Aborting init");
                return false;
            }
            Console.WriteLine("Password files Init sucessfull, we are ready to rock and roll");
            return true;
        }

        public int GetNumPatterns()
        {
            return checkPatterns.Count;
        }

        public String GetPatternAtIndex(int idx)
        {
            return checkPatterns.ElementAt(idx);
        }

        public bool LoadPatternAtIndex(int idx)
        {
            if (idx >= checkPatterns.Count)
            {
                Console.WriteLine("Pattern index out of range. Returning");
                return false;
            }
            UnloadPattern();
            LoadNewPattern(checkPatterns.ElementAt(idx));
            Console.WriteLine("---------------------------------------------------------------------------------");
            Console.WriteLine("Loaded new pattern to evaluate : " + checkPatterns.ElementAt(idx));
            Console.WriteLine("---------------------------------------------------------------------------------");
            return true;
        }

        private LinkedList<String> ReadQueryPatternsFile(String queryPatternFile)
        {
            LinkedList<String> qp = new LinkedList<string>();
            try
            {
                using (StreamReader sr = new StreamReader(queryPatternFile))
                {
                    String line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        qp.AddLast(line);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("The file could not be read:" + queryPatternFile);
                Console.WriteLine(e.Message);
                return null;
            }
            return qp;
        }

        private Dictionary<String, String> ReadCodeMappingFile(String codeMapFile)
        {
            Dictionary<String, String> codeMapping = new Dictionary<string, string>();
            try
            {
                using (StreamReader sr = new StreamReader(codeMapFile))
                {
                    String line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        String[] words = line.Split(',');
                        codeMapping.Add(words[0], words[1]);
                        Console.WriteLine("Parsed [code,file] input [" + words[0] + "," + words[1] + "]");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("The codeMapFile could not be read:" + codeMapFile);
                Console.WriteLine(e.Message);
                return null;
            }
            return codeMapping;
        }

        private String GetCodeForHintFile(String hintFile)
        {
            foreach (var codeOfFile in codesForFiles)
            {
                String code = codeOfFile.Key;
                String path = codeOfFile.Value;
                if (path.Equals(hintFile))
                {
                    return code;
                }
            }
            return null;
        }
        private Boolean VerifyPasswordTemplate()
        {
            if (minPasswordLength > maxPasswordLength || maxPasswordLength == 0)
            {
                return false;
            }
            if (VerifyPasswordHintsFolder(passwordHintsFolder) == false)
            {
                Console.WriteLine("Consistency check on password hints folder has failed");
                return false;
            }
            foreach (var codeOfFile in codesForFiles)
            {
                String code = codeOfFile.Key;
                String path = codeOfFile.Value;
                Boolean codeToFileMappingIsValid = false;
                foreach (String hintFile in hintFilesList)
                {
                    if (hintFile.Equals(path))
                    {
                        codeToFileMappingIsValid = true;
                        break;
                    }
                }
                if (!codeToFileMappingIsValid)
                {
                    Console.WriteLine("Provided code [" + code + "," + path + "] is not valid. Please check your code maps file [" + codeMappingFilepath + "]");
                    return false;
                }
            }

            if (VerifyCheckPatterns() == false)
            {
                Console.WriteLine("Pattern Check format verification has failed!");
                return false;
            }
            return true;
        }

        /*
         * Verifies that all the patterns passed have corresponding hint files.
         * Ex. The{COLOR}foxjumpedover{OBJECT}
         * Ex. {COLOR}turnsto{COLOR}
         * Ex. {C0}X{C0}Version{INT}
         * where, {COLOR}, {C0}, {INT} and {OBJECT} are mapped to hint files.
         */
        private Boolean VerifyCheckPatterns()
        {
            Console.WriteLine("Checking pattern files. Total patterns provided:" + checkPatterns.Count);
            foreach (String pattern in checkPatterns)
            {
                Console.WriteLine("Input pattern \"" + pattern + "\"");
                LinkedList<String> codes = ExtractCodes(pattern);
                if (codes.Count == 0)
                {
                    Console.WriteLine("Pattern " + pattern + " does not have any valid codes. Please check formatting");
                    return false;
                }
                //For each code, verify user has provided an hint file.
                foreach (String code in codes)
                {
                    String hintsFile;
                    if (!codesForFiles.TryGetValue(code, out hintsFile))
                    {
                        Console.WriteLine("Code (" + code + ") of pattern (" + pattern + ") has no corresponding hints file");
                        return false;
                    }
                }
            }
            return true;
        }

        /*
         * Populates the segment iterators at that position and verifies if the password is valid or not.
         * For this to work, the pattern must be loaded along with initialization.
         */ 
        public Boolean TestPasswordAtIndex(int count, int[] positions)
        {
            if (!isPatternLoaded)
            {
                Console.WriteLine("Pattern is not loaded, so cannot test password at the provided index");
                return false;
            }
            if (count != currentPatternMaxSegments) 
            {
                Console.WriteLine("Mismatch between provided count and max segments as per loaded pattern [" + currentPatternMaxSegments + " vs " + count);
                return false;
            }
            for (int i = currentPatternMaxSegments - 1; i >= 0; i--)
            {
                currentPatternSegmentIterator[i] = positions[i];
            }
            Console.WriteLine("Test password : " + GetCurrentIteratingPassword());
            
            Console.WriteLine("isOkay() : "  + isOkay());
            Console.WriteLine("isNumComponentsOkay() : " + isNumComponentsOkay());
            Console.WriteLine("isPositionsOkay() : " + isPositionsOkay());
            Console.WriteLine("isExclusionsOkay() : " + isExclusionsOkay());
            return (isOkay() && isNumComponentsOkay() && isPositionsOkay() && isExclusionsOkay());
        }

        private LinkedList<String> ExtractCodes(String pattern)
        {
            int fIndex = 0;
            int lIndex = 0;
            LinkedList<String> codesInPattern = new LinkedList<String>();
            while (fIndex != -1 && lIndex != -1)
            {
                fIndex = pattern.IndexOf("{");
                lIndex = pattern.IndexOf("}");
                if (fIndex < lIndex && (lIndex - fIndex) >= 2)
                {
                    codesInPattern.AddLast(pattern.Substring(fIndex + 1, (lIndex - fIndex - 1)));
                }
                pattern = pattern.Substring(lIndex + 1);
            }
            return codesInPattern;
        }
        /*
         * Check the files folder and verifies that there is no conflicting logic in password files.
         * Checks that all the password files have codes defined.
         */
        private Boolean VerifyPasswordHintsFolder(String directory)
        {
            // Process the list of files found in the directory.
            string[] fileEntries = Directory.GetFiles(directory);
            foreach (string fileName in fileEntries)
            {
                Boolean retval = VerifyPasswordsFile(fileName);
                if (retval == false)
                {
                    Console.WriteLine("Password hint file [" + fileName + "] verification has failed!");
                    return false;
                }
            }

            // Recurse into subdirectories of this directory.
            string[] subdirectoryEntries = Directory.GetDirectories(directory);
            foreach (string subdirectory in subdirectoryEntries)
            {
                Boolean retval = VerifyPasswordHintsFolder(subdirectory);
                if (retval == false)
                {
                    Console.WriteLine("Password hint directory [" + subdirectory + "] verification has failed");
                    return false;
                }
            }
            return true;
        }

        private String RelativeFilePath(String file)
        {
            return file.Substring(passwordHintsFolder.Length + 1, file.Length - passwordHintsFolder.Length - 1);
        }

        /*
         * We have two groups of words, we dont want them to be checked together since we know its part of password, but
         * not sure if its upper case or lower case. "1" and "2" are exclusion groups. Only one of the variant can be part
         * of the password, never two or more segments of the same group
         * 1,F,sheep,1
         * 2,F,Sheep,1
         * 3,F,Goat,2
         * 4,F,goat,2
         * A simple conflict example, when we add "black" and we dont want black to be a part of sheep or goat (incorrect grouping)
         * 1,F,sheep,1,3
         * 2,F,Sheep,1,3   << bad, since now because all words are in exclusion group '3', goat and sheep will never
         * 3,F,Goat,2,3    <<  come together. We want goat and sheep to be evaluated in the same password.
         * 4,F,goat,2,3
         * 5,F,Black,3
         * 6,F,black,3
         * We dont want "sheep" and "Sheep" together in a password, and also "goat" and "Goat. But we are okay to have
         * goat & sheep in the password. If we add "black" and we dont want black to be included, the above consistency
         * check fails because now "sheep" and "goat" will be excluded because of group "3". Correct version should look something like below
         * 1,F,sheep,1,4       <<sheep cannot appear with Sheep & Black/black
         * 2,F,Sheep,1,4       <<Sheep cannot appear with sheep & Black/black
         * 3,F,Goat,2,3        <<same as above
         * 4,F,goat,2,3
         * 5,F,Black,3,4
         * 6,F,black,3,4
         * The above "3" and "4" groups will exclude black coming together with either sheep/goat, but wont prevent
         * sheep & goat coming in the same password.
         */
        public Boolean EvaluateInputWordListForConflicts(String code)
        {
            return true;
        }

        /*
         * Verifies that the password file does not have any conflicting logic
         */
        private Boolean VerifyPasswordsFile(String hintsFile)
        {
            String relativeHintsPath = RelativeFilePath(hintsFile);
            String code = GetCodeForHintFile(relativeHintsPath);
            if (code == null)
            {
                Console.WriteLine("There is no corresponding CODE found for hint file [ " + relativeHintsPath + "]");
                //This hint file is not being used for this run. Dont worry, just return.
                return true;
            }

            int wordCount = 0;

            String[] allWordsList = new String[100]; //100 itself is quite big.
            int[][] wordExclusionList = new int[100][];
            int[] numExclusionsGroupsForWord = new int[100];
            String[] tpreferedWordPosition = new String[100];

            for (int i = 0; i < 100; i++)
            {
                wordExclusionList[i] = new int[100]; //100 groups
            }

            try
            {
                using (StreamReader sr = new StreamReader(hintsFile))
                {
                    String line;
                    allWordsList[wordCount++] = "";

                    while ((line = sr.ReadLine()) != null)
                    {
                        String[] words = line.Split(',');
                        int index = Int32.Parse(words[0]);
                        if (index != wordCount)
                        {
                            Console.WriteLine("Exiting since indexes in [ " + relativeHintsPath + " ] did not match");
                            return false;
                        }
                        tpreferedWordPosition[wordCount] = words[1];

                        allWordsList[wordCount] = words[2];
                        if (words.Length > 2)
                        {
                            for (int ex = 3; ex < words.Length; ex++)
                            {
                                wordExclusionList[wordCount][ex - 3] = Int32.Parse(words[ex]);
                            }
                        }
                        numExclusionsGroupsForWord[wordCount] = words.Length - 3;
                        wordCount++;
                    }
                }

                wordList.Add(code, allWordsList);
                wordListCount.Add(code, wordCount);
                wordExclusionLists.Add(code, wordExclusionList);
                preferedWordPositiosn.Add(code, tpreferedWordPosition);
                numExclusionsGroupsForWords.Add(code, numExclusionsGroupsForWord);
                hintFilesList.AddLast(relativeHintsPath);
                return EvaluateInputWordListForConflicts(code);
            }
            catch (Exception e)
            {
                Console.WriteLine("Password file [ " + hintsFile + " ] could not be read");
                Console.WriteLine(e.Message);
                return false;
            }
        }

        private Boolean HasEmbeddedCodeSegment(String pattern)
        {
            int fIndex = pattern.IndexOf("{");
            int lIndex = pattern.IndexOf("}");
            if (fIndex < lIndex && fIndex != -1 && (lIndex - fIndex) >= 2)
            {
                String code = pattern.Substring(fIndex + 1, (lIndex - fIndex - 1));
                //Check code is present
                foreach (var entry in codesForFiles)
                {
                    if (entry.Key.Equals(code))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        private void UnloadPattern()
        {
            isPatternLoaded = false;
            stringComponentsInPattern = 0;
            stringAttachSegments = null;
            isStringAttachSegmentACode = null;

            currentEvaluatingPattern = "";
            currentPatternMaxSegments = 0;
            currentPatternSegmentIterator = null;
        }

        /*
         * Init are internal datastructures to start generating passwords for the new pattern
         */
        public void LoadNewPattern(String pattern)
        {
            stringComponentsInPattern = 0;
            stringAttachSegments = new String[32];
            isStringAttachSegmentACode = new Boolean[32];
            currentEvaluatingPattern = pattern;

            LinkedList<String> codes = ExtractCodes(pattern);
            // codes must come in order
            foreach (String code in codes)
            {
                String codeWithBraces = "{" + code + "}";
                int codeIndex = pattern.IndexOf(codeWithBraces);
                String prefix = pattern.Substring(0, codeIndex);
                String postfix = pattern.Substring(codeIndex + codeWithBraces.Length);
                Boolean hasEmbedd = HasEmbeddedCodeSegment(postfix);
                if (!String.IsNullOrEmpty(prefix))
                {
                    stringAttachSegments[stringComponentsInPattern] = prefix;
                    isStringAttachSegmentACode[stringComponentsInPattern] = false;
                    stringComponentsInPattern++;
                }
                stringAttachSegments[stringComponentsInPattern] = code;
                isStringAttachSegmentACode[stringComponentsInPattern] = true;
                stringComponentsInPattern++;
                if (!hasEmbedd && !String.IsNullOrEmpty(postfix))
                {
                    stringAttachSegments[stringComponentsInPattern] = postfix;
                    isStringAttachSegmentACode[stringComponentsInPattern] = false;
                    stringComponentsInPattern++;
                    break;
                }
                pattern = postfix;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < stringComponentsInPattern; i++)
            {
                sb.Append(stringAttachSegments[i]);
                Console.WriteLine("[" + i + "] " + stringAttachSegments[i] + " isCode:" + isStringAttachSegmentACode[i]);
            }
            Console.WriteLine(sb.ToString());


            currentPatternMaxSegments = codes.Count;
            currentPatternSegmentIterator = new int[codes.Count];

            codeAtSegmentPosition = new String[codes.Count];

            int currentEstimatedPasswordsForPattern = 1;

            for (int i = 0; i < codes.Count; i++)
            {
                String code = codes.ElementAt(i);
                codeAtSegmentPosition[codes.Count - i - 1] = code;
                Console.WriteLine("[Code, words] = [" + code + "," + (wordListCount[code] - 1) + "]");
                currentEstimatedPasswordsForPattern *= wordListCount[code];
            }

            Console.WriteLine("Estimated passwords brute force:" + currentEstimatedPasswordsForPattern) ;
            Console.WriteLine("currentPatternMaxSegments: " + currentPatternMaxSegments);
            bruteForcePasswordCount += currentEstimatedPasswordsForPattern;
            isPatternLoaded = true;
        }

        private bool isLengthOkay(String password)
        {
            if (password.Length >= minPasswordLength &&
                password.Length <= maxPasswordLength)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private bool isNumComponentsOkay()
        {
            //return false if there is "" in between.
            int components = 0;
            int firstBlankPosition = currentPatternMaxSegments - 1;
            int firstWordPosition = 0;
            for (int i = currentPatternMaxSegments - 1; i >= 0; i--)
            {
                if (currentPatternSegmentIterator[i] > 0)
                {
                    firstWordPosition = (firstWordPosition == 0) ? currentPatternSegmentIterator[i] : 0;
                    components++;
                }
                else
                {
                    firstBlankPosition = (firstBlankPosition == currentPatternMaxSegments - 1) ?
                            (currentPatternMaxSegments - 1) : currentPatternSegmentIterator[i];
                }
            }
            return !(firstWordPosition > firstBlankPosition);
        }

        //we dont want repetitions of segments, right?
        private bool isOkay()
        {
            Dictionary<String, int[]> repetitionCheck = new Dictionary<string, int[]>();

            for (int i = 0; i < currentPatternMaxSegments; i++)
            {
                String code = codeAtSegmentPosition[i];
                int[] dummy;
                if (!repetitionCheck.TryGetValue(code, out dummy)) {
                    repetitionCheck.Add(code, new int[wordListCount[code]]);
                }
            }

            for (int i = 0; i < currentPatternMaxSegments; i++)
            {
                //Console.WriteLine("[" + codeAtSegmentPosition[i] + "] @index[" + i + " ] of segments = " + currentPatternSegmentIterator[i]);
                if (currentPatternSegmentIterator[i] > 0)
                {
                    String code = codeAtSegmentPosition[i];
                    int[] listToUpdate = repetitionCheck[code];
                    listToUpdate[currentPatternSegmentIterator[i]]++;
                }
            }
            foreach (var entry in repetitionCheck)
            {
                String code = entry.Key;
                int[] list = entry.Value;
                for (int i = 0; i < list.Length; i++)
                {
                    if (list[i] > 1)
                    {
                        //Console.WriteLine("[" + code + "] @index[" + i + " ] = " + list[i]);
                        return false;
                    }
                }
            }
            //Console.WriteLine("isOkay() suceeded");
            return true;
        }

        /*
         * F = the word is always in the first position
         * L = Word always in last position
         * FL = First or last position
         * M = Always in middle
         * NF = Not in first, but anywhere else
         * NL = Not in last, but anywhere else
         * A = Can be present anywhere.
         * 
         */ 
        private bool isPositionsOkay()
        {
            int firstWordPosition = -1;
            int lastWordPosition = 0;

            for (int i = currentPatternMaxSegments - 1; i >= 0; i--)
            {
               // Console.WriteLine("preferedWordPositiosn[" + codeAtSegmentPosition[i] + "][" + currentPatternSegmentIterator[i] + "]" +
               //     preferedWordPositiosn[codeAtSegmentPosition[i]][currentPatternSegmentIterator[i]]);

                if (currentPatternSegmentIterator[i] > 0 && firstWordPosition == -1)
                {
                    firstWordPosition = i;
                }
                if (currentPatternSegmentIterator[i] > 0)
                {
                    lastWordPosition = i;
                }
            }

            if (firstWordPosition == -1)
            {
                return false;
            }
            else
            {
                Boolean isSingleWord = (firstWordPosition == lastWordPosition);
                String codeAtFirstPosition = codeAtSegmentPosition[firstWordPosition];
                String codeAtLastPosition = codeAtSegmentPosition[lastWordPosition];

                String posF = preferedWordPositiosn[codeAtFirstPosition][currentPatternSegmentIterator[firstWordPosition]];
                String posL = preferedWordPositiosn[codeAtLastPosition][currentPatternSegmentIterator[lastWordPosition]];
                //Console.WriteLine("posf=" + posF + " posL=" + posL + " and " + firstWordPosition + "-" + lastWordPosition);

                if (isSingleWord)
                {
                    return true;
                }

                if (!(posF.Equals("F") || posF.Equals("A") || posF.Equals("NL") || posF.Equals("FL")))
                {
                    return false;
                }

                if (!(posL.Equals("L") || posL.Equals("A") || posF.Equals("NF") || posF.Equals("FL")))
                {
                    return false;
                }
                for (int i = firstWordPosition - 1; i >= lastWordPosition + 1; i--)
                {
                    String codeAtPosition = codeAtSegmentPosition[i];
                    if (currentPatternSegmentIterator[i] > 0)
                    {
                        String posM = preferedWordPositiosn[codeAtPosition][currentPatternSegmentIterator[i]];
                        if (!(posM.Equals("A") || posM.Equals("M") || posM.Equals("NF") || posM.Equals("NL")))
                        {
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        private bool isExclusionsOkay()
        {
            Dictionary<String, int[]> repetitionCheck = new Dictionary<string, int[]>();

            for (int i = 0; i < stringComponentsInPattern; i++)
            {
                if (isStringAttachSegmentACode[i])
                {
                    String code = stringAttachSegments[i];
                    int[] dummy;
                    if (!repetitionCheck.TryGetValue(code, out dummy))
                    {
                        repetitionCheck.Add(code, new int[100]); //100 exclusion groups
                    }                    
                }
            }

            for (int i = 0; i < currentPatternMaxSegments; i++)
            {
                if (currentPatternSegmentIterator[i] > 0)
                {
                    String code = codeAtSegmentPosition[i];
                    int[] numExclusionsGroupsForWordTemp = numExclusionsGroupsForWords[code];
                    int[] listToUpdate = repetitionCheck[code];
                    int[][] wordExclusionList = wordExclusionLists[code];
                    for (int p = 0; p < numExclusionsGroupsForWordTemp[currentPatternSegmentIterator[i]]; p++)
                    {
                        listToUpdate[wordExclusionList[currentPatternSegmentIterator[i]][p]]++;
                        //Console.WriteLine(allWordsList[segmentIterator[i]] + ".." + wordExclusionList[segmentIterator[i]][p]);
                    }
                }
            }
            /*
            foreach (var entry in repetitionCheck)
            {
                String code = entry.Key;
                int[] list = entry.Value;
                for (int i = 0; i < list.Length; i++)
                {
                    if (list[i] > 1)
                    {
                        //Console.WriteLine("k [" + i + " ] = " + k[i]);
                        return false;
                    }
                }
            }
            */
            return true;
        }

        /*
         * Prints the current password at the current iteration and automatically increments the indexes
         * to the next password position
         * */
        public Boolean TestPrintPasswordAndIncrementCounters()
        {
            Console.WriteLine(GetCurrentIteratingPassword());
            return incrementBucketPosition(0);
        }

        private Boolean incrementBucketPosition(int bucketid)
        {
            String code = codeAtSegmentPosition[bucketid];
            int wordCount = wordListCount[code];
            if (bucketid == currentPatternMaxSegments - 1 && currentPatternSegmentIterator[bucketid] == wordCount - 1)
            {
                //we are done.
                return false;
            }
            if (currentPatternSegmentIterator[bucketid] == wordCount - 1)
            {
                //We have exhausted;
                currentPatternSegmentIterator[bucketid] = 0;
                return incrementBucketPosition(bucketid + 1);
            }

            currentPatternSegmentIterator[bucketid]++;
            return true;
        }

        private String GetCurrentIteratingPassword() 
        {
            StringBuilder sb = new StringBuilder();
            int counter = currentPatternMaxSegments;
            for (int k = 0; k < stringComponentsInPattern; k++)
            {
                if (isStringAttachSegmentACode[k])
                {
                    counter--;
                    String code = codeAtSegmentPosition[counter];
                    sb.Append(wordList[code][currentPatternSegmentIterator[counter]]);
                }
                else
                {
                    sb.Append(stringAttachSegments[k]);
                }

            }
            return sb.ToString();
        }
        /*
         * Returns the next string, Its upto the caller to examine the public members of this class to 
         * figure out the state of the password generation progress and the pattern being worked on.
         * Can return empty String, the caller must ignore the empty string ""
         * Return value of null implies the process has error or its done with all password iterations
         */
        public String next()
        {
            lock (_object)
            {
                if (isPatternLoaded == false) {
                    Console.WriteLine("No pattern loaded to evalute, Please provide an input pattern. Terminating!");
                    return null;
                }

                if (totalPasswordsCreated >= bruteForcePasswordCount)
                {
                    Console.WriteLine("We have already generated all the passwords, Exiting");
                    return null;
                }

                if (true == incrementBucketPosition(0))
                {
                    totalPasswordsCreated++;
                    String xpw = GetCurrentIteratingPassword();

                    currentPassword = xpw;
                    if (/*isOkay() && */ isNumComponentsOkay() && isPositionsOkay() && isExclusionsOkay())
                    {
                        if (isLengthOkay(xpw))
                        {
                            generatedPasswordCount++;
                            //Console.WriteLine("Valid pasword: " + xpw);
                            return xpw;
                        }
                        return "";
                    }

                    if (totalPasswordsCreated % kthPasswordToPrint == 0)
                        Console.WriteLine("Current " + xpw + ":" + totalPasswordsCreated + ":" + isOkay() + ":" + isPositionsOkay() + ":" + isExclusionsOkay());

                    return "";
                }
                else
                {
                    return null;
                }
            }
        }
    }
}
