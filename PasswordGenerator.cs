using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace _7Zip_And_TrueCrypt_Password_Cracker
{
    public class PasswordGenerator
    {
        static readonly object _object = new object();
        public Boolean passwordFoundTerminationFlag = false;

        public int maxSegments;
        public int maxPasswordLength = 15;
        public int minPasswordLength = 5;

        int[] segmentIterator;
        String[] allWordsList;
        int[][] wordExclusionList; //Ex: Dont check for "Ghost" & "ghost" together.
        String[] preferedWordPosition;
        int[] numExclusionsGroupsForWord; //Ex: Dont check for "Ghost" & "ghost" together.
        public int wordCount;

        public long generatedPasswordCount = 0;
        public long totalPasswordsCreated = 0;

        //Wont be verified if it fits in graph since this is coming from disk.
        public void LoadListFromDisk(String pwhintFile)
        {
            allWordsList = new String[200]; //100 itself is quite big.

            //Exclusion list, for ex we dont want 1 hint to check along with another hint
            //Ex: 'Ghost' & 'ghost'. I know that i use one of those words as password, but never together.
            wordExclusionList = new int[200][];
            numExclusionsGroupsForWord = new int[200];
            preferedWordPosition = new String[200];

            for (int i = 0; i < 200; i++)
            {
                wordExclusionList[i] = new int[200]; //100 groups
            }

            try
            {
                using (StreamReader sr = new StreamReader(pwhintFile))
                {
                    String line;
                    //allow for empty word in the first position
                    allWordsList[wordCount++] = "";

                    while ((line = sr.ReadLine()) != null)
                    {
                        String[] words = line.Split(',');
                        Console.WriteLine("line " + line + " - " + words.Length + " & " + words[2]);
                        int index = Int32.Parse(words[0]);
                        if (index != wordCount) {
                            Console.WriteLine("Exiting since index didnt match");
                            return;
                        }
                        preferedWordPosition[wordCount] = words[1];

                        allWordsList[wordCount] = words[2];
                        if (words.Length > 2) {
                            for (int ex = 3; ex < words.Length; ex++)
                            {
                                //Console.WriteLine("parse " + words[ex]);
                                wordExclusionList[wordCount][ex-3] = Int32.Parse(words[ex]);
                            }
                        }
                        numExclusionsGroupsForWord[wordCount] = words.Length - 3;
                        //Console.WriteLine(line + "->" + numExclusionsGroupsForWord[wordCount]);
                        wordCount++;
                    }
                }

                //XXX/ Todo, evaluate conflicts of exclusion.
            }
            catch (Exception e)
            {
                Console.WriteLine("The file could not be read:");
                Console.WriteLine(e.Message);
            }
        }

        public PasswordGenerator(int m, String pwhintFile)
        {
            maxSegments = m;
            segmentIterator = new int[maxSegments];
            LoadListFromDisk(pwhintFile);
        }

        private Boolean incrementBucketPosition(int bucketid)
        {
            if (bucketid == maxSegments - 1 && segmentIterator[bucketid] == wordCount - 1)
            {
                //we are done.
                return false;
            }
            if (segmentIterator[bucketid] == wordCount - 1)
            {
                //We have exhausted;
                segmentIterator[bucketid] = 0;
                return incrementBucketPosition(bucketid + 1);
            }

            segmentIterator[bucketid]++;
            return true;
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

        private bool isNumComponentsOkay() {

            //return false if there is "" in between.
            int components = 0;
            int firstBlankPosition = maxSegments - 1;
            int firstWordPosition = 0;
            for (int i = maxSegments-1; i >= 0; i--)
            {
                if (segmentIterator[i] > 0)
                {
                    firstWordPosition = (firstWordPosition == 0) ? segmentIterator[i] : 0;
                    components++;
                }
                else 
                { 
                    firstBlankPosition = (firstBlankPosition == maxSegments - 1)? (maxSegments - 1): segmentIterator[i];
                }
            }
            return !(firstWordPosition > firstBlankPosition);
        }

        //we dont want repetitions of segments, right?
        private bool isOkay()
        {
           //Console.WriteLine(segmentIterator[3] + "." + segmentIterator[2] + "." + segmentIterator[1] + "." + segmentIterator[0]);
           //Console.WriteLine(allWordsList[segmentIterator[3]] + "." + allWordsList[segmentIterator[2]] + "." + allWordsList[segmentIterator[1]] + "." + allWordsList[segmentIterator[0]]);
            int[] k = new int[wordCount];
            for (int i = 0; i < maxSegments; i++)
            {
                if (segmentIterator[i] > 0)
                {
                    k[segmentIterator[i]]++;
                }
            }
            for (int i = 0; i < wordCount; i++)
            {
                if (k[i] > 1)
                {
                    //Console.WriteLine("k [" + i + " ] = " + k[i]);
                    return false;
                }
            }
            return true;
        }

        private bool isPositionsOkay() {
            int firstWordPosition = -1;
            int lastWordPosition = 0;

            for (int i = maxSegments-1; i >= 0 ; i--) {
                if (segmentIterator[i] > 0 && firstWordPosition == -1) {
                    firstWordPosition = i;
                }
                if (segmentIterator[i] > 0) {
                    lastWordPosition = i;
                }
            }

            if (firstWordPosition == -1) {
                return false;
            } 
            else
            {
                Boolean isSingleWord = (firstWordPosition == lastWordPosition);
                String posF = preferedWordPosition[segmentIterator[firstWordPosition]];
                String posL = preferedWordPosition[segmentIterator[lastWordPosition]];
                //Console.WriteLine("posf=" + posF + " posL=" + posL + " and " + firstWordPosition + "-" + lastWordPosition);

                if (isSingleWord) {
                    return true;
                }

                if (!(posF.Equals("F") || posF.Equals("A")))
                {
                    return false;
                }
                
                if (!(posL.Equals("L") || posL.Equals("A")))
                {
                    return false;
                }
                for (int i = firstWordPosition-1; i >= lastWordPosition+1; i--)
                {
                    if (segmentIterator[i] > 0)
                    {
                        String posM = preferedWordPosition[segmentIterator[i]];
                        if (!(posM.Equals("A") || posM.Equals("M")))
                        {
                            return false;
                        }
                    }
                }
            }
            return true;
        }
            
        private bool isPatternOkay(String pw) {
             return true;
        }
        private bool isExclusionsOkay() {
            int[] k = new int[wordCount];
            for (int i = 0; i < maxSegments; i++)
            {
                for (int p = 0; p < numExclusionsGroupsForWord[segmentIterator[i]]; p++)
                {
                    k[wordExclusionList[segmentIterator[i]][p]]++;
                    //Console.WriteLine(allWordsList[segmentIterator[i]] + ".." + wordExclusionList[segmentIterator[i]][p]);
                }
            }
            for (int i = 0; i < wordCount; i++)
            {
                if (k[i] > 1) return false;
            }
            return true;
        }

        public void Checkpoint() {
            Console.WriteLine("generatedPasswordCount = " + generatedPasswordCount);
            for (int k = maxSegments - 1; k >= 0; k--)
                Console.Write(segmentIterator[k] + ".");
            Console.WriteLine("");
        }

        public String next()
        {
            lock (_object)
            {
                if (true == incrementBucketPosition(0))
                {
                    totalPasswordsCreated++;
                    StringBuilder sb = new StringBuilder();
                    for (int k = maxSegments - 1; k >= 0; k--)
                    {
                        sb.Append(allWordsList[segmentIterator[k]]);

                    }
                    String xpw = sb.ToString();

                    if (isOkay() && isNumComponentsOkay() && isPositionsOkay() && isExclusionsOkay())
                    {

                        if (isLengthOkay(xpw))
                        {
                            generatedPasswordCount++;
                            return xpw;
                        }
                        return "";
                    }
                    else
                    {
                        if (totalPasswordsCreated % 1 == 0)
                         Console.WriteLine("failed " + xpw + ":" + totalPasswordsCreated + ":" + isPositionsOkay() + ":" + isExclusionsOkay());

                    }
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
