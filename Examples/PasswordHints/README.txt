Please read this before you start creating your password search templates

You need to provide 3 inputs to run this tool
1.	A hintsFolder/ (provided as example) which contains hints for one part of the password to be guessed.
2.	A codeMap file that the program can use to understand how to permute the parts given in (1).
3.	A pattern file that contains a pattern to be tested, each pattern in a new line.

Let's say, for example, that I usually use names of animals or fruits along with a number as my password. It could be something like Lion123 or tiger1tiger or abc@123 
You can quicky see that my password styles are something like
{ANIMAL}{NUMBER}{NUMBER}{NUMBER}
or
{ANIMAL}{ANIMAL}
or
{TEXTSEG}@{NUMBER}.

As I currently cannot brute force all these passwords manually, I can code the knowledge that I have in the 3 files mentioned in (1),(2) and (3)

I could create a RUN of these tool, for some password check.
Ex. Create a textSeg.txt file in hintsFolder/ and it contain information like
1,F,abc
2,F,xyz
3,F,mno
where I have listed the textSegments I normally use. I would also create another file for the third part of the password
Create a file secondTextSeg.txt in hintsFolder/ and it contains
1,L,123
1,L,321

The 'F' indicates that this segment will always be the first part of the password, while 'L' signifies that its always the last part of the password.
Other supported options are NF (Not first), NL (Not last), M (Middle)
NF = M + L
NL = M + F

After creating the two files in hintsFolder/, I now have to tell the tool how to link these segments to our patterns. For this, I create a codeMap.txt file, which contains two lines
TXT1,textSeg.txt
TXT2,secondTextSeg.txt

Finally, we create our patterns in patterns.txt. Each search pattern must appear in a new line. And coding string is in braces.
{TXT1}@{TXT2}

The following password will be generated an tried on the 7zip archive / truecrypt volume.
abc@123
abc@321
xyz@123
xyz@321
mno@123
mno@321

You can obserse that {TXT1} is replace with codes in TXT1,textSeg.txt, and {TXT2} is replaced with codes in TXT2,secondTextSeg.txt
All possible combinations of {TXT1}@{TXT2} are tried.

You can also refer to another example provided in the PasswordHints/ folder.


---------------- Adding exclusions -------------
Generally your passwords will follow a certain pattern. for ex. My password might contain "redhat" or "REDHat" or RedHat". You might want to check both upper and lower case characters, which is fine, but dont want to check them together.
i.e You want both 'Red' and 'red' to be checked but not 'Redred' or 'redRed' together as you already know they will never appear to gether in your password.

This is where exclusions come in. So how do you mark exclusions in the files in hintsFolder/ folder??
Think of it this way. For each file, construct a matrix of rows and columns with each password. In the matrix[i][j] assign an unique number. Then take all the numbers for password at i'th location and put it as comma seperated values in the hintsFolder/ *.txt files

        /*
         * We have two groups of words, we dont want them to be checked together since we know its part of password, but
         * not sure if its upper case or lower case. "1" and "2" are exclusion groups. Only one of the variant can be part
         * of the password, never two or more segments of the same group
         * 1,F,sheep,1
         * 2,F,Sheep,1
         * 3,F,Goat,2
         * 4,F,goat,2
         * A simple conflict example, when we add "black" and we dont want black to be a part of sheep or goat (incorrect grouping example)
         * 1,F,sheep,1,3
         * 2,F,Sheep,1,3   << bad, since now because all words are in exclusion group '3', goat and sheep will never
         * 3,F,Goat,2,3    <<  come together. We want goat &sheep to be evaluated in the same password.
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

 MATRIX                sheep	Sheep	goat Goat	black Black
sheep			-	1	-	-	4	4
Sheep			1	-	-	-	4	4
goat			-	-	-	2	3	3
Goat			-	-	2	-	3	3
black			4	4	3	3	-	-
Black			4	4	3	3	-	-

Note that the matrix is symmetric across the diagnol. Also since black & Black are in together in exclusion groups 3 & 4, they wont appear together as well. You could add black & Black to a new exclusion group, say 5, but that is not required due to 3 & 4 already being assinged to black & Black.
