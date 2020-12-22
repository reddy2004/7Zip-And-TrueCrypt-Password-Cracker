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