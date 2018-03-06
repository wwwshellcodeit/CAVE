# CAVE
Cerberus - AV Evasion Project

![alt text](https://raw.githubusercontent.com/wwwshellcodeit/CAVE/master/logo.png)

What is CAVE?
----
Cerberus AV Evasion aka CAVE, is a Windows Shellcode Generator that aims to help Penetration Testers during their day to day job.

Dependencies
----
On Kali 2018 64bit, in order to compile Assembly code for Windows, you need:

1º - edit /etc/apt/sources.list

2º - comment (#) default repositories

3º - add the follow repositorie to your source.list


deb http://old.kali.org/kali sana main non-free contrib

deb-src http://old.kali.org/kali sana main non-free contrib

4º - save source.list file

5º - apt-get update

6º - apt-get install mingw32
