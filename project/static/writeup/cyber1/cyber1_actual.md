# Euan's Cyber1 Write-up

This is a write-up of the 1st challenge that has been tasked for 2021 Warwick applicants. This is my intended solution for the challenge. The flag is located in the `lastpass_pwd.txt` file which we eventually find.

At the end, there is a TL;DR to recap of the steps taken and the techniques learnt / used.

### Warning
This is quite a long write-up, sorry!

## Let the write-up begin!
>  Our forensics team back in the lab have managed to receive some malware, and upon analysis have found this file. Can you have a look and see if you can pull anything from it? (Just to note, this isn't malware, that's a fictional story behind this file).

> Category: Misc

So, the name of the challenge, nor the description doesn't help us too much, apart from telling us that we're not downloading malware (thankfully). So, let's do some enumeration.

```bash
euan@euanb26  cyber1  file challenge.jpg
challenge.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=2, datetime=2020:11:01 13:59:43], baseline, precision 8, 300x300, components 3
```
So the header tells us that it's a jpeg, which lines up with the extension provided. Everything else seems to be normal. Let's open it and see what we find.

![QR code](../../challenges/cyber1/challenge.jpg)

So we get a QR code ... let's follow it. Using [Zxing](https://zxing.org/w/decode), we get a URI out of it ... `https://www.youtube.com/watch?v=dQw4w9WgXcQ`. I wonder where this leads us ...
![Rick roll](../../images/rick_roll.png)

Ah yes, the good old rick roll. Well done, well done.

So that's told us that we're probably not going to want to just analyse the qr code as is, we've got to look deeper.

So what does "deeper" look like?
- Steganography
  - File carving
  - Extracting info from the raw data, such as strings
  - Looking at the metadata
- Manipulating the hex bytes to gain a flag
- Hex data might have been labelled incorrectly, ie. some binary has replace hex

The file loads up perfectly fine, so I feel like it's not going to be the last point, as usually that would provide an error, such as "can't open the file, something is wrong with the hex". SO we've got options 1 and 2 to take a look at. I'm going to start with the steg portion, because we open up a can of worms here with multiple different paths.

Let's take a look at the strings and see what we can find:
```bash
euan@euanb26  cyber1  strings challenge.jpg
JFIF
Exif
2020:11:01 13:59:43
JFIF
...
<?xpacket begin="
" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="XMP Core 6.0.0">
   <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
      <rdf:Description rdf:about=""
            xmlns:dc="http://purl.org/dc/elements/1.1/">
         <dc:description>Did I forget to pwd protect the files ... uhhhhhh</dc:description>
      </rdf:Description>
   </rdf:RDF>
</x:xmpmeta>
...
1Did I forget to pwd protect the files ... uhhhhhh
...
lastpass_pwd.txtUT
Putting this here so that I don\'t forget
euan:$1$6fb42da0e32e07b61c9f0251fe627a9c:1001:1001:::/bin/bash
...
```
Wow, so that's gained some interesting features. SO reading those XML tags, we have some additional metadata, and we also have what seems to be a file labelled `lastpass_pwd.txtUT`. We also have a description: `Did I forget to pwd protect the files ... uhhhhhhh`. We also gain a hash as well. Interesting .... Let's take a look at the metadata to see if there's any more useful things.
```bash
 euan@euanb26  cyber1  exiftool challenge.jpg
 ...
 Description                     : Did I forget to pwd protect the files ... uhhhhhh
 ...
```
Nope, nothing else useful there. So, we know that there's a file called `lastpass_pwd.txt`, so let's try and extract that.
```bash
euan@euanb26  cyber1  binwalk -e challenge.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
30            0x1E            TIFF image data, little-endian offset of first image directory: 8
136           0x88            JPEG image data, JFIF standard 1.01

euan@euanb26  cyber1  ls
challenge.jpg  _challenge.jpg.extracted
euan@euanb26  cyber1  ls -aRl
.:
total 44
drwxrwxr-x 3 euan euan  4096 Nov  1 16:29 .
drwxrwxr-x 5 euan euan  4096 Oct 29 21:55 ..
-rw-rw-r-- 1 euan euan 32717 Nov  1 15:45 challenge.jpg
drwxrwxr-x 2 euan euan  4096 Nov  1 16:29 _challenge.jpg.extracted

./_challenge.jpg.extracted:
total 12
drwxrwxr-x 2 euan euan 4096 Nov  1 16:29 .
drwxrwxr-x 3 euan euan 4096 Nov  1 16:29 ..
-rw-rw-r-- 1 euan euan 1396 Nov  1 16:29 7A59.zip
euan@euanb26  cyber1  cd _challenge.jpg.extracted
euan@euanb26  _challenge.jpg.extracted  unzip 7A59.zip
Archive:  7A59.zip
[7A59.zip] lastpass_pwd.txt password:
```
Ah, a password protected zip file, great. Could we just trial some common passwords and hope that that's it?
```bash
euan@euanb26  _challenge.jpg.extracted  unzip 7A59.zip
Archive:  7A59.zip
[7A59.zip] lastpass_pwd.txt password: [blank]
  skipping: lastpass_pwd.txt        incorrect password
✘ euan@euanb26  _challenge.jpg.extracted  unzip 7A59.zip
Archive:  7A59.zip
[7A59.zip] lastpass_pwd.txt password: [password]
password incorrect--reenter: [PASSWORD]
password incorrect--reenter: [iloveyou]
  skipping: lastpass_pwd.txt        incorrect password
```
Unfortunately a couple of common passwords aren't going to work. However, it seems as though we've found that `lastpass_pwd.txt` that the strings showed us. Let's see if the hash we were given can be used for breaking in.

The format of the string including the hash seems very similar to `/etc/passwd` in a linux system:
```bash
euan:x:1000:1000:Euan,,,:/home/euan:/bin/bash
```
Where the `x` shows that the password is in `/etc/shadow`.

We can notice that it's a md5 hash because of the `$1$` prepended at the front of the hash, so let's chuck it at hashcat to try and crack the hash:

```bash
euan@euanb26  cyber1  nano hash.txt
euan@euanb26  cyber1  cat hash.txt
6fb42da0e32e07b61c9f0251fe627a9c
# Hashcat -m 0 (mode = md5) -a 0 (dictionary attack) -o cracked.txt (output file)
euan@euanb26  cyber1  hashcat -m 0 -a 0 -o cracked.txt hash.txt ~/wordlists/rockyou.txt --force
hashcat (v5.1.0) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: [Some specs of the device]

INFO: All hashes found in potfile! Use --show to display them.

Started: Sun Nov  1 17:52:49 2020
Stopped: Sun Nov  1 17:52:51 2020
euan@euanb26  cyber1  ls    
challenge.jpg  hash.txt
euan@euanb26  cyber1  hashcat --show hash.txt
6fb42da0e32e07b61c9f0251fe627a9c:0987654321
```
Bingo, hashcat found the password to be `0987654321`. So let's try opening that zip again:

```bash
euan@euanb26  cyber1  unzip _challenge.jpg.extracted/7A59.zip
Archive:  _challenge.jpg.extracted/7A59.zip
warning [_challenge.jpg.extracted/7A59.zip]:  1501 extra bytes at beginning or within zipfile
 (attempting to process anyway)
[_challenge.jpg.extracted/7A59.zip] lastpass_pwd.txt password:
 inflating: lastpass_pwd.txt        
✘ euan@euanb26  cyber1  ls -alR
.:
total 56
drwxrwxr-x 3 euan euan  4096 Nov  1 17:56 .
drwxrwxr-x 5 euan euan  4096 Oct 29 21:55 ..
-rw-rw-r-- 1 euan euan 34218 Nov  1 17:47 challenge.jpg
drwxrwxr-x 2 euan euan  4096 Nov  1 17:55 _challenge.jpg.extracted
-rw-rw-r-- 1 euan euan    33 Nov  1 17:52 hash.txt
-rw-rw-r-- 1 euan euan  2300 Nov  1 13:56 lastpass_pwd.txt

./_challenge.jpg.extracted:
total 12
drwxrwxr-x 2 euan euan 4096 Nov  1 17:55 .
drwxrwxr-x 3 euan euan 4096 Nov  1 17:56 ..
-rw-rw-r-- 1 euan euan 2897 Nov  1 17:55 7A59.zip
euan@euanb26  cyber1  cat lastpass_pwd.txt
Data Dump from LastPass

HackTheBox (Joined August 2018)
-> URI to profile: https://www.hackthebox.eu/home/users/profile/58042
-> username: EuanB26
-> password: NYas}@ba{5YH8gr

Gitbook:
-> URI: https://euanb26.gitbook.io
-> username: euanb26
-> password: my_Typ3_c0nfus10n_w1ll_BOF_f0r_y0ur_h3ap_f3ng_shui

Github:
-> URI: https://github.com/EuanB26
-> username: euanb26
-> password: g1thub_g1tb00k_g1tl4b_wh1ch_0n3?>:(@~

Cyber Discovery (2017, 2018, 2019, 2020, 2021)
-> URI: https://joincyberdiscovery.com/
-> username: euanb26
-> password: n00b1ng_my_w4y_up

  Tomahawque (Elite 2019)
  -> URI: https://www.tomahawque.com/profile/EuanB26
  -> username: EuanB26
  -> password: d0_w3_r3_u53_z3_p4$$w0rd?

  SANS (Elite 2020 - 98% on CD game, woooooo)
  -> URI (showcasing GCIH): https://www.youracclaim.com/badges/3e559d21-1582-43ec-a46e-dfeb5ef4f5be/public_url
  -> Login URI: https://www.sans.org/
  -> username: euanb
  -> password: yh_7h15_0n3_5h0uld_b3_pr377y_$3cuR3_43943284893024¬\"£$£\"$

CyberFirst Advanced
-> URI: https://www.smallpeicetrust.org.uk/cyberfirst-advanced
-> username: euanb26
-> password: d0nt_f34r_3u4n_is_here!!!!><?

CTFtime
  Personal account
  -> URI: https://ctftime.org/user/72108
  -> username: EuanB26 (Using capitals, whoop)
  -> password: ctf_4r3_4w3s0me_43243243576576

  The WinRaRs (co founded)
  -> URI: https://ctftime.org/team/113086
  -> username: The_WinRaRs
  -> password: screw_you_Crown_yes_plain_text_for_our_message_:)

hackerOne
-> URI: https://hackerone.com/euanb26?type=user
-> username: euanb26
-> password: -g]{u4B}3j&9Z\`Vu

School
-> URI: Do we really need one?
-> username: 14euanB
-> password: "' OR '1'='1"
(Hehe, testing security as we go)

Nationwide work experience with the Pentesting team
-> URI: https://www.nationwide.co.uk/
-> username: euanB
-> password: 6<VbUur*Wn2E\"(y?

Warwick 2019 open day + 2020 virtual
-> URI: https://warwick.ac.uk

Google podcasts (Darknet Diaries, The Social Engineering Podcast, Open Source Security Podcast, Unnamed RE, Kona Edge, Triathlon Taren, Hackable?..)
-> URI: https://podcasts.google.com/
-> username: EuanB26@gmail.com
-> password: g00gl3_15_4lw4y5_w4tch1ng_m0v3_t\()_duck_duck_g0_0r_pr0t0nM41l_:)

flag
-> URI: https://hehe.welldone.com/
-> username: flagity_flag
-> password: flag{D0nt_d4t4_dump_4nd_m0ve}
```
And boom, down at the bottom there we have our flag.
In addition to all that, go and check out the links that I've provided :)

Sorry to burst your bubble, by these aren't actually my passwords :)

## TL;DR
1. Check file header
2. Open up image, follow QR code, see that we shouldn't be there
3. Run `strings` shows a hash inside the file as well as a zip file
4. `$1$` tells us that it's an md5 hash, crackable against rockyou.txt
5. Use password gained to access password protected zip file
