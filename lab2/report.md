# Lab 2 - Secret-Key Encryption

## Task 1: Frequency Analysis Against Monoalphabetic Substitution Cipher

Using text statistics and language analytics (mostly http://www.richkni.co.uk/php/crypta/freq.php) together with

```console
$ tr ’aet’ ’XGE’ < ciphertext > decrypted.txt
```

the final decrypted text was found to be an article about the Oscars.

## Task 2: Encryption using Different Ciphers and Modes

```console
$ openssl enc -aes-128-cbc -e -in plain.txt -out aes-128-cbc.bin -K 01234567890123456789 -iv 0123456789
$ openssl enc -aes-128-ecb -e -in plain.txt -out aes-128-ecb.bin -K 01234567890123456789 -iv 0123456789
$ openssl enc -aes-256-cfb -e -in plain.txt -out aes-256-cfb.bin -K 01234567890123456789 -iv 0123456789
$ openssl enc -aes-128-cbc -d -in aes-128-cbc.bin -out decryptd.txt -K 01234567890123456789 -iv 0123456789
$ cat decrypted.txt
This is some unencrypted txt.
```

The file was encrypted using three different encryption models and one of those was decrypted to test.

## Task 3: Encryption Mode – ECB vs. CBC

### Part 1: Encrypt bmp files

```console
$ head -c 54 pic_original.bmp > header
$ tail -c +55 pic_original.bmp > body
```

We now have two files, header and body. Body is the one to be encryted and appended to the original header (non-encrypted).

```console
$ openssl enc -aes-128-cbc -in body -out body-cbc -K 01234567890123456789 -iv 0123456789
$ cat header body-cbc > cbc.bmp
$ openssl enc -aes-128-ecb -in body -out body-ecb -K 01234567890123456789
$ cat header body-ecb > ecb.bmp
```

Two bitmap files exists. Their bodies are encrypted but header parts containing the bitmap info is unencrypted.

### Part 2: View the encrypted files

Using a image viewer, in this case `eog` it shows that the ECB encryption pixelates the picture and distorts colors, but the edges are clearly visible. The CBC on the other hand evenly pixelates the entire picture.

### Part 3: Repeat part 2 with custom image

When using a picture of a real life motive the ECB performs better. Probably since there are no clear edges like the example picture given. The constant varying pixels smudge the picture more evenly without the need of an -iv flag.

## Task 4: Padding

### Part 1: Encypt a file using different ciphers

```console
$ echo -n "a" > text.txt
$ openssl enc -aes-128-ecb -e -in text.txt -out ecb -K 0123456789
$ openssl enc -aes-128-cbc -e -in text.txt -out cbc -K 0123456789 -iv 0123456789
$ openssl enc -aes-128-cfb -e -in text.txt -out cfb -K 0123456789 -iv 0123456789
$ openssl enc -aes-128-ofb -e -in text.txt -out ofb -K 0123456789 -iv 0123456789
$ hexdump -C ecb
00000000  f5 9b 3a 0b e3 fe 00 5d  f1 f0 f6 a5 ca e9 20 84  |..:....]...... .|
00000010
$ hexdump -C cbc
00000000  9b 1a 72 d1 d6 37 d5 93  e2 51 d0 7e 38 44 b9 dc  |..r..7...Q.~8D..|
00000010
$ hexdump -C cfb
00000000  0a                                                |.|
00000001
$ hexdump -C ofb
00000000  0a                                                |.|
00000001
```

#### Question 1: Which modes have padding?

The ECB and CBC modes.

#### Question 2: For those that do not need paddings, explain why.

Those are what's called "stream ciphers"

### Part 2: CBC encyption with 5, 10 and 16 bytes

#### Step 1: Create 3 files, containing 5, 10, and 16 bytes respectively

```console
$ echo -n "12345" > 5bytes.txt
$ echo -n "1234567890" > 10bytes.txt
$ echo -n "1234567890123456" > 16bytes.txt
```

#### Step 2: Encrypt the files

```console
$ openssl enc -aes-128-cbc -e -in 5bytes.txt -out 5bytes-encrypted -K 0123456789 -iv 0123456789
$ openssl enc -aes-128-cbc -e -in 10bytes.txt -out 10bytes-encrypted -K 0123456789 -iv 0123456789
$ openssl enc -aes-128-cbc -e -in 16bytes.txt -out 16bytes-encrypted -K 0123456789 -iv 0123456789
```

#### Step 3: Analyze the files

```console
$ hexdump -C 5bytes-encrypted
00000000  ab 90 7c 15 e8 53 b3 72  13 8a 67 0e e2 24 ff 96  |..|..S.r..g..$..|
00000010
$ hexdump -C 10bytes-encrypted
00000000  a4 fc a0 d0 12 59 a8 c9  ce 2f 9c a5 4b 9a 57 14  |.....Y.../..K.W.|
00000010
$ hexdump -C 16bytes-encrypted
00000000  e7 dd 95 7c a2 fd 8c 69  4b 91 51 fe db aa e5 ad  |...|...iK.Q.....|
00000010  f6 ae e3 22 99 0d 2c 8a  22 b1 90 f2 89 f4 4c 25  |..."..,.".....L%|
00000020
```

The output above shows that the CBC encryption is padding in blocks of 16 bytes. Once the data reaces a multiple of 16 bytes, 16 more bytes are padded.

#### Step 4: Decrypt the encryption, keeping padded data

```console
$ openssl enc -aes-128-cbc -d -nopad -in 5bytes-encrypted -out 5bytes-decrypted.txt -K 0123456789 -iv 0123456789
$ hexdump -C 5bytes-decrypted.txt
00000000  31 32 33 34 35 0a 0a 0a  0a 0a 0a 0a 0a 0a 0a 0a  |12345...........|
00000010
```

The appended padding consists of 0x0a (escape characters).

## Task 5: Error Propagation - Corrupted Cipher Text

### Question: How much data can you recover by decrypting a corrupted file (byte #55) using ECB, CBC, CFB, OFB?

ECB: The current block of 16 bytes would be unrecoverable.

CBC: The current block of 16 bytes would be unrecoverable. Also the 16th byte after the corrupted byte.

CFB: The corrupted byte will be unrecoverable. And also the entire next 16 byte block.

OFB: Only the corrupted byte would be unrecoverable.

### Verifying

The text file will be encypted and decrypted the same way as above steps. In between those steps a binary editor (bless) will be used to corrupt the 55th byte.
`

```console
$ hexdump -C text.txt | head
00000000  0a 72 65 6d 20 69 70 73  75 6d 20 64 6f 6c 6f 72  |.rem ipsum dolor|
00000010  20 73 69 74 20 61 6d 65  74 2c 20 63 6f 6e 73 65  | sit amet, conse|
00000020  63 74 65 74 75 65 72 20  61 64 69 70 69 73 63 69  |ctetuer adipisci|
00000030  6e 67 20 65 6c 69 74 2e  20 41 65 6e 65 61 6e 20  |ng elit. Aenean |
00000040  63 6f 6d 6d 6f 64 6f 20  6c 69 67 75 6c 61 20 65  |commodo ligula e|
[…]
$ hexdump -C ecb_decrypted.txt | head
00000000  0a 72 65 6d 20 69 70 73  75 6d 20 64 6f 6c 6f 72  |.rem ipsum dolor|
00000010  20 73 69 74 20 61 6d 65  74 2c 20 63 6f 6e 73 65  | sit amet, conse|
00000020  63 74 65 74 75 65 72 20  61 64 69 70 69 73 63 69  |ctetuer adipisci|
00000030  6f e9 cd 2d a5 1e 65 d1  c9 fc 77 2b 1a 39 bb 8f  |o..-..e...w+.9..|
00000040  63 6f 6d 6d 6f 64 6f 20  6c 69 67 75 6c 61 20 65  |commodo ligula e|
[…]
$ hexdump -C cbc_decrypted.txt | head
00000000  0a 72 65 6d 20 69 70 73  75 6d 20 64 6f 6c 6f 72  |.rem ipsum dolor|
00000010  20 73 69 74 20 61 6d 65  74 2c 20 63 6f 6e 73 65  | sit amet, conse|
00000020  63 74 65 74 75 65 72 20  61 64 69 70 69 73 63 69  |ctetuer adipisci|
00000030  16 b6 eb 59 52 f9 b6 21  94 1d 3c a3 ff 82 98 58  |...YR..!..<....X|
00000040  63 6f 6d 6d 6f 64 be 20  6c 69 67 75 6c 61 20 65  |commod. ligula e|
[…]
$ hexdump -C cfb_decrypted.txt | head
00000000  0a 72 65 6d 20 69 70 73  75 6d 20 64 6f 6c 6f 72  |.rem ipsum dolor|
00000010  20 73 69 74 20 61 6d 65  74 2c 20 63 6f 6e 73 65  | sit amet, conse|
00000020  63 74 65 74 75 65 72 20  61 64 69 70 69 73 63 69  |ctetuer adipisci|
00000030  6e 67 20 65 6c 69 cf 2e  20 41 65 6e 65 61 6e 20  |ng eli.. Aenean |
00000040  7d 04 cd ea 95 62 15 54  d8 84 f0 5f 8e b1 ad 5e  |}....b.T..._...^|
00000050  67 65 74 20 64 6f 6c 6f  72 2e 20 41 65 6e 65 61  |get dolor. Aenea|
[…]
$ hexdump -C ofb_decrypted.txt | head
00000000  0a 72 65 6d 20 69 70 73  75 6d 20 64 6f 6c 6f 72  |.rem ipsum dolor|
00000010  20 73 69 74 20 61 6d 65  74 2c 20 63 6f 6e 73 65  | sit amet, conse|
00000020  63 74 65 74 75 65 72 20  61 64 69 70 69 73 63 69  |ctetuer adipisci|
00000030  6e 67 20 65 6c 69 38 2e  20 41 65 6e 65 61 6e 20  |ng eli8. Aenean |
00000040  63 6f 6d 6d 6f 64 6f 20  6c 69 67 75 6c 61 20 65  |commodo ligula e|
[…]
```

## Task 6: Initial Vector (IV)

### Part 6.1: Reuse IV

```console
$ openssl enc -aes-128-cbc -e -in text.txt -out encrypted-same-iv-1 -K 0123456789 -iv 0123456789
$ openssl enc -aes-128-cbc -e -in text.txt -out encrypted-same-iv-2 -K 0123456789 -iv 0123456789
$ openssl enc -aes-128-cbc -e -in text.txt -out encrypted-new-iv -K 0123456789 -iv 9876543210
```

### Question: Describe the observation and explain why IV needs to be unique

The same Key and IV creates the very same encryption. Based on what we know from earlier tasks this means the same text strings will generate the same output, giving the potential to once again perform i.e. frequency analysis and such. A new IV scrambles the output encryption.

### Task 6.2: Reverse OFB encryption

    Plaintext  (P1): This is a known message!
    Ciphertext (C1): a469b1c502c1cab966965e50425438e1bb1b5f9037a4c159
    Plaintext  (P2): (unknown to you)
    Ciphertext (C2): bf73bcd3509299d566c35b5d450337e1bb175f903fafc159

We can see the messages are the same length and some parts of the message are identical
--------a------ m-ss--e!

### Question: If the encryption was performed using CFB?

Once any byte in a 16-byte block is changed, the upcoming blocks are scrambled again. But this can still be used to find messages that begins the same way.

### Task 6.3:

We know the actual value of C1 is "Yes" or "No". So we start assuming the affirmative option.

```console
$ echo Yes > P2.txt
$ hexdump -p P2.txt
00000000  59 65 73 0a                                       |Yes.|
00000004
```
The message needs to be padded with a hex editor or similar.

```console
$ hexdump -C P2 
00000000  59 65 73 0d 0d 0d 0d 0d  0d 0d 0d 0d 0d 0d 0d 0d  |Yes.............|
00000010
```

We then XOR the hex value with both the last known IV and the next to be used. In this case, an online editor was used and a file was created containing the result. After that the file is sent to Bob to do the actually encryption and we can see the resulting C2 is the same as the unknown C1.

```console
$ echo -n "5965730d0d0d0d0d0d0d0d0d0d0d0d0c" | xxd -r -p > P2-xor
$ openssl enc -aes-128-cbc -e -in P2-xor -out C2 -K 00112233445566778899aabbccddeeff -iv 31323334353637383930313233343537 -nopad
hexdump -C C2 
00000000  be f6 55 65 57 2c ce e2  a9 f9 55 31 54 ed 94 98  |..UeW,....U1T...|
00000010
```

