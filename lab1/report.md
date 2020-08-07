# Lab 1 - MD5 Collision Attack

## Task 1: Generating Two Different Files with the Same MD5 Hash

### Steps

#### 1.1: Prefix text file

First, a text file named prefix.txt is created. Both the name and content can be whatever, but in this case the text "This is a prefix text file" was chosen.

#### 1.2: Collision generator

`$ md5collgen -p prefix.txt -o out1.bin out2.bin`

This uses the text file from 1.1 and creates two different binary files, out1.bin and out2.bin. The content in these files should differ, but the MD5 hash should be the same.

#### 1.3: Verification

```console
$ diff out1.bin out2.bin
Binary files out1.bin and out2.bin differ
$ md5sum out1.bin
a178e2b63c21a38943793337918291f1  out1.bin
$ md5sum out2.bin
a178e2b63c21a38943793337918291f1  out2.bin
```

The files differ, but the MD5 hash is the same.

### Questions

#### Question 1

The prefix is padded by 0's until reach multiple of 64 bytes.

#### Question 2

The prefix is appended by 64 new zero-bytes. My guess is that an escape character is appended followed by padded zeros until multiple of 64 bytes.

#### Question 3

Not completly. It is actually hard to find the diffing bits since only five of them differs. Them being byte number 19, 45, 83, 109, 123.

## Task 2: Understanding MD5´s Property

### Steps

#### 2.1 Generating first part binary

Generally, any even 64 multiple bytes binary could be used. We can use md5collgen from Task 1 to make sure it works correctly, but only one file is neccessary. We call the file we save suffix1.bin.

#### 2.2 Make a collision

A new collision is made. This time both files will be neccessary. We call those prefix1.bin and prefix2.bin.

#### 2.3 Merge

```console
$ cat prefix1.bin suffix1.bin > merged1.bin
$ cat prefix2.bin suffix1.bin > merged2.bin
$ diff merged1.out merged2.out
Binary files merged1.bin and merged2.bin differ
$ md5sum merged1.out
fb1ca29892882c455109070576d69eb8  merged1.bin
$ md5sum merged2.out
fb1ca29892882c455109070576d69eb8  merged2.bin
```

## Task 3: Generating Two Executable Files with the Same MD5 Hash

### Steps

#### 3.1: Original C-program

We start with the given C-program and create the original 200 char array using only the char 'A'.

```c++
#include <stdio.h>

unsigned char xyz[200] = {
    /* The actual contents of this array are up to you */
    'A', 'A', […], 'A', 'A'
};

int main() {
    int i ;
    for (i=0; i<200; i++) {
        printf("%x", xyz[i]);
    }
    printf("\n");
}
```

```console
$ gcc task3.c
```

Creates an executable file called a.out that, when it runs, outputs '41' 200 times.

#### 3.2 Cut program into parts.

Using a hex editor, we can find the huge array of 'A's. The bits are stored right before "GCC". In the middle of that array we can find a 128-byte region to essentially cut out, creating 3 parts. In this case 32 butes into the array.

We cut the 128 byte part since we know that is how much out md5collgen appends, but in theory any multiple length of 64 should work.

This leaves us with two parts, prefix and suffix.

#### 3.3 Collision generation

```console
$ md5collgen -p prefix -o coll1 coll2
```

By using md5collgen we "paste" back the removed 128 byte part. We get two files named coll1 and coll 2.

#### 3.4 Append the suffix

```console
$ cat coll1 suffix > file1.out
$ cat coll2 suffix > file2.out
```

#### 3.5 Make the files executable

```console
$ chmod +x file1.out file2.out
```

We must tell the computer that the new files are executable.

#### 3.6 Verification

```console
$ diff file1.out file2.out
Binary files file1.out and file2.out differ
$ md5sum file1.out
58ad985924fc9643a8599c376badcad4  file1.out
$ md5sum file2.out
58ad985924fc9643a8599c376badcad4  file2.out
$ ./file1.out
4ec62bea80e9a34968f46209fd6aebe8f83d6686e292bae7f2594a431f7513c15dc5da836ef14e329b31931a52db9d989391e58c081757fc3ced493ea32796c26e48b76d17d53f69211f42c3e341074a156c55715c5cd61593289679fd6699bae949b71d08f33666366bbf9da8316c5b284ed31050b26a358414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
$ ./file2.out
4ec62bea80e9a34968f46209fd6aebe8f3d6686e292bae7f2594a431f7513c15dc5da836ef14e329bb1931a52db9d989391e58c08175ffc3ced493ea32796c26e48b76d17d53f69211f42c3eb41074a156c55715c5cd61593289679fd6699bae949b71d08f33e66266bbf9da8316c5b284ed310d0b26a358414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
```

The files differ and outputs different outputs, but the MD5 hash is the same.

## Task 4: Making the two Programs Behave Differently

### Tasks 4.1: The base program

```c
#include <stdio.h>

unsigned char data1[128] = {
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'
    };

unsigned char data2[128] = {
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'
    };

int main() {
    int equals = 1;
    int i;
    for (i = 0; i < 32; i++) {
        if (data1[i] != data2[i]) {
            equals = 0;
        }
    }
    if (equals) {
        printf("Running some benign code\n");
    } else {
        printf("Deleting your hard drive\n");
    }
}
```

```console
$ gcc program.c
$ ./a.out
Running som benign code
```

#### Task 4.2: Cut into parts.

Since both 128-byte arrays is stored next to each other in the source code it creates a 256 byte block of 'A's beginning at offset 0x1040. This can be found using a hex editor like Bless for instance.

This is an even multiple of 64, so we can use this to locate the byte where we should cut the prefix (to byte 4160) and suffix (from byte 4289 (4160+128+1)).

```console
$ head -c 4160 a.out > prefix
$ tail -c +4289 a.out > suffix
```

Now we have a prefix and a suffix. In between those we need to store two 128-byte arrays. In the good program those should equal, and in the bad program those should differ. However, the MD5 needs to be the same.

```console
$ md5collgen -p prefix -o good1 bad1
```

This creates two new files from the prefix and appends 128 bytes with different content, but the same MD5.

```console
$ tail -c 128 good1 > goodArray
```

This copies the last 128 bytes from the benign program, i.e. the good array. If this is appended to the benign program the benign code should be executed (together with the "suffix" part), if it is appended to the malign program the malign code should be executed. Since the bytes are identical, the MD5 should also be identical.

```console
$ cat good1 goodArray suffix > goodProgram.out
$ cat bad1 goodArray suffix > badProgram.out
$ diff goodProgram.out badProgram.out
Binary files goodProgram.out and badProgram.out differ
$ md5sum goodProgram.out
66327a61501416a3b71a53972099651a  goodProgram.out
$ md5sum badProgram.out
66327a61501416a3b71a53972099651a  badProgram.out
```

The MD5 are the same, but the content differ. Now it is time to see if the programs are actually executing.

```console
$ chmod +x goodProgram.out badProgram.out
$ ./goodProgram.out
Running some benign code
$ ./badProgram.out
Deleting your hard drive
```

Same MD5, different code execution.
