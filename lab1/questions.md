# Task 1:

## Question 1:

It is padded by 0's.

## Question 2:

An escape character is appended. Followed by padded zeros

## Question 3:

Bit 19, 45, 83, 109, 123.

# Task 2:

`$ cat out1.bin out21.bin > out31.bin`

`$ cat out2.bin out21.bin > out32.bin`

`$ md5sum out31.bin` => 10159c6ee635a111ddb62ca27c3748c6 out31.bin

out31.bin and out32.bin differ with same md5 hash.

# Task 3:

`$ gcc task3.c` creates a.out

The bits are stored right before "GCC".
Build from prefix (right before array).
Appended by suffix, 32 bits into array.

# Task 4: