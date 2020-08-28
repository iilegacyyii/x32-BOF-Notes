# x32-BOF-Notes
# Fuzzing

My preferred way of fuzzing, although unlikely to be the most efficient, is by using msf to generate a cyclic pattern of 2048 bytes and sending it to each possible user input. If a seg fault gets raised, then great! You've found your vulnerable input, if you have checked every input and still no seg fault? Increase the length of the cyclic pattern and try again.

Note: many functions that take an input from stdin will keep on reading until they hit either a null byte or a new line (\x00 or \x0a) so ensure to try appending this to the end of your payload if the binary seems to be hanging

## Generating Cyclic Patterns

Using metasploit:
```
msf-pattern_create -l 1024
```

Using pwntools:
```py
from pwn import *
cyclic(1024)
```
OR
```py
import pwn
pwn.cyclic(1024)
```