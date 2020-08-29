# Fuzzing

My preferred way of fuzzing, although unlikely to be the most efficient, is by using msf to generate a cyclic pattern of 2048 bytes and sending it to each possible user input. If a seg fault gets raised, then great! You've found your vulnerable input, if you have checked every input and still no seg fault? Increase the length of the cyclic pattern and try again.

Note: *If the binary seems to be hanging, remember that many functions that take an input from stdin will keep on reading until they hit either a null byte or a new line (\x00 or \x0a) so try appending this to the end of your payload*

Once you have found the vulnerable input, you can use a debugger to check which chunk of the pattern has overwrote the EIP. You can then search your cyclic pattern to find the size of the offset (a.k.a padding) that will be required in your exploit.

## Generating Cyclic Patterns

**Using metasploit**
```bash
msf-pattern_create -l 1024
```

**Using pwntools**  
The first method here is preferred as you can also search the pattern
```py
import pwn
pattern = pwn.cyclic_gen()
pattern.get(1024)
```
OR
```py
import pwn
pwn.cyclic(1024)
```

**Using vanilla python**
```py
def gen_pattern(length=64):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    pattern = "aaaa"
    while len(pattern) < length:
        lchars = pattern[len(pattern) - 4:][0] + pattern[len(pattern) - 4:][1] + pattern[len(pattern) - 4:][2] + pattern[len(pattern) - 4:][3]
        if lchars[0] == "9":
            print("Maximum pattern length reached!")
            break
        elif lchars[1] == "9":
            pattern += chars[chars.find(lchars[0]) + 1] + "a99"
            continue
        elif lchars[2] == "9":
            pattern += "a" + chars[chars.find(lchars[1]) + 1] + "a9"
            continue
        elif lchars[3] == "9":
            pattern += "aa" + chars[chars.find(lchars[2]) + 1] + "a"
            continue
        else:
            pattern += lchars[0] + lchars[1] + lchars[2] + chars[chars.find(lchars[3]) + 1]
    return pattern[:length]
```

## Finding the Offset
If using metasploit or pwntools you can enter either the raw hex value stored in EIP or the ASCII equivilent e.g. 0x616d6261 or "amba"

**Using metasploit**
```bash
msf-pattern_find -q ValueInEIP
```

**Using pwntools**
```py
import pwn
pattern = pwn.cyclic_gen()
pattern.find(ValueInEIP)
```

**Using vanilla python**
```py
# pattern is a string containing the cyclic pattern,
# unique must be in ASCII format.
unique = input("Enter the value stored in EIP: ")

if unique in pattern:
	offset = len(pattern.split(unique)[0])
	print("Your offset is {}, meaning your EIP value is located at character {} and onwards.".format(offset, offset+1))
else:
	print("EIP value not found in cyclic pattern...")
```

**Using mona with Immunity Debugger**
Once you've got a segfault using your pattern, you can use the following command:
```bash
!mona findmsp
```
