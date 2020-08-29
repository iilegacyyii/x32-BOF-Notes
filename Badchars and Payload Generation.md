# Bad Characters
One of the most crucial steps when working on buffer overflows is checking for bad characters.  
Bad characters are characters that the binary will treat differently to others, and can either change the functionality or even completely truncate your payload, rendering it useless.
The most common are 0x00 and 0x0a, (null byte and newline), this is because many buffer overflows rely on input from stdin and most c functions that take input from stdin use either 0x00 or 0x0a to detect the end of an input.
However each binary will have it's own for you to discover.

The easiest way to check for bad characters is sending every character to the application and using a debugger such as Immunity Debugger to check for changes to the sent payload in memory. The first step of course is to generate

**Generating all characters**
```py
# Generate pattern for badchar detection.
badchar_test = ""
badchars = [0x00, 0x0A]	# Definite bad chars

for i in range(0x00, 0xFF + 1):	# range(0x00, 0xFF) only returns up to 0xFE
	if i not in badchars:
		badchar_test += chr(i)
```

**Using mona within Immunity Debugger**
Assuming that your payload is located at the location pointed to by esp
```
!mona compare -a esp -f c:\badchar_test.bin
```
When the window pops up, status unmodified means that there are no more bad characters for you to remove.

**Doing it manually**
PLACEHOLDER TEXT


