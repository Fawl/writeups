# Runtime Environment 1

```
Author: rootkid

GO and try to solve this basic challenge.

FAQ: If you found the input leading to the challenge.txt you are on the right track
```

## Attack of the Gopher

From the challenge description, and the name of the downloadable tarball `gogogo.tar.gz`, it's pretty apparent that this is a Go binary.
In my previous experience with Go-based challenges, oftentimes the greatest difficulty is in finding the `main` function. Luckily, running the `file` command assuages my worries.

```bash
❯ file binary
binary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=OHBJFJh5S4MEkda8Q683/cMydJq6y9QbVjBCjK1KP/8R1f9ddSl9EfpM8KP2Dy/3G9-Ju3BW7WUsgoGNyvl, not stripped
```

So, it's not stripped. What does it do, then?

Running the binary just gives a prompt. Entering a string and hitting enter spits out an output that looks suspiciously like base64.
We can test this hypothesis by checking the output of the binary if we vary the input string slightly:

```bash
❯ ./binary
aaaabaaacaaadaaa
CGTxCGmxCGT2CGTx+1TxCV--
❯ ./binary
aaaabaaacaaadaa
CGTxCGmxCGT2CGTx+1Tx
```

We were also provided with a `challenge.txt`, containing the following textual data: `GvVf+fHWz1tlOkHXUk3kz3bqh4UcFFwgDJmUDWxdDTTGzklgIJ+fXfHUh739+BUEbrmMzGoQOyDIFIz4GvTw+j--`.
We can assume that the correct input to the binary would produce the corresponding output to the contents of `challenge.txt`.

## Going Deeper

With the help of the included debug symbols, finding the `main` function is trivial.
Here's a snippet of the decompiled `main` function, retaining the important lines.

```c
void __cdecl main_main()
{
  __int64 v0; // [rsp+10h] [rbp-98h]
  __int64 input_ptr; // [rsp+18h] [rbp-90h]
  __int64 in_len; // [rsp+48h] [rbp-60h]
  __int64 out_buf; // [rsp+70h] [rbp-38h]
  // * snip *

  v4 = fmt_Fscanln((__int64)&go_itab__ptr_os_File_comma_io_Reader, os_Stdin, (__int64)v13, 1LL, 1LL); // reading input
  in_len = 4
         * (((__int64)(((unsigned __int128)((v11[1] + 2) * (__int128)(__int64)0xAAAAAAAAAAAAAAABLL) >> 64) + v11[1] + 2) >> 1)
          - ((v11[1] + 2) >> 63));
  out_buf = runtime_makeslice((__int64)&RTYPE_uint8, in_len, in_len);
  input_ptr = runtime_stringtoslicebyte((__int64)v9, *v11, v11[1]); // conversion to bytes
  v5 = main_Encode(out_buf, in_len, in_len, input_ptr, v2, v4); // passing input to encode function
  v3 = runtime_slicebytetostring(0LL, v5, v6, v7);
  v0 = runtime_convTstring(v3, *((__int64 *)&v3 + 1));
  // * snip * 
  fmt_Fprintln((__int64)&go_itab__ptr_os_File_comma_io_Writer, os_Stdout, (__int64)v12, 1LL, 1LL); // printing output
}
```

The `main` function doesn't do much beyond reading in the user's output, converting it to bytes and calling the `main.Encode` subfunction.
The output of `main.Encode` is then printed to console. This is in line with the expected behaviour given our prior black-box testing.

Here's a snippet of `main.Encode` with Go-inserted error-handling snipped for easier reading:

```c
qmemcpy(enc_string, "NaRvJT1B/m6AOXL9VDFIbUGkC+sSnzh5jxQ273d4lHPg0wcEpYqruWyfZoM8itKe", sizeof(enc_string));
  str_index = 0LL;
  out_index = 0LL;
  while ( (__int64)str_index < 3 * ((__int64)len_input / 3) )
  {
    // * snip *
    temp_hash = ((unsigned __int64)*(unsigned __int8 *)(input_ptr + str_index) << 16) | ((unsigned __int64)*(unsigned __int8 *)(input_ptr + str_index + 1) << 8) | *(unsigned __int8 *)(str_index + input_ptr + 2);
    // * snip *
    *(_BYTE *)(out_buf + out_index) = *((_BYTE *)enc_string + ((temp_hash >> 18) & 63));
    temp_hash_1 = temp_hash;
    v9 = *((_BYTE *)enc_string + ((temp_hash >> 12) & 0x3F));
    // * snip *
    *(_BYTE *)(out_index + out_buf + 1) = v9;
    temp_hash_2 = temp_hash_1;
    v11 = *((_BYTE *)enc_string + ((temp_hash_1 >> 6) & 0x3F));
    // * snip *
    *(_BYTE *)(out_index + out_buf + 2) = v11;
    v12 = *((_BYTE *)enc_string + (temp_hash_2 & 0x3F));
    // * snip *
    *(_BYTE *)(out_buf + out_index + 3) = v12;
    str_index += 3LL;
    out_index += 4LL;
```

In an attempt to understand this algorithm better, I converted it to Python, a language I'm more comfortable with.
I've annotated portions of the translated code that I found interesting and indicative that my base64 hypothesis was right.

```python
ENC_STRING = "NaRvJT1B/m6AOXL9VDFIbUGkC+sSnzh5jxQ273d4lHPg0wcEpYqruWyfZoM8itKe"
str_index = 0
out_index = 0

while str_index < 3 * (len_input // 3): 
'''
You can observe input is split up into groups of 3 characters each.
Output of 4 characters is generated.
'''
    temp_1 = ord(in_str[str_index]) << 16 | ord(in_str[str_index + 1]) << 8 | ord(in_str[str_index + 2])

    out_str += ENC_STRING[temp_1 >> 18 & 0x3F]
    out_str += ENC_STRING[temp_1 >> 12 & 0x3F]
    out_str += ENC_STRING[temp_1 >> 6 & 0x3F]
    out_str += ENC_STRING[temp_1 & 0x3F]

    str_index += 3
    out_index += 4

temp_2 = len_input - str_index

if temp_2 == 2:
    temp_3 = ord(in_str[str_index]) << 16 | ord(in_str[str_index + 1]) << 8
else:
    temp_3 = ord(in_str[str_index]) << 16

out_str += ENC_STRING[temp_3 >> 18 & 0x3F]
out_str += ENC_STRING[temp_3 >> 12 & 0x3F]

'''
Padding of the "-"s at the end of the string is done here
'''
if temp_2 == 1:
    out_str += chr(0x45)
    out_str += chr(0x45)
elif temp_2 == 2:
    out_str += ENC_STRING[temp_3 >> 6 & 0x3F]
    out_str += chr(0x45)
```

Curiously enough, while I was doing translation, GitHub Copilot was doing an excellent job of filling in the next lines of code I would write.
Along with the behaviour I observed while translating the code, this further confirmed my base64 hypothesis.
A quick Google search put any remaining doubt to rest.

[hehe](./images/runtime_env_1_1.png)

Reversing the base64 encryption is easy with the help of Python's `base64` module.
This can be accomplished in a few steps:

1. Extract the custom base64 alphabet from our binary
2. Make a string translation mapping the encrypted base64 string to the default base64 alphabet.
3. Profit?

```python
import base64

INFILE = "challenge.txt"
STD_B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
CUSTOM_ALPHABET = "NaRvJT1B/m6AOXL9VDFIbUGkC+sSnzh5jxQ273d4lHPg0wcEpYqruWyfZoM8itKe-"

with open(INFILE) as f:
    ENC_FLAG = f.read()

def custom_b64_decode(in_str: str) -> str:
    data = str(in_str).translate(str(in_str).maketrans(CUSTOM_ALPHABET, STD_B64_CHARS))
    return base64.b64decode(data).decode()


out = custom_b64_decode(ENC_FLAG)

while not out.startswith("grey{"):
    out = custom_b64_decode(out)

print(out)
```

Running the function once spits out yet another base64-encoded string.
Wrapping repeated calls to our custom base64 decode yields the flag, eventually.

```powershell
❯ python .\solve_gogogo.py
grey{B4s3d_G0Ph3r_r333333}
```