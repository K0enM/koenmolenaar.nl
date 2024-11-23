+++
title = "jeFF0Falltrades Sandbox Crackme"
date = "2024-11-21"
author = "Koen Molenaar"
cover = "/write-ups/jeFF0Falltrades-sandbox-crackme/jeFF0Falltrades-logo.jpg"
tags = ["write-up", "crackme"]
keywords = ["write-up", "crackme", "malware analysis"]
description = "A write-up of jeFF0Falltrades Crackme challenge, which was part of his DIY Malware Analysis Sandbox series."
showFullContent = false
draft = false
+++

# Introduction

A few days ago, I noticed that one of my favorite reverse engineer youtubers, [jeFF0Falltrades](https://www.youtube.com/@jeFF0Falltrades) had uploaded a [2-part series on setting up a DIY Malware Analysis Sandbox.](https://www.youtube.com/watch?v=ELPWeRXxnSE&list=PLs-lxQfNn-H3n9TghY02njSFYdBvf_Sea&index=4)

I already had a Malware Analysis lab setup ([FLARE VM](https://github.com/mandiant/flare-vm)), but I had not used in quite a while. Moreover, one of the most important parts, faking & capturing internet traffic using Fakenet-ng was not really working for me. Therefore, I decided to revamp my lab using his video series. I did deviate a bit (I updated my existing FLARE VM & I used [PolarProxy](https://www.netresec.com/?page=PolarProxy) instead of [BurpSuite](https://portswigger.net/burp) as my TLS termination proxy), but in the end I had an up-to-date lab again.

Of course, I needed to test my workflow using this new lab. So, I decided to take on jeFF0Falltrades's Crackme, which he posted on his [DIY Malware Analysis Lab Github](https://github.com/jeFF0Falltrades/Tutorials/tree/master/master0Fnone_classes/2_Sandbox_in_a_Box/).

# Initial Analysis

- Filename: crackme.exe
- Size: 5103616 bytes
- SHA256: BB203AB338BE9968BA5ECBDF1B53633EB15D9BE82B7BC32D4E4ADE86B3467788

**CAPA output:**
```plaintext
┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ md5         │ 12712bfc9bc3196414cd8a38853e1131                                                                             │
│ sha1        │ 0447c87644a8f3a3df05849f8d9544d629ec1a72                                                                     │
│ sha256      │ bb203ab338be9968ba5ecbdf1b53633eb15d9be82b7bc32d4e4ade86b3467788                                             │
│ analysis    │ static                                                                                                       │
│ os          │ windows                                                                                                      │
│ format      │ pe                                                                                                           │
│ arch        │ amd64                                                                                                        │
│ path        │ C:/Users/test/Desktop/crackme/crackme.exe                                                                    │
┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙

┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ ATT&CK Tactic                        │ ATT&CK Technique                                                                 │
┝━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┥
│ DEFENSE EVASION                      │ Deobfuscate/Decode Files or Information T1140                                    │
│                                      │ Obfuscated Files or Information T1027                                            │
│                                      │ Virtualization/Sandbox Evasion::System Checks T1497.001                          │
├─────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
│ EXECUTION                            │ Shared Modules T1129                                                             │
┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙

┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ MBC Objective                        │ MBC Behavior                                                                      │
┝━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┥
│ ANTI-BEHAVIORAL ANALYSIS             │ Debugger Detection::Software Breakpoints [B0001.025]                             │
│                                      │ Virtual Machine Detection [B0009]                                                │
├─────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
│ COMMUNICATION                        │ HTTP Communication::Read Header [C0002.014]                                      │
├─────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
│ CRYPTOGRAPHY                         │ Crypto Library [C0059]                                                           │
│                                      │ Cryptographic Hash::SHA256 [C0029.003]                                           │
│                                      │ Decrypt Data::AES [C0031.001]                                                    │
│                                      │ Encrypt Data::3DES [C0027.004]                                                   │
│                                      │ Encrypt Data::AES [C0027.001]                                                    │
│                                      │ Encrypt Data::RC4 [C0027.009]                                                    │
│                                      │ Generate Pseudo-random Sequence::RC4 PRGA [C0021.004]                            │
│                                      │ Hashed Message Authentication Code [C0061]                                       │
├─────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
│ DATA                                 │ Check String [C0019]                                                             │
│                                      │ Encode Data::Base64 [C0026.001]                                                  │
│                                      │ Encode Data::XOR [C0026.002]                                                     │
│                                      │ Non-Cryptographic Hash::FNV [C0030.005]                                          │
│                                      │ Non-Cryptographic Hash::MurmurHash [C0030.001]                                   │
├─────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
│ DEFENSE EVASION                      │ Obfuscated Files or Information::Encoding-Custom Algorithm [E1027.m03]          │
│                                      │ Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]        │
│                                      │ Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]      │
├─────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
│ DISCOVERY                            │ Code Discovery::Enumerate PE Sections [B0046.001]                                │
├─────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
│ PROCESS                              │ Allocate Thread Local Storage [C0040]                                            │
┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙

┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ Capability                            │ Namespace                                                                        │
┝━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┥
│ check for software breakpoints        │ anti-analysis/anti-debugging/debugger-detection                                 │
│ reference anti-VM strings             │ anti-analysis/anti-vm/vm-detection                                              │
│ parse credit card information         │ collection/credit-card                                                          │
│ check HTTP status code                │ communication/http/client                                                       │
│ compiled with Go                      │ compiler/go                                                                     │
│ encode data using ADD XOR SUB         │ data-manipulation/encoding                                                      │
│ encode data using Base64              │ data-manipulation/encoding/base64                                               │
│ reference Base64 string               │ data-manipulation/encoding/base64                                               │
│ encode data using XOR                 │ data-manipulation/encoding/xor                                                  │
│ decrypt data using AES                │ data-manipulation/encryption/aes                                                │
│ encrypt data using AES                │ data-manipulation/encryption/aes                                                │
│ encrypt data using DES                │ data-manipulation/encryption/des                                                │
│ encrypt data using RC4                │ data-manipulation/encryption/rc4                                                │
│ hash data using fnv                   │ data-manipulation/hashing/fnv                                                   │
│ hash data using SHA256                │ data-manipulation/hashing/sha256                                                │
│ hash data using SHA512                │ data-manipulation/hashing/sha512                                                │
│ authenticate HMAC                     │ data-manipulation/hmac                                                          │
│ allocate thread local storage         │ host-interaction/thread/tls                                                    │
│ enumerate PE sections                 │ load-code/pe                                                                    │
│ resolve function by parsing PE exports│ load-code/pe                                                                    │
┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙
```

**DIE output:**

{{< image src="/write-ups/jeFF0Falltrades-sandbox-crackme/die-output.png" alt="Detect it Easy output" position="center" title="Detect it Easy output" >}}

Seeing this, we know this is a 64-bit Go executable, probably compiled using version 1.22.4.

Normally, I would also use [PE-studio](https://www.winitor.com/) to analyze a PE file. However, when analyzing the crackme.exe inside PE-studio, it became extremely slow and made my VM unusable. Therefore, I used [CFF explorer](https://ntcore.com/explorer-suite/) to analyze the import table of the crackme. Doing this, I found several interesting WinAPI function calls:

**Interesting imported functions**

- WriteFile
- VirtualAlloc
- SwitchToThread
- LoadLibraryW
- GetProcAddress
- CreateThread
- CreateFileA

**Strings analysis:**

Analyzing the strings contained in the binary, I could see a large amount of strings related to Go code, again confirming this binary was written in Go. Moreover, a lot of strings seemed to be related to cryptography & signatures (I saw "X.509" multiple times in the binary). From this, it can be assumed that the binary will try to connect to the internet over TLS.

After this simple static analyis, I decided not to reverse engineer the binary using Ghidra, but to find the answers to the following questions dynamically so I could practice my dynamic analysis skills.

# Questions

To not spoil the challenge, I will not show the actual answers to the questions in this write-up.
## Question 1

> What string, starting with the prefix "flag_", is found when running crackme.exe?

I solved this question using [SystemInformer](https://systeminformer.sourceforge.io/). In SystemInformer, you can look at the memory of a running (or suspended) process. In the memory tab, there is the options button which allows you to look at the strings in memory and filter them. Since we know the answers contains "flag_", a simple filter for strings containing this shows the answer.

{{< image src="/write-ups/jeFF0Falltrades-sandbox-crackme/q1-answer.png" alt="Screenshot of blurred answer to Question 1" position="center" title="Screenshot of blurred answer to Question 1" >}}


## Question 2

> What is the full path of the file that crackme.exe attempts to access?

I solved this using [ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon). To weed out background noise, I filtered the events by only including events originating from crackme.exe. To easily find file operations, I also filtered on operations containing "File". The answer to this question can then be found inside ProcMon.

{{< image src="/write-ups/jeFF0Falltrades-sandbox-crackme/q2-answer.png" alt="Screenshot of blurred answer to Question 2" position="center" title="Screenshot of blurred answer to Question 2" >}}


## Question 3

> crackme.exe uses a suspicious library...how big is this DLL in **bytes?**

This was a slightly more difficult question. Initially, I was unsure as to how to answer this. After a while, I remembered jeFF0Falltrades installing [PE-sieve](https://github.com/hasherezade/pe-sieve), which can be used to extract **suspicious** DLLs & EXEs from a running process. Running PE-sieve on a running / suspended process of crackme outputs a suspicous DLL. I analyzed this DLL in PE-studio, which shows use the size.

{{< image src="/write-ups/jeFF0Falltrades-sandbox-crackme/q3-answer.png" alt="Screenshot of blurred answer to Question 3" position="center" title="Screenshot of blurred answer to Question 3" >}}


## Question 4

> Speaking of that suspicious library, what is the file name opened by this library called?

This answer I got fairly trivially. I looked at the strings inside the DLL in [PE-studio](https://www.winitor.com/), which shows the answer immediately.

{{< image src="/write-ups/jeFF0Falltrades-sandbox-crackme/q4-answer.png" alt="Screenshot of blurred answer to Question 4" position="center" title="Screenshot of blurred answer to Question 4" >}}


## Question 5

> What is the full URL crackme.exe attempts to contact?

During static analysis, I found multiple references to TLS in the binary. I confirmed my suspicions by using Wireshark to capture network traffic while running the binary, which revealed that the binary generates HTTPS traffic. Therefore, to answer this question I needed to decrypt the TLS traffic. Luckily, a large part of the tutorial was focussed on setting up [INetSim](https://www.inetsim.org/) together with BurpSuite to do exactly this. However, I could not get BurpSuite to work and more importantly, I do not like using a cumbersome GUI tool for something which probably can be done inside the terminal. Therefore, I decided to use [PolarProxy](https://www.netresec.com/?page=PolarProxy) instead. 

Like with BurpSuite, you need to install the Root Certificate in the Windows VM before you are able to decrypt TLS traffic coming from it. The command I used to run PolarProxy to decrypt my TLS traffic was:

```plaintext
sudo polarproxy --terminate --connect 10.10.10.3 -p 443,80,80 --leafcert sign -o . -v
```

This intercepts TLS traffic coming from port 443, decrypts it, and forwards the decrypted traffic to 10.10.10.3:80 (My Remnux VM IP), where it is caught by INetSim's HTTP Listener and logged. It also writes a PCAP to the local directory containing the decrypted traffic as if it was directed at port 80.

You can find the full URL by looking at the INetSim report or looking through the PCAP generated by PolarProxy.

{{< image src="/write-ups/jeFF0Falltrades-sandbox-crackme/q5-answer.png" alt="Screenshot of blurred answer to Question 5" position="center" title="Screenshot of blurred answer to Question 5" >}}

## Question 6

> What is the data sent to this URL? (including spaces and punctuation)

No extra steps are needed to answer this question. The answer can be found by looking at the file generated by INetSim which contains the HTTP Post payload, or by looking through the PCAP generated by PolarProxy.

{{< image src="/write-ups/jeFF0Falltrades-sandbox-crackme/q6-answer.png" alt="Screenshot of blurred answer to Question 6" position="center" title="Screenshot of blurred answer to Question 6" >}}

## Question 7

> What is the name of the file crackme.exe writes to disk? (just the name, not the path; case sensitive)

For this question, I used ProcMon again with the same filters as for [Question 2](#question-2). However, since the question states "writes to disk" instead of just "accesses", I specifically looked for WriteFile operations.

{{< image src="/write-ups/jeFF0Falltrades-sandbox-crackme/q7-answer.png" alt="Screenshot of blurred answer to Question 7" position="center" title="Screenshot of blurred answer to Question 7" >}}

## Question 8

> What are the contents of this file?

After running the malware, I saw that the file it writes to was not persisted on disk after the binary was finished executing. A look at File operations in ProcMon seemed to confirm this. Luckily, I had learned about the [capture-py.py](https://github.com/fbruzzaniti/Capture-Py) script, recommended by jeFF0Falltrades. Using this, I was able to obtain a copy of the file so I could answer this question.

{{< image src="/write-ups/jeFF0Falltrades-sandbox-crackme/q8-answer.png" alt="Screenshot of blurred answer to Question 8" position="center" title="Screenshot of blurred answer to Question 8" >}}

# Conclusion

Overall, this challenge was really nice. It was not too easy, but also doable with limited experience using dynamic analysis tools. Moreover, it was very clear that this challenge was designed to be solved with the tools recommended in the tutorial. This made solving this crackme a good shakedown for my lab, which I intend to use in the future for more practice in malware analysis & reverse engineering.

Lastly, a big thanks to [je0FFalltrades](https://www.youtube.com/@jeFF0Falltrades) for creating amazing RE content and setting up this challenge!