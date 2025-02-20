<div align="center">
  <img src="https://github.com/reecdeep/hollowise/blob/main/hollowise_logo.png?raw=true" alt="hollowise" width="230" />
</div>

# Hollowise - Mask your analysis software from malware!

**Hollowise** is a Windows-based tool that implements **process hollowing** and **PPID (Parent Process ID) spoofing** techniques. It allows for stealth execution of debuggers and code and network analizers by replacing the memory of a suspended process (e.g. calc.exe) with arbitrary code while masquerading PEB, under a legitimate parent process (explorer.exe).

**Note:** This project provides an opportunity to explore techniques commonly used by malware for educational purposes.

## Credits
A special thank you to my dear friend Pillo for his precious advice. 
I would like to say thank you for the great work by [NATsCodes](https://github.com/NATsCodes/ProcessHollowing), the developer of a well designed process hollowing PoC. I got ispiration from that code to build the process hollowing function inside hollowise.
Thank you for sharing your work with the community!
<br><br>

## ⚠️ Disclaimer
This project is intended for **educational and research purposes only**. Misuse of this tool for malicious purposes is strictly prohibited. The author assumes no responsibility for any misuse.

## Features
- **Process Hollowing**: Replaces the memory of a legitimate process with a custom payload.
- **PPID Spoofing**: Creates a new process while spoofing its parent process (default: `explorer.exe`).
- **Window Title Manipulation**: Dynamically modifies the window title of the injected process.
- **Memory Relocation Handling**: Ensures correct relocation of the payload to match the new process base address.
- **Remote CommandLine & ImagePathName Modification**: Adjusts process parameters in memory.

## Usage
```sh
hollowise.exe [legit_process.exe] [payload.exe path] [WindowTitle]

legit_process.exe: A legitimate Windows executable (e.g., calc.exe) to be hollowed
payload.exe path: The malware analysis tool to hide
WindowTitle: The new window title for the injected process

e.g. commandline for starting x64dbg with the window text "EatMySocks"
hollowise.exe  "C:\Windows\system32\calc.exe"  "C:\Program Files\x3264dbg\x64\x64dbg.exe"  EatMySocks
```

<div align="center">
  <img src="https://github.com/reecdeep/hollowise/blob/main/hollowise_example.png?raw=true" alt="Segugio" width="1745" />
</div>

📜 License
This project is licensed under the CC Zero License - see the LICENSE file for details.
