# Process Hollowing

## Overview

An educational implementation of [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/) for studying Windows internals, PE loading, process architecture detection and base relocation.

> THIS PROJECT IS STRICTLY DEDICATED TO EDUCATIONAL PURPOSE ONLY. DO NOT TAKE ADVANTAGE OF THE PROJECT FOR ILLEGAL ACTIVITIES.

For technical issues due to Windows VM environment, the injector has no verified demonstrations available. Development will continue in order to get the script to execute successfully.

## Notable features

- Validates the basic structure of PE entities, including the suspended process on RAM and the payload on disk;
- Supports both  PE32 and PE32+;
- Determines the target process architecture using `IsWow64Process2`, avoiding [the ambiguity of `IsWow64Process`](https://robinva-uit.github.io/posts/ProcessHollowing/#:~:text=Using%20IsWow64Process%20is%20not%20recommended%20here.%20In%20case%20the%20API%20returns%20true%2C%20you%20can%20confidently%20say%20the%20target%E2%80%99s%20arch%20is%20x86.%20However%2C%20if%20the%20return%20value%20is%20false%2C%20the%20target%20could%20be%2064%2Dbit%20process%2C%20or%2032%2Dbit%20process%20running%20in%2032%2Dbit%20Windows.%20For%20that%20reason%2C%20false%20is%20kind%20of%20vague.);
- Maps PE headers and sections into the target process, as well as applies relocation in case of unsuccessful mapping at payload's `ImageBase`.
- Safely closes the target process (if any step fails), handles and clears payload buffer.

## Requirements

- Windows 10 or later.
- A C++ compiler supporting the Windows API.
- Matching payload and target architectures.
- A controlled testing environment, preferably a virtual machine.

## Build

Example using MinGW-w64:

```bash
x86_64-w64-mingw32-g++ ProcessHollowing.cpp -o ProcessHollowing.exe \
 -static -static-libgcc -static-libstdc++
```

## Usage

Run the syntax:

```bash
.\ProcessHollowing.exe <payload_path> <target_process>
```

Make sure to run this command while your Command Prompt/Powershell is at the location of this injector. Furthermore, select payload and target that [compatible](https://robinva-uit.github.io/posts/ProcessHollowing/#compatibility-check) with each other

## [Analysis blog](https://robinva-uit.github.io/posts/ProcessHollowing/)

## Attribution

This project is adapted from [Process-Hollowing](https://github.com/adamhlt/Process-Hollowing) by [adamhlt](https://github.com/adamhlt).

The original project is licensed under the GNU General Public License version 3.0 (GPL-3.0).

This version includes modifications and additional implementation, validation, documentation, and error handling by [RobinVA-UIT](https://github.com/RobinVA-UIT).



## License

This project is distributed under the GNU General Public License v3.0.
