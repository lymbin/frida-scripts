# frida-scripts

## frida-memory-dumper.py

Tool for memory dump and search data in process memory.

Worked on Linux and Windows.

Has 2 modes: **spawn** and **attach**.

**When spawn (app not running yet) may run from user.**

**When attach (app is already running) need to be run in privileged mode.**

## Install

Works only with **Python >=3.7** and need a **pip3** package.

`sudo pip3 intall -r requirements.txt`

### Note: new frida 16 need updated version of pip, wheel and setuptools

`sudo pip3 install --upgrade pip setuptools wheel`

## Usage

### Dump all process memory

`python3 frida-memory-dumper.py --dump <process_name>`

### Dump process memory from address and size

`python3 frida-memory-dumper.py --dump --addr <addr_in_hex> --size <size_in_bytes> <process_name>`

### Scan process memory and search bytes pattern

`python3 frida-memory-dumper.py --scan --pattern <bytes_pattern> <process_name>`

### Scan process memory and search string

`python3 frida-memory-dumper.py --scan --string <string> <process_name>`

### Interactive Dump all process memory

`python3 frida-memory-dumper.py --dump --interactive <process_name>`

Press Enter to dump memory when you want.

## Examples

Dump process with 1234 id

`python3 frida-memory-dumper.py --dump 1234`

Dump firefox process in interactive mode

`python3 frida-memory-dumper.py --dump --interactive firefox`

Scan firefox memory and search bytes

`python3 frida-memory-dumper.py --scan --pattern "30 ?? 32 33 34 35 36 37 38" firefox`

Scan firefox memory and search string

`python3 frida-memory-dumper.py --scan --string "12345678" firefox`
