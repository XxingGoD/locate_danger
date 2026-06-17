# Locatespace IDA Plugin

`Locatespace` is an IDAPython plugin for finding calls to user-defined dangerous functions and highlighting them in Hex-Rays pseudocode.

## Features

- Scan for calls to dangerous functions
- Highlight matched pseudocode lines in red
- Jump from the results list to the callsite
- Manage dangerous functions through a GUI rule manager
- Store the dangerous function list inside the current IDB

## Requirements

- IDA Pro with IDAPython
- Hex-Rays decompiler

## Install

Copy or symlink `locate_danger.py` into your IDA `plugins` directory:

```bash
ln -s /path/to/ida_plugin/locate_danger.py /path/to/IDA/plugins/locate_danger.py
```

For this machine:

```bash
ln -s /home/starlight/CtfTools/ida_plugin/locate_danger.py /home/starlight/CtfTools/IDA9.4/plugins/locate_danger.py
```

## Usage

After restarting IDA:

1. Open a target binary.
2. Run `Edit -> Plugins -> Locatespace: Scan dangerous calls`.
3. If no dangerous functions are configured yet, the plugin opens a rule manager window.
4. In the rule manager, use insert/edit/delete to manage dangerous functions.
5. Run the scan again, or use `Shift-Alt-D`.

Each rule has:

- Function name
- Category
- Severity

## Notes

- Dangerous functions are stored in the current IDB.
- The plugin hotkey is `Shift-Alt-D`.
