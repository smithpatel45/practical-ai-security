# Tested Environment

Last verification run: **2026-11-21**

| Item | Value |
|---|---|
| Operating system | Windows 11 Home (10.0.26300) |
| Python | 3.13.5 |
| Test runner | pytest 9.1.1 |
| Third-party runtime dependencies | none (standard library only) |
| Result | `python -m pytest` → **74 passed** |
| Additional checks | `python -m py_compile` on all lab sources: OK; every lab's main command re-run and compared with its `expected_output.txt` |

The book states Python 3.11+ as the requirement. **Only Python 3.13.5 has actually been tested.** Running the suite on 3.11 and 3.12 is still to be done; if you run it on another version or operating system, the result is useful to know. The labs have not been run on macOS or Linux in this pass; nothing in them is intentionally Windows-specific (paths use `pathlib`, servers bind to `127.0.0.1`).
