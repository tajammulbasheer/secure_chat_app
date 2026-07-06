# 9. Structured Logging using Python's Standard Logging Library

* Status: **Accepted**
* Date: 2026-06-26
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
The codebase is currently riddled with raw standard output print calls (e.g. `print()`, `sys.stderr.write()`) to log system operations, debugging outputs, and warnings. 

This presents several issues:
1. **No level isolation**: Normal informational logs cannot be distinguished from security alerts, error stack traces, or trace logs. 
2. **Standard output clutter**: It is difficult to run scripts in the background or inspect clean CLI screens because background thread output intercepts the terminal inputs.
3. **No file persistence**: Log outputs are completely lost when the application or server process terminates.

We need a unified logging approach to enforce consistent diagnostic tracking, severities, and the ability to persist logs to disk.

## Decision Drivers
- Support severities (DEBUG, INFO, WARNING, ERROR, CRITICAL).
- Allow configuration of log level and log targets (console vs. file) via `.env`.
- Minimize performance overhead.

## Considered Options
1. **Option A (Custom print wrapper)**: Write a custom utility function that appends timestamps and prints to files. (Hard to scale, ignores standard Python log ecosystems).
2. **Option B (Python Standard Library `logging`)**: Create a unified logger module in `shared/logger.py` configured via `logging.basicConfig`.
3. **Option C (Loguru Library)**: Use the modern third-party `loguru` library. (Provides beautiful out-of-the-box colorization and rotation, but adds another third-party dependency).

## Decision Outcome
Chosen Option: **Option B (Python Standard Library `logging`)**

### Implementation
1. **Shared Logger (`shared/logger.py`)**:
   Establish a configuration helper inside the shared package:
   ```python
   import logging
   import os

   def setup_logger(name, log_file=None, level=logging.INFO):
       formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
       logger = logging.getLogger(name)
       logger.setLevel(level)

       # Clear existing handlers to prevent duplicate logging
       if logger.hasHandlers():
           logger.handlers.clear()

       # Console Handler
       ch = logging.StreamHandler()
       ch.setFormatter(formatter)
       logger.addHandler(ch)

       # Optional File Handler
       if log_file:
           fh = logging.FileHandler(log_file)
           fh.setFormatter(formatter)
           logger.addHandler(fh)

       return logger
   ```
2. **STS Integration**:
   Configure log paths in `server/config.py` (e.g., `server/data/sts.log`) and import the logger inside `sts.py`. Replace print statements (e.g., replace `print(f"Server started on {HOST}:{PORT}")` with `logger.info(f"Server started on {HOST}:{PORT}")`).
3. **Client Engine Integration**:
   Add client logs (e.g., `client/data/client_<username>.log`) to persist connection logs and security exceptions.

### Positive Consequences
- **Level filtering**: In production, the log level can be set to `WARNING` via `.env` to hide verbose handshake steps.
- **Audit Logs**: Security warnings (like invalid signature exceptions or failed challenge signs) are preserved in local file logs for analysis.
- **Standardized output format**: Incorporates precise timestamps and thread identifiers automatically.

### Negative Consequences
- Standard console stream handlers will print directly to stdout, which might still conflict with the CLI's interactive prompt if not suppressed. CLI app can set logging level to `ERROR` for console outputs and write lower-level logs to file only.
