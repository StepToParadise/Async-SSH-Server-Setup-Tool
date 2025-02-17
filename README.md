# Async SSH Server Configuration Tool

## Overview
This tool is designed to execute remote commands and upload files to multiple servers asynchronously via SSH. It supports parallel execution, retries, and detailed logging.

## Features
- **Asynchronous execution** using `asyncssh`.
- **Parallel processing** with configurable concurrency.
- **Automatic retries** for failed commands and file uploads.
- **Custom command execution** from a file or predefined list.
- **File uploading** to remote servers.
- **Detailed logging** and JSON report generation.
- **Automatic package manager detection and retries** for `apt` operations.
- **Support for RSA, ECDSA, and ED25519 keys for authentication.**
- **Automatic detection and handling of SSH key-based authentication.**
- **Execution on multiple hosts with structured JSON output.**

## Requirements
- Python 3.7+
- `asyncssh` library

## Installation
```sh
pip install asyncssh
```

## Usage
### Running the Script
```sh
python setup.py --credentials credentials.txt --threads 5 --retries 5 --retry-delay 3 --commands-file commands.txt --upload-file local_file.txt --remote-path /remote/path/file.txt
```

### Arguments
| Argument | Description | Default |
|----------|-------------|---------|
| `--credentials` | Path to the credentials file | `credentials.txt` |
| `--threads` | Number of concurrent SSH connections | `5` |
| `--retries` | Number of retry attempts for SSH operations | `5` |
| `--retry-delay` | Delay between retries (seconds) | `3.0` |
| `--upload-file` | Local file to upload | `None` |
| `--remote-path` | Remote path to upload the file to | `None` |
| `--commands-file` | File containing commands to execute | `None` |
| `--private-key` | Path to the SSH private key for authentication | `None` |

### Credentials Format
Each line in `credentials.txt` must be in the format:
```
user:password@host[:port]
```
Example:
```
admin:password123@192.168.1.10:22
user:securePass@myserver.com
```
For key-based authentication, specify the username and host only:
```
admin@192.168.1.10:22
user@myserver.com
```

### Commands File Format
The `commands.txt` file should contain one command per line:
```
sudo apt update -y
sudo apt install -y docker.io
echo "Setup complete"
```

## Output
The script generates a `report.json` containing the results of all operations.

## Logging
- Logs are saved in `server_setup.log`.
- Errors and command outputs are logged.

## Example Output (report.json)
```json
[
    {
        "server": { "host": "192.168.1.10", "port": 22, "user": "admin" },
        "commands": { "sudo apt update -y": { "status": "success", "output": "..." } },
        "file_upload": { "status": "success", "local_path": "local_file.txt", "remote_path": "/remote/path/file.txt" },
        "authentication": { "method": "key", "status": "success" },
        "error": null
    }
]
```

## Donate

- EVM: `0x3124Be9C360d4931bF9937Da4DB3507899F0f7EB`
- SOL: `9htc1cTKmHwBMwQZSgZJFQNz7nKiUaC9G5x1ZDt8oXHP`