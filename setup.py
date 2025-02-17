import os
import json
import logging
import asyncio
import argparse
from typing import List, Dict, Any

import asyncssh

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server_setup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def parse_credential(line: str) -> Dict[str, Any]:
    line = line.strip()
    if '@' not in line:
        raise ValueError("Invalid credential format")
    
    userpass, hostpart = line.split('@', 1)
    user, password = userpass.split(':', 1)
    
    if ':' in hostpart:
        host, port = hostpart.split(':', 1)
        port = int(port)
    else:
        host = hostpart
        port = 22
    
    return {
        'user': user,
        'password': password,
        'host': host,
        'port': port
    }


async def execute_commands(
    conn: asyncssh.SSHClientConnection, 
    commands: List[str], 
    password: str,
    retries: int = 3,
    retry_delay: float = 5.0
) -> Dict[str, Any]:
    results = {}

    pre_commands = [
        "sudo dpkg --configure -a",
        "sudo rm -f /var/lib/apt/lists/lock /var/lib/dpkg/lock*",
        "sudo bash -c 'while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 1; done'",
        "sudo sed -i.bak 's|ru.archive.ubuntu.com|archive.ubuntu.com|g' /etc/apt/sources.list",
        "sudo sed -i 's|http://|https://|g' /etc/apt/sources.list"
    ]
    
    full_commands = pre_commands + commands

    for cmd in full_commands:
        original_cmd = cmd
        for attempt in range(retries):
            try:
                if cmd.startswith("sudo apt "):
                    cmd = cmd.replace("sudo apt ", "sudo DEBIAN_FRONTEND=noninteractive apt-get ")
                    cmd += " -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'"
                    current_retry_delay = 10.0
                else:
                    current_retry_delay = retry_delay

                if cmd.strip().startswith('sudo '):
                    sanitized_cmd = cmd[5:].strip().replace("'", "'\"'\"'")
                    modified_cmd = (
                        f'echo "{password}" | '
                        f'sudo -S bash -c \'{sanitized_cmd}\''
                    )
                    result = await conn.run(
                        modified_cmd,
                        request_pty=True,
                        timeout=120 if 'apt' in cmd else 60
                    )
                else:
                    result = await conn.run(cmd, timeout=30)

                if result.exit_status == 100 and 'dpkg' in result.stderr:
                    logger.warning("Detected dpkg interruption, attempting auto-repair...")
                    fix_result = await conn.run(
                        f'echo "{password}" | sudo -S dpkg --configure -a',
                        request_pty=True,
                        timeout=120
                    )
                    if fix_result.exit_status == 0:
                        logger.info("Dpkg fixed, retrying command...")
                        attempt -= 1
                        continue
                if result.exit_status == 0:
                    results[original_cmd] = {
                        'status': 'success',
                        'output': result.stdout,
                        'error': result.stderr
                    }
                    break
                else:
                    cmd = original_cmd
                    error_msg = f"Exit status {result.exit_status}"
                    if result.stderr:
                        error_msg += f": {result.stderr.strip()}"
                    
                    if attempt < retries - 1:
                        logger.warning(
                            f"Command failed: {error_msg} "
                            f"(attempt {attempt+1}/{retries}). Retrying..."
                        )
                        await asyncio.sleep(current_retry_delay)
                    else:
                        results[original_cmd] = {
                            'status': 'error',
                            'error': error_msg,
                            'output': result.stdout,
                            'stderr': result.stderr
                        }
            except Exception as e:
                error_msg = str(e)
                if isinstance(e, asyncssh.Error) and e.stderr:
                    error_msg += f" | stderr: {e.stderr}"
                
                if attempt < retries - 1:
                    logger.warning(
                        f"Command '{cmd}' failed: {error_msg} "
                        f"(attempt {attempt+1}/{retries}). Retrying..."
                    )
                    await asyncio.sleep(retry_delay)
                else:
                    results[original_cmd] = {
                        'status': 'error',
                        'error': error_msg,
                        'output': result.stdout if result else None,
                        'stderr': result.stderr if result else None
                    }
    return results

async def process_server(
    server: Dict[str, Any], 
    commands: List[str], 
    semaphore: asyncio.Semaphore,
    upload_file: str = None, 
    remote_path: str = None,
    retries: int = 3,
    retry_delay: float = 5.0
) -> Dict[str, Any]:
    result = {
        'server': server,
        'commands': {},
        'file_upload': None,
        'error': None
    }
    
    async with semaphore:
        for attempt in range(retries):
            try:
                async with asyncssh.connect(
                    host=server['host'],
                    port=server['port'],
                    username=server['user'],
                    password=server['password'],
                    known_hosts=None
                ) as conn:
                    result['commands'] = await execute_commands(
                        conn, commands, server['password'], retries, retry_delay
                    )
                    
                    if upload_file and remote_path:
                        for upload_attempt in range(retries):
                            try:
                                await asyncssh.scp(
                                    upload_file, 
                                    (conn, remote_path)
                                )
                                result['file_upload'] = {
                                    'status': 'success',
                                    'local_path': upload_file,
                                    'remote_path': remote_path
                                }
                                break
                            except Exception as e:
                                if upload_attempt < retries - 1:
                                    logger.warning(
                                        f"Upload failed for {server['host']} (attempt {upload_attempt+1}). Retrying..."
                                    )
                                    await asyncio.sleep(retry_delay)
                                else:
                                    result['file_upload'] = {
                                        'status': 'error',
                                        'error': str(e)
                                    }
                    break
            except Exception as e:
                if attempt < retries - 1:
                    logger.warning(
                        f"Connection to {server['host']} failed (attempt {attempt+1}/{retries}): {e}. "
                        f"Retrying in {retry_delay} seconds..."
                    )
                    await asyncio.sleep(retry_delay)
                else:
                    result['error'] = str(e)
        return result


async def main(args):
    servers = []
    try:
        with open(args.credentials, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        servers.append(parse_credential(line))
                    except Exception as e:
                        logger.error(f"Error parsing line '{line}': {e}")
    except Exception as e:
        logger.error(f"Error reading credentials file: {e}")
        return

    if args.commands_file:
        try:
            with open(args.commands_file, 'r') as f:
                commands = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error reading commands file: {e}")
            return
    else:
        commands = [
            "sudo apt update -y",
            "sudo apt upgrade -y",
            "sudo apt install -y git",
            "sudo apt install -y docker.io",
            "sudo apt install -y screen",
            "sudo apt install -y nano",
            "sudo apt autoremove -y",
            "sudo apt autoclean -y"
        ]

    upload_file = args.upload_file
    if upload_file and not os.path.isfile(upload_file):
        logger.error(f"File not found: {upload_file}")
        return

    semaphore = asyncio.Semaphore(args.threads)

    tasks = [
        process_server(
            server, 
            commands, 
            semaphore, 
            args.upload_file, 
            args.remote_path,
            args.retries,
            args.retry_delay
        )
        for server in servers
    ]

    results = await asyncio.gather(*tasks)

    with open('report.json', 'w') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    successful = 0
    for result in results:
        host = f"{result['server']['host']}:{result['server']['port']}"
        if result['error']:
            logger.error(f"Server {host} failed: {result['error']}")
        else:
            successful += 1
            logger.info(f"Server {host} processed successfully")
            
    logger.info(f"Processing complete. Success: {successful}/{len(servers)}")
    logger.info("Detailed report saved to report.json")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Async SSH Server Configuration Tool'
    )
    parser.add_argument(
        '--credentials', 
        default='credentials.txt', 
        help='Path to credentials file (default: credentials.txt)'
    )
    parser.add_argument(
        '--threads', 
        type=int, 
        default=5,
        help='Number of concurrent connections (default: 5)'
    )
    parser.add_argument(
        '--retries',
        type=int,
        default=5,
        help='Number of retry attempts for each operation (default: 3)'
    )
    parser.add_argument(
        '--retry-delay',
        type=float,
        default=3.0,
        help='Delay in seconds between retry attempts (default: 5.0)'
    )
    parser.add_argument(
        '--upload-file', 
        help='Local file path to upload'
    )
    parser.add_argument(
        '--remote-path', 
        help='Remote path to upload file to'
    )
    parser.add_argument(
        '--commands-file', 
        help='File containing commands to execute'
    )
    parser.add_argument(
        '--package-retries',
        type=int,
        default=5,
        help='Number of retry attempts for package operations (default: 5)'
    )

    args = parser.parse_args()
    
    if (args.upload_file and not args.remote_path) or (not args.upload_file and args.remote_path):
        logger.error("Both --upload-file and --remote-path must be specified")
        exit(1)
    
    asyncio.run(main(args))