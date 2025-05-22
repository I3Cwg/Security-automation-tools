#!/urs/bin/env python3
"""
Helper Functions - Functions for various tasks
"""

import os
import sys
import json
import logging
import platform
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
import re

# Third party imports
from colorama import init, Fore, Back, Style
from tabulate import tabulate

init(autoreset=True)

def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_format: Optional[str] = None
) -> logging.Logger:
    """
    Set up logging configuration.
    """

    if log_format is None:
        log_format = ("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    #create logs directory if it doesn't exist
    log_dir = Path(__file__).parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)

    # default log file name
    if log_file is None:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = log_dir / f"security_tool_{timestamp}.log"

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger("SecurityTool")
    logger.info(f"Logging initialized - Level: {log_level}, File: {log_file}")
    
    return logger

def print_banner():
    """In banner cho tool"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
██████╗ ███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     
██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
██████╔╝█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝        ██║   ██║   ██║██║   ██║██║     
██╔═══╝ ██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝         ██║   ██║   ██║██║   ██║██║     
██║     ███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║          ██║   ╚██████╔╝╚██████╔╝███████╗
╚═╝     ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{Style.RESET_ALL}
{Fore.YELLOW}🛡️  Threat Intelligence & Security Analysis Tool{Style.RESET_ALL}
{Fore.GREEN}Version 1.0 | Developed for SOC/CERT Teams{Style.RESET_ALL}
"""
    print(banner)


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_colored(text: str, color: str = "white", style: str = "normal") -> None:
    """In text với màu sắc"""
    color_map = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'yellow': Fore.YELLOW,
        'blue': Fore.BLUE,
        'magenta': Fore.MAGENTA,
        'cyan': Fore.CYAN,
        'white': Fore.WHITE,
        'black': Fore.BLACK
    }
    
    style_map = {
        'normal': Style.NORMAL,
        'bright': Style.BRIGHT,
        'dim': Style.DIM
    }
    
    color_code = color_map.get(color.lower(), Fore.WHITE)
    style_code = style_map.get(style.lower(), Style.NORMAL)
    
    print(f"{color_code}{style_code}{text}{Style.RESET_ALL}")


def format_table(data: List[Dict], headers: Optional[List[str]] = None) -> str:
    """Format data to table"""
    if not data:
        return "No data to display"
    
    if headers is None:
        headers = list(data[0].keys()) if data else []
    
    # Convert data to list format for tabulate
    table_data = []
    for row in data:
        table_data.append([row.get(header, 'N/A') for header in headers])
    
    return tabulate(table_data, headers=headers, tablefmt="grid")


def format_json_pretty(data: Union[Dict, List]) -> str:
    """Format JSON with pretty print"""
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def format_file_size(size_bytes: int) -> str:
    """Format file size to human readable"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"


def format_timestamp(timestamp: Union[int, float, str]) -> str:
    """Format timestamp to human readable string"""
    try:
        if isinstance(timestamp, str):
            # Try to parse ISO format first
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except:
                return timestamp
        
        # Convert unix timestamp
        dt = datetime.fromtimestamp(float(timestamp))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(timestamp)


def validate_file_path(file_path: str, must_exist: bool = True) -> bool:
    """Validate file path"""
    try:
        path = Path(file_path)
        if must_exist:
            return path.exists() and path.is_file()
        else:
            return path.parent.exists()
    except:
        return False


def read_file_content(file_path: str, encoding: str = 'utf-8') -> Optional[str]:
    """Read file content"""
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None


def write_file_content(file_path: str, content: str, encoding: str = 'utf-8') -> bool:
    """Write content to file"""
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w', encoding=encoding) as f:
            f.write(content)
        return True
    except Exception as e:
        logging.error(f"Error writing file {file_path}: {e}")
        return False


def read_lines_from_file(file_path: str, strip_empty: bool = True) -> List[str]:
    """Read lines from file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Clean up lines
        lines = [line.strip() for line in lines]
        if strip_empty:
            lines = [line for line in lines if line]
        
        return lines
    except Exception as e:
        logging.error(f"Error reading lines from {file_path}: {e}")
        return []


def write_lines_to_file(file_path: str, lines: List[str]) -> bool:
    """Write lines to file"""
    try:
        content = '\n'.join(lines)
        return write_file_content(file_path, content)
    except Exception as e:
        logging.error(f"Error writing lines to {file_path}: {e}")
        return False


def safe_json_loads(json_str: str) -> Optional[Union[Dict, List]]:
    """Parse JSON string safely"""
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error: {e}")
        return None


def safe_json_dumps(data: Union[Dict, List], indent: int = 2) -> Optional[str]:
    """Convert to JSON string safely"""
    try:
        return json.dumps(data, indent=indent, ensure_ascii=False, default=str)
    except Exception as e:
        logging.error(f"JSON encode error: {e}")
        return None


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to be safe for filesystem"""
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Limit length
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:200-len(ext)] + ext
    
    return filename


def create_temp_file(suffix: str = '', prefix: str = 'security_tool_') -> str:
    """Tạo temporary file"""
    import tempfile
    fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    os.close(fd)
    return temp_path


def cleanup_temp_files(temp_dir: Optional[str] = None):
    """Cleanup temporary files"""
    import tempfile
    import glob
    
    if temp_dir is None:
        temp_dir = tempfile.gettempdir()
    
    pattern = os.path.join(temp_dir, 'security_tool_*')
    temp_files = glob.glob(pattern)
    
    cleaned = 0
    for temp_file in temp_files:
        try:
            os.remove(temp_file)
            cleaned += 1
        except:
            pass
    
    logging.info(f"Cleaned up {cleaned} temporary files")


def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    return {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'python_implementation': platform.python_implementation(),
        'hostname': platform.node()
    }


def defang_ioc(ioc: str, ioc_type: str = 'auto') -> str:
    """Defang IOCs for safe sharing"""
    if not ioc:
        return ioc
    
    # Auto-detect type if not specified
    if ioc_type == 'auto':
        if '.' in ioc and not ioc.replace('.', '').replace(':', '').isdigit():
            if ioc.startswith('http'):
                ioc_type = 'url'
            else:
                ioc_type = 'domain'
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', ioc):
            ioc_type = 'ip'
        else:
            ioc_type = 'unknown'
    
    # Apply defanging
    if ioc_type in ['domain', 'url']:
        ioc = ioc.replace('.', '[.]')
        ioc = ioc.replace('http://', 'hxxp://')
        ioc = ioc.replace('https://', 'hxxps://')
    elif ioc_type == 'ip':
        ioc = ioc.replace('.', '[.]')
    elif ioc_type == 'email':
        ioc = ioc.replace('@', '[@]')
        ioc = ioc.replace('.', '[.]')
    
    return ioc


def refang_ioc(defanged_ioc: str) -> str:
    """Refang IOCs from defanged format"""
    if not defanged_ioc:
        return defanged_ioc
    
    # Reverse defanging
    ioc = defanged_ioc.replace('[.]', '.')
    ioc = ioc.replace('[@]', '@')
    ioc = ioc.replace('hxxp://', 'http://')
    ioc = ioc.replace('hxxps://', 'https://')
    
    return ioc


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract IOCs from text"""
    if not text:
        return {}
    
    iocs = {
        'ips': [],
        'domains': [],
        'urls': [],
        'emails': [],
        'hashes': []
    }
    
    # IP addresses (IPv4)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    iocs['ips'] = list(set(re.findall(ip_pattern, text)))
    
    # Domains (basic pattern)
    domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b'
    potential_domains = re.findall(domain_pattern, text)
    # Filter out IPs from domains
    iocs['domains'] = [d for d in set(potential_domains) if not re.match(ip_pattern, d)]
    
    # URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    iocs['urls'] = list(set(re.findall(url_pattern, text)))
    
    # Email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    iocs['emails'] = list(set(re.findall(email_pattern, text)))
    
    # Hashes (MD5, SHA1, SHA256)
    hash_patterns = [
        r'\b[a-fA-F0-9]{32}\b',  # MD5
        r'\b[a-fA-F0-9]{40}\b',  # SHA1
        r'\b[a-fA-F0-9]{64}\b'   # SHA256
    ]
    
    for pattern in hash_patterns:
        iocs['hashes'].extend(re.findall(pattern, text))
    
    iocs['hashes'] = list(set(iocs['hashes']))
    
    return iocs


def progress_bar(current: int, total: int, width: int = 50, prefix: str = '') -> str:
    """Create progress bar"""
    if total == 0:
        return f"{prefix} [{'█' * width}] 100%"
    
    percent = current / total
    filled = int(width * percent)
    bar = '█' * filled + '░' * (width - filled)
    percentage = f"{percent:.1%}"
    
    return f"{prefix} [{bar}] {percentage} ({current}/{total})"


def print_progress(current: int, total: int, prefix: str = 'Progress'):
    """Print progress bar"""
    bar = progress_bar(current, total, prefix=prefix)
    print(f"\r{bar}", end='', flush=True)
    if current >= total:
        print()  # New line when complete


def confirm_action(message: str, default: bool = False) -> bool:
    """Confirm user action"""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{message} ({default_str}): ").strip().lower()
    
    if not response:
        return default
    
    return response in ['y', 'yes', '1', 'true']


def select_from_list(items: List[str], prompt: str = "Select an option") -> Optional[int]:
    """Select item from list"""
    if not items:
        return None
    
    print(f"\n{prompt}:")
    for i, item in enumerate(items, 1):
        print(f"{i}. {item}")
    
    try:
        choice = int(input("\nEnter your choice: ").strip())
        if 1 <= choice <= len(items):
            return choice - 1
        else:
            print("Invalid choice")
            return None
    except ValueError:
        print("Invalid input")
        return None


def calculate_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
    """Calculate hash of data"""
    import hashlib
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hash_func = getattr(hashlib, algorithm.lower(), None)
    if hash_func is None:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    return hash_func(data).hexdigest()


def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate hash of a file"""
    import hashlib
    
    try:
        hash_func = getattr(hashlib, algorithm.lower())
        
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None


def is_valid_hash(hash_str: str, hash_type: str = 'auto') -> bool:
    """Validate hash string"""
    if not hash_str:
        return False
    
    # Remove any whitespace
    hash_str = hash_str.strip()
    
    # Check if it's all hex characters
    if not re.match(r'^[a-fA-F0-9]+$', hash_str):
        return False
    
    # Check length based on type
    if hash_type == 'auto':
        return len(hash_str) in [32, 40, 64, 128]  # MD5, SHA1, SHA256, SHA512
    elif hash_type.lower() == 'md5':
        return len(hash_str) == 32
    elif hash_type.lower() == 'sha1':
        return len(hash_str) == 40
    elif hash_type.lower() == 'sha256':
        return len(hash_str) == 64
    elif hash_type.lower() == 'sha512':
        return len(hash_str) == 128
    
    return False


def retry_with_backoff(func, max_retries: int = 3, base_delay: float = 1.0):
    """Retry function with exponential backoff"""
    import time
    import random
    
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            
            # Exponential backoff with jitter
            delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
            logging.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay:.2f}s...")
            time.sleep(delay)


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate string if too long"""
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def mask_sensitive_data(data: str, mask_char: str = "*", keep_chars: int = 4) -> str:
    """Mask sensitive data (API keys, passwords, etc.)"""
    if len(data) <= keep_chars * 2:
        return mask_char * len(data)
    
    start = data[:keep_chars]
    end = data[-keep_chars:]
    middle = mask_char * (len(data) - keep_chars * 2)
    
    return start + middle + end


# Export important functions
__all__ = [
    'setup_logging', 'print_banner', 'clear_screen', 'print_colored',
    'format_table', 'format_json_pretty', 'format_file_size', 'format_timestamp',
    'validate_file_path', 'read_file_content', 'write_file_content',
    'read_lines_from_file', 'write_lines_to_file', 'safe_json_loads', 'safe_json_dumps',
    'sanitize_filename', 'create_temp_file', 'cleanup_temp_files', 'get_system_info',
    'defang_ioc', 'refang_ioc', 'extract_iocs_from_text',
    'progress_bar', 'print_progress', 'confirm_action', 'select_from_list',
    'calculate_hash', 'calculate_file_hash', 'is_valid_hash',
    'retry_with_backoff', 'truncate_string', 'mask_sensitive_data'
]