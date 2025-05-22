# -*- coding: utf-8 -*-
"""
Validators - Validation functions for IP, domain, hash, email, URL, etc.
This module provides various functions to validate different types of data
"""

import re
import socket
import logging
from typing import Optional, Union, List
from urllib.parse import urlparse
import ipaddress


def validate_ip(ip: str) -> bool:
    """Validate IP address (IPv4 và IPv6)"""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_ipv4(ip: str) -> bool:
    """Validate IPv4 address specifically"""
    try:
        ipaddress.IPv4Address(ip.strip())
        return True
    except ValueError:
        return False


def validate_ipv6(ip: str) -> bool:
    """Validate IPv6 address specifically"""
    try:
        ipaddress.IPv6Address(ip.strip())
        return True
    except ValueError:
        return False


def validate_ip_range(ip_range: str) -> bool:
    """Validate IP range/CIDR"""
    try:
        ipaddress.ip_network(ip_range.strip(), strict=False)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP is private"""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        return ip_obj.is_private
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    """Check if IP is public"""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        return not (ip_obj.is_private or ip_obj.is_loopback or 
                   ip_obj.is_multicast or ip_obj.is_reserved)
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """Validate domain name"""
    if not domain or len(domain) > 253:
        return False
    
    # Remove trailing dot
    domain = domain.rstrip('.')
    
    # Check overall format
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    if not domain_regex.match(domain):
        return False
    
    # Check each label
    labels = domain.split('.')
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
    
    return True


def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url.strip())
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_email(email: str) -> bool:
    """Validate email address"""
    email_regex = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    return bool(email_regex.match(email.strip()))


def validate_hash(hash_value: str, hash_type: str = 'auto') -> bool:
    """Validate hash value"""
    if not hash_value:
        return False
    
    hash_value = hash_value.strip()
    
    # Check if it's all hex characters
    if not re.match(r'^[a-fA-F0-9]+$', hash_value):
        return False
    
    # Check length based on type
    if hash_type == 'auto':
        return len(hash_value) in [32, 40, 64, 128]  # MD5, SHA1, SHA256, SHA512
    elif hash_type.lower() == 'md5':
        return len(hash_value) == 32
    elif hash_type.lower() == 'sha1':
        return len(hash_value) == 40
    elif hash_type.lower() == 'sha256':
        return len(hash_value) == 64
    elif hash_type.lower() == 'sha512':
        return len(hash_value) == 128
    
    return False


def detect_hash_type(hash_value: str) -> Optional[str]:
    """Detect hash type from length"""
    if not validate_hash(hash_value):
        return None
    
    length = len(hash_value.strip())
    hash_types = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        128: 'sha512'
    }
    
    return hash_types.get(length)


def validate_api_key(service: str, api_key: str) -> bool:
    """Validate API key format for different services"""
    if not api_key or not api_key.strip():
        return False
    
    api_key = api_key.strip()
    
    # Service-specific validation
    validators = {
        'virustotal': lambda k: len(k) == 64 and re.match(r'^[a-fA-F0-9]+$', k),
        'abuseipdb': lambda k: len(k) >= 16 and len(k) <= 80,
        'otx': lambda k: len(k) == 40 and re.match(r'^[a-fA-F0-9]+$', k),
        'shodan': lambda k: len(k) == 32 and re.match(r'^[A-Za-z0-9]+$', k),
        'urlvoid': lambda k: len(k) >= 16,
        'hybrid_analysis': lambda k: len(k) >= 16,
        'ipinfo': lambda k: len(k) >= 8
    }
    
    validator = validators.get(service.lower())
    if validator:
        return validator(api_key)
    
    # Default validation - at least 8 chars
    return len(api_key) >= 8


def validate_port(port: Union[str, int]) -> bool:
    """Validate port number"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_cidr(cidr: str) -> bool:
    """Validate CIDR notation"""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        return True
    except ValueError:
        return False


def validate_hostname(hostname: str) -> bool:
    """Validate hostname"""
    if not hostname or len(hostname) > 253:
        return False
    
    # Allow IP addresses
    if validate_ip(hostname):
        return True
    
    # Validate as domain name
    return validate_domain(hostname)


def validate_file_extension(filename: str, allowed_extensions: List[str]) -> bool:
    """Validate file extension"""
    if not filename:
        return False
    
    extension = filename.lower().split('.')[-1] if '.' in filename else ''
    return extension in [ext.lower().lstrip('.') for ext in allowed_extensions]


def validate_user_agent(user_agent: str) -> bool:
    """Validate User-Agent string"""
    if not user_agent or len(user_agent.strip()) == 0:
        return False
    
    # Basic checks
    if len(user_agent) > 500:  # Too long
        return False
    
    # Check for common suspicious patterns
    suspicious_patterns = [
        r'<script',
        r'javascript:',
        r'<iframe',
        r'eval\(',
        r'document\.',
        r'window\.'
    ]
    
    user_agent_lower = user_agent.lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, user_agent_lower):
            return False
    
    return True


def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """Sanitize user input"""
    if not input_str:
        return ""
    
    # Remove dangerous characters
    sanitized = re.sub(r'[<>"\';\\]', '', input_str)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()


def validate_timeout(timeout: Union[str, int, float]) -> bool:
    """Validate timeout value"""
    try:
        timeout_val = float(timeout)
        return 0 < timeout_val <= 300  # Max 5 minutes
    except (ValueError, TypeError):
        return False


def validate_regex_pattern(pattern: str) -> bool:
    """Validate regex pattern"""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def is_ioc_format(text: str) -> dict:
    """Detect IOC format from text"""
    text = text.strip()
    
    result = {
        'is_ip': validate_ip(text),
        'is_domain': validate_domain(text),
        'is_url': validate_url(text),
        'is_email': validate_email(text),
        'is_hash': validate_hash(text),
        'hash_type': detect_hash_type(text) if validate_hash(text) else None,
        'detected_type': None
    }
    
    # Determine primary type
    if result['is_ip']:
        result['detected_type'] = 'ip'
    elif result['is_url']:
        result['detected_type'] = 'url'
    elif result['is_email']:
        result['detected_type'] = 'email'
    elif result['is_hash']:
        result['detected_type'] = 'hash'
    elif result['is_domain']:
        result['detected_type'] = 'domain'
    
    return result


def validate_ioc_list(ioc_list: List[str]) -> dict:
    """Validate IOCs from a list"""
    results = {
        'valid': [],
        'invalid': [],
        'by_type': {
            'ip': [],
            'domain': [],
            'url': [],
            'email': [],
            'hash': []
        }
    }
    
    for ioc in ioc_list:
        ioc = ioc.strip()
        if not ioc:
            continue
            
        ioc_info = is_ioc_format(ioc)
        
        if ioc_info['detected_type']:
            results['valid'].append(ioc)
            results['by_type'][ioc_info['detected_type']].append(ioc)
        else:
            results['invalid'].append(ioc)
    
    return results


def check_domain_resolution(domain: str) -> bool:
    """Check if domain can be resolved"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def validate_json_structure(json_data: dict, required_fields: List[str]) -> bool:
    """Validate JSON structure has all required fields"""
    if not isinstance(json_data, dict):
        return False
    
    for field in required_fields:
        if field not in json_data:
            return False
    
    return True


def validate_severity_level(level: str) -> bool:
    """Validate severity level"""
    valid_levels = ['low', 'medium', 'high', 'critical', 'info']
    return level.lower() in valid_levels


def validate_confidence_score(score: Union[str, int, float]) -> bool:
    """Validate confidence score (0-100)"""
    try:
        score_val = float(score)
        return 0 <= score_val <= 100
    except (ValueError, TypeError):
        return False


def validate_date_format(date_str: str, format_str: str = "%Y-%m-%d") -> bool:
    """Validate date format"""
    try:
        from datetime import datetime
        datetime.strptime(date_str, format_str)
        return True
    except ValueError:
        return False


def clean_ioc(ioc: str) -> str:
    """Clean và normalize IOC"""
    if not ioc:
        return ""
    
    # Remove whitespace
    ioc = ioc.strip()
    
    # Remove common prefixes/suffixes
    prefixes_to_remove = ['http://', 'https://', 'ftp://', 'www.']
    for prefix in prefixes_to_remove:
        if ioc.lower().startswith(prefix):
            ioc = ioc[len(prefix):]
    
    # Remove trailing slashes for domains/URLs
    ioc = ioc.rstrip('/')
    
    # Convert to lowercase for domains
    if validate_domain(ioc) or validate_email(ioc):
        ioc = ioc.lower()
    
    return ioc


# Export functions
__all__ = [
    'validate_ip', 'validate_ipv4', 'validate_ipv6', 'validate_ip_range',
    'is_private_ip', 'is_public_ip', 'validate_domain', 'validate_url',
    'validate_email', 'validate_hash', 'detect_hash_type', 'validate_api_key',
    'validate_port', 'validate_cidr', 'validate_hostname', 'validate_file_extension',
    'validate_user_agent', 'sanitize_input', 'validate_timeout',
    'validate_regex_pattern', 'is_ioc_format', 'validate_ioc_list',
    'check_domain_resolution', 'validate_json_structure', 'validate_severity_level',
    'validate_confidence_score', 'validate_date_format', 'clean_ioc'
]
