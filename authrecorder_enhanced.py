#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AuthRecorder Pro Enhanced - v2.2.0
==================================

Production Ready Authentication Capture Tool with Advanced Features:
- 🔐 Encrypted Credential Vault
- 📊 Interactive Dashboard & Analytics
- 🔄 Session Replay & Debugging
- 📱 Multi-Factor Authentication (MFA) Support
- 🛡️ Advanced Proxy & Interception

Author: AuthRecorder Team
Version: 2.2.0
License: MIT
"""

import argparse
import json
import logging
import os
import pathlib
import re
import subprocess
import sys
import threading
import time
import shutil
import hashlib
import secrets
import base64
import tkinter as tk
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from collections import defaultdict

# External dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from rich import print as rprint
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False

try:
    from tkinter import filedialog, messagebox, scrolledtext, ttk
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# ============================================================================
# Constants
# ============================================================================
VERSION = "2.2.0"
DEFAULT_PROXY = "http://127.0.0.1:8080"
MITM_PORT = 8080

# ============================================================================
# 1. ENCRYPTED CREDENTIAL VAULT
# ============================================================================
class CredentialVault:
    """Secure encrypted credential storage"""
    
    def __init__(self, vault_path: Path = Path("credentials.vault"), master_key: Optional[str] = None):
        self.vault_path = vault_path
        self.master_key = master_key
        self.credentials = {}
        self._init_vault()
    
    def _init_vault(self):
        """Initialize or load vault"""
        if not CRYPTO_AVAILABLE:
            logging.warning("cryptography not installed. Vault disabled.")
            return
        
        if self.vault_path.exists():
            self._load_vault()
        else:
            self._create_vault()
    
    def _create_vault(self):
        """Create new encrypted vault"""
        if not CRYPTO_AVAILABLE:
            return
        
        if not self.master_key:
            self.master_key = Fernet.generate_key().decode()
        
        vault_data = {
            "version": "1.0",
            "created": datetime.now().isoformat(),
            "credentials": {}
        }
        
        self._save_vault(vault_data)
        logging.info(f"Credential vault created at {self.vault_path}")
    
    def _get_cipher(self):
        """Get cipher instance"""
        if not CRYPTO_AVAILABLE or not self.master_key:
            return None
        return Fernet(self.master_key.encode())
    
    def store_credential(self, service: str, username: str, password: str, metadata: Dict = None):
        """Store encrypted credential"""
        if not CRYPTO_AVAILABLE:
            logging.error("Encryption not available")
            return False
        
        cipher = self._get_cipher()
        if not cipher:
            return False
        
        credential = {
            "service": service,
            "username": username,
            "password_encrypted": cipher.encrypt(password.encode()).decode(),
            "stored_at": datetime.now().isoformat(),
            "metadata": metadata or {}
        }
        
        self.credentials[f"{service}:{username}"] = credential
        self._save_vault()
        logging.info(f"Stored credential for {service}:{username}")
        return True
    
    def retrieve_credential(self, service: str, username: str) -> Optional[str]:
        """Retrieve and decrypt password"""
        if not CRYPTO_AVAILABLE:
            return None
        
        cipher = self._get_cipher()
        if not cipher:
            return None
        
        key = f"{service}:{username}"
        if key not in self.credentials:
            return None
        
        cred = self.credentials[key]
        try:
            password = cipher.decrypt(cred["password_encrypted"].encode()).decode()
            return password
        except Exception as e:
            logging.error(f"Failed to decrypt credential: {e}")
            return None
    
    def list_credentials(self) -> List[Dict]:
        """List all stored credentials (without passwords)"""
        return [
            {"service": c["service"], "username": c["username"], "stored_at": c["stored_at"]}
            for c in self.credentials.values()
        ]
    
    def _save_vault(self):
        """Save vault to disk"""
        vault_data = {
            "version": "1.0",
            "credentials": self.credentials
        }
        self.vault_path.write_text(json.dumps(vault_data), encoding="utf-8")
    
    def _load_vault(self):
        """Load vault from disk"""
        try:
            data = json.loads(self.vault_path.read_text(encoding="utf-8"))
            self.credentials = data.get("credentials", {})
            logging.info(f"Vault loaded with {len(self.credentials)} credentials")
        except Exception as e:
            logging.error(f"Failed to load vault: {e}")

# ============================================================================
# 2. ANALYTICS & DASHBOARD
# ============================================================================
@dataclass
class CaptureAnalytics:
    """Analytics for capture session"""
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    status_codes: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    request_types: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    tokens_found: List[Dict[str, str]] = field(default_factory=list)
    cookies_count: int = 0
    anti_bot_detected: bool = False
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def get_duration(self) -> float:
        """Get capture duration in seconds"""
        end = self.end_time or time.time()
        return end - self.start_time
    
    def get_success_rate(self) -> float:
        """Get success rate percentage"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    def print_report(self):
        """Print analytics report"""
        if not RICH_AVAILABLE:
            return
        
        console = Console()
        
        table = Table(title="Capture Analytics Report")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Duration", f"{self.get_duration():.2f}s")
        table.add_row("Total Requests", str(self.total_requests))
        table.add_row("Successful", str(self.successful_requests))
        table.add_row("Failed", str(self.failed_requests))
        table.add_row("Success Rate", f"{self.get_success_rate():.1f}%")
        table.add_row("Cookies Captured", str(self.cookies_count))
        table.add_row("Tokens Found", str(len(self.tokens_found)))
        table.add_row("Anti-Bot Detected", "Yes" if self.anti_bot_detected else "No")
        
        console.print(table)

# ============================================================================
# 3. SESSION REPLAY & DEBUGGING
# ============================================================================
@dataclass
class ReplayableRequest:
    """Request that can be replayed"""
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    response_status: Optional[int] = None
    response_body: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    notes: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)

class SessionReplayer:
    """Replay and debug captured authentication sessions"""
    
    def __init__(self, vault: Optional[CredentialVault] = None):
        self.vault = vault
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        self.replay_history: List[Dict] = []
    
    def replay_request(self, req: ReplayableRequest, modify_headers: Dict = None) -> Tuple[int, str]:
        """Replay a captured request with optional modifications"""
        if not REQUESTS_AVAILABLE:
            logging.error("Requests library not available")
            return 0, ""
        
        headers = {**req.headers}
        if modify_headers:
            headers.update(modify_headers)
        
        try:
            if req.method.upper() == "GET":
                resp = self.session.get(req.url, headers=headers, timeout=10)
            elif req.method.upper() == "POST":
                resp = self.session.post(req.url, data=req.body, headers=headers, timeout=10)
            else:
                resp = self.session.request(req.method, req.url, data=req.body, headers=headers, timeout=10)
            
            result = {
                "request": req.to_dict(),
                "status_code": resp.status_code,
                "response_length": len(resp.text),
                "timestamp": datetime.now().isoformat()
            }
            self.replay_history.append(result)
            
            return resp.status_code, resp.text
        
        except Exception as e:
            logging.error(f"Replay failed: {e}")
            return 0, str(e)
    
    def compare_responses(self, original: str, replayed: str) -> Dict:
        """Compare original and replayed responses"""
        return {
            "original_length": len(original),
            "replayed_length": len(replayed),
            "identical": original == replayed,
            "differences": self._find_differences(original, replayed)
        }
    
    def _find_differences(self, str1: str, str2: str) -> List[Dict]:
        """Find differences between two strings"""
        diffs = []
        lines1 = str1.split('\n')
        lines2 = str2.split('\n')
        
        for i, (line1, line2) in enumerate(zip(lines1, lines2)):
            if line1 != line2:
                diffs.append({
                    "line": i + 1,
                    "original": line1[:100],
                    "replayed": line2[:100]
                })
        
        return diffs[:10]  # Limit to first 10 differences
    
    def export_replay_session(self, path: Path):
        """Export replay history to file"""
        path.write_text(json.dumps(self.replay_history, indent=2), encoding="utf-8")
        logging.info(f"Replay session exported to {path}")

# ============================================================================
# 4. MFA SUPPORT
# ============================================================================
class MFAHandler:
    """Handle Multi-Factor Authentication"""
    
    def __init__(self):
        self.totp_secrets: Dict[str, str] = {}
        self.backup_codes: Dict[str, List[str]] = {}
    
    def generate_totp_secret(self, service: str) -> Optional[str]:
        """Generate TOTP secret (Google Authenticator compatible)"""
        if not PYOTP_AVAILABLE:
            logging.error("pyotp not installed")
            return None
        
        secret = pyotp.random_base32()
        self.totp_secrets[service] = secret
        return secret
    
    def get_totp_code(self, service: str) -> Optional[str]:
        """Get current TOTP code"""
        if not PYOTP_AVAILABLE or service not in self.totp_secrets:
            return None
        
        totp = pyotp.TOTP(self.totp_secrets[service])
        return totp.now()
    
    def generate_backup_codes(self, service: str, count: int = 10) -> List[str]:
        """Generate backup codes for account recovery"""
        codes = [secrets.token_hex(4) for _ in range(count)]
        self.backup_codes[service] = codes
        return codes
    
    def verify_backup_code(self, service: str, code: str) -> bool:
        """Verify and consume a backup code"""
        if service not in self.backup_codes or code not in self.backup_codes[service]:
            return False
        
        self.backup_codes[service].remove(code)
        return True
    
    def parse_otp_from_response(self, response_text: str) -> Optional[str]:
        """Parse OTP code from HTML response (email/SMS simulation)"""
        patterns = [
            r'code["\']?\s*[=:]\s*["\']?([0-9]{4,6})',
            r'OTP["\']?\s*[=:]\s*["\']?([0-9]{4,6})',
            r'\b([0-9]{4,6})\b(?=.*code)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

# ============================================================================
# 5. ADVANCED PROXY & INTERCEPTION
# ============================================================================
@dataclass
class InterceptionRule:
    """Rule for request/response interception and modification"""
    name: str
    pattern: str  # URL pattern (regex)
    action: str  # 'modify_header', 'modify_body', 'inject_auth', 'block'
    match_headers: Dict[str, str] = field(default_factory=dict)
    replace_values: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    priority: int = 0

class ProxyInterceptor:
    """Advanced request/response interception"""
    
    def __init__(self):
        self.rules: List[InterceptionRule] = []
        self.recorded_flows: List[Dict] = []
        self.filters: Dict[str, Any] = {}
    
    def add_rule(self, rule: InterceptionRule):
        """Add interception rule"""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        logging.info(f"Added interception rule: {rule.name}")
    
    def apply_rules(self, request_data: Dict) -> Dict:
        """Apply interception rules to request"""
        modified = dict(request_data)
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            if not re.search(rule.pattern, modified.get("url", "")):
                continue
            
            if rule.action == "modify_header":
                if "headers" not in modified:
                    modified["headers"] = {}
                modified["headers"].update(rule.replace_values)
            
            elif rule.action == "modify_body" and modified.get("body"):
                for old, new in rule.replace_values.items():
                    modified["body"] = modified["body"].replace(old, new)
            
            elif rule.action == "inject_auth":
                if "headers" not in modified:
                    modified["headers"] = {}
                modified["headers"].update(rule.replace_values)
            
            elif rule.action == "block":
                modified["_blocked"] = True
                break
        
        return modified
    
    def record_flow(self, request: Dict, response: Dict):
        """Record HTTP flow for analysis"""
        flow = {
            "timestamp": datetime.now().isoformat(),
            "request": {
                "method": request.get("method"),
                "url": request.get("url"),
                "headers": request.get("headers", {}),
                "body_length": len(request.get("body", ""))
            },
            "response": {
                "status": response.get("status"),
                "headers": response.get("headers", {}),
                "body_length": len(response.get("body", ""))
            }
        }
        self.recorded_flows.append(flow)
    
    def export_har(self, path: Path):
        """Export flows to HAR (HTTP Archive) format"""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "AuthRecorder", "version": VERSION},
                "entries": self.recorded_flows
            }
        }
        path.write_text(json.dumps(har_data, indent=2), encoding="utf-8")
        logging.info(f"HAR file exported to {path}")
    
    def apply_filter(self, filter_name: str, filter_value: str):
        """Apply filter to recorded flows"""
        self.filters[filter_name] = filter_value
    
    def get_filtered_flows(self) -> List[Dict]:
        """Get flows matching current filters"""
        result = self.recorded_flows
        
        for key, value in self.filters.items():
            if key == "status_code":
                result = [f for f in result if f["response"]["status"] == int(value)]
            elif key == "url_pattern":
                result = [f for f in result if re.search(value, f["request"]["url"])]
        
        return result

# ============================================================================
# INTEGRATED CAPTURE ENGINE (Updated)
# ============================================================================
@dataclass
class CapturedRequest:
    """Captured HTTP request"""
    method: str
    url: str
    headers: Dict[str, Any]
    post_data: Any = None
    response_status: int = None
    response_headers: Dict[str, Any] = None
    html_source: str = None
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class CaptureResult:
    """Complete capture result"""
    requests: List[CapturedRequest]
    cookies: List[Dict[str, Any]]
    analytics: CaptureAnalytics
    mfa_detected: bool = False
    replay_data: Optional[List[ReplayableRequest]] = None
    interceptor: Optional[ProxyInterceptor] = None
    mitm_flows: List[Dict[str, Any]] = field(default_factory=list)
    anti_bot: bool = False
    capture_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_json(self) -> Dict[str, Any]:
        return {
            "requests": [r.to_dict() for r in self.requests],
            "cookies": self.cookies,
            "analytics": self.analytics.to_dict(),
            "mfa_detected": self.mfa_detected,
            "mitm_flows": self.mitm_flows,
            "anti_bot": self.anti_bot,
            "capture_metadata": self.capture_metadata,
            "version": VERSION,
            "timestamp": datetime.now().isoformat()
        }

# ============================================================================
# ENHANCED RECORD AUTHENTICATION
# ============================================================================
def record_authentication_enhanced(
    target_url: str,
    proxy: Optional[str] = None,
    browser_type: str = "chromium",
    vault: Optional[CredentialVault] = None,
    interceptor: Optional[ProxyInterceptor] = None,
    mfa_handler: Optional[MFAHandler] = None,
    timeout: int = 120
) -> Optional[CaptureResult]:
    """
    Enhanced authentication recording with new features
    """
    if not PLAYWRIGHT_AVAILABLE:
        logging.error("Playwright not installed")
        return None
    
    analytics = CaptureAnalytics()
    captured_requests = []
    cookies = []
    mfa_detected = False
    replay_requests = []
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()
            
            # Request handler
            def on_request(req):
                try:
                    method = req.method
                    url = req.url
                    headers = dict(req.headers)
                    
                    analytics.total_requests += 1
                    analytics.request_types[method] = analytics.request_types.get(method, 0) + 1
                    
                    # Apply interception rules if available
                    request_data = {"method": method, "url": url, "headers": headers}
                    if interceptor:
                        request_data = interceptor.apply_rules(request_data)
                        if request_data.get("_blocked"):
                            return
                    
                    post_data = None
                    if method != "GET":
                        try:
                            post_data = req.post_data
                        except:
                            pass
                    
                    captured_requests.append(CapturedRequest(
                        method=method,
                        url=url,
                        headers=headers,
                        post_data=post_data,
                        timestamp=time.time()
                    ))
                    
                    # Create replayable request
                    replay_requests.append(ReplayableRequest(
                        method=method,
                        url=url,
                        headers=headers,
                        body=post_data
                    ))
                    
                    analytics.successful_requests += 1
                    logging.info(f"Captured {method} {url}")
                
                except Exception as e:
                    analytics.failed_requests += 1
                    analytics.errors.append(str(e))
            
            # Response handler
            def on_response(resp):
                try:
                    status = resp.status
                    analytics.status_codes[status] = analytics.status_codes.get(status, 0) + 1
                    
                    if captured_requests:
                        last_req = captured_requests[-1]
                        last_req.response_status = status
                        last_req.response_headers = dict(resp.headers)
                        
                        if status == 200 and 'text/html' in resp.headers.get('content-type', ''):
                            try:
                                html = resp.text()
                                last_req.html_source = html
                                
                                # Detect MFA
                                if mfa_handler and any(pattern in html.lower() for pattern in 
                                    ['otp', 'two-factor', 'authenticator', 'totp', 'sms code', 'email code']):
                                    nonlocal mfa_detected
                                    mfa_detected = True
                                    
                                    # Try to extract OTP
                                    otp = mfa_handler.parse_otp_from_response(html)
                                    if otp:
                                        analytics.tokens_found.append({"type": "OTP", "value": otp})
                            
                            except:
                                pass
                        
                        # Record flow in interceptor
                        if interceptor:
                            response_data = {"status": status, "headers": dict(resp.headers)}
                            interceptor.record_flow(
                                {"method": last_req.method, "url": last_req.url, "headers": last_req.headers},
                                response_data
                            )
                
                except Exception as e:
                    logging.error(f"Error processing response: {e}")
            
            page.on("request", on_request)
            page.on("response", on_response)
            
            logging.info(f"Navigating to {target_url}")
            page.goto(target_url, wait_until="load", timeout=timeout * 1000)
            time.sleep(3)
            
            cookies = context.cookies()
            analytics.cookies_count = len(cookies)
            browser.close()
        
        analytics.end_time = time.time()
        
        return CaptureResult(
            requests=captured_requests,
            cookies=cookies,
            analytics=analytics,
            mfa_detected=mfa_detected,
            replay_data=replay_requests,
            interceptor=interceptor,
            capture_metadata={
                "target_url": target_url,
                "browser_type": browser_type,
                "duration": analytics.get_duration()
            }
        )
    
    except Exception as e:
        analytics.end_time = time.time()
        analytics.errors.append(str(e))
        logging.error(f"Capture failed: {e}")
        return None

# ============================================================================
# CLI WITH NEW FEATURES
# ============================================================================
def setup_logging(log_level: str = "INFO", log_file: Optional[Path] = None) -> logging.Logger:
    """Setup logging"""
    log_dir = Path("outputs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    if log_file is None:
        log_file = log_dir / "authrecorder_enhanced.log"
    
    handlers = [logging.FileHandler(log_file, encoding='utf-8')]
    
    if RICH_AVAILABLE:
        handlers.append(RichHandler(rich_tracebacks=True))
    else:
        handlers.append(logging.StreamHandler(sys.stdout))
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s %(levelname)8s %(name)s: %(message)s",
        handlers=handlers,
        force=True
    )
    
    return logging.getLogger("authrecorder")

def run_cli_enhanced(args):
    """Run enhanced CLI"""
    logger = setup_logging(args.log_level)
    
    # Initialize components
    vault = CredentialVault() if CRYPTO_AVAILABLE else None
    mfa_handler = MFAHandler() if PYOTP_AVAILABLE else None
    interceptor = ProxyInterceptor()
    
    # Add interception rules if provided
    if hasattr(args, 'intercept_rules') and args.intercept_rules:
        rules = json.loads(args.intercept_rules)
        for rule_data in rules:
            rule = InterceptionRule(**rule_data)
            interceptor.add_rule(rule)
    
    # Run enhanced capture
    result = record_authentication_enhanced(
        target_url=args.target_url,
        vault=vault,
        interceptor=interceptor,
        mfa_handler=mfa_handler
    )
    
    if result:
        # Print analytics
        result.analytics.print_report()
        
        # Export data
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save capture data
        capture_file = output_dir / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        capture_file.write_text(json.dumps(result.to_json(), indent=2), encoding="utf-8")
        logger.info(f"Capture saved to {capture_file}")
        
        # Export HAR if interceptor has data
        if interceptor and interceptor.recorded_flows:
            har_file = output_dir / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.har"
            interceptor.export_har(har_file)
        
        # Store credentials if vault available
        if vault and hasattr(args, 'store_credentials') and args.store_credentials:
            for req in result.requests:
                if 'password' in str(req.post_data).lower():
                    vault.store_credential("captured", "user", "password", {"url": req.url})
        
        print("\n✅ Enhanced capture completed!")
        print(f"📊 Analytics: {result.analytics.total_requests} requests captured")
        if result.mfa_detected:
            print("🔐 MFA detected in capture")
        print(f"📁 Output: {capture_file}")
    else:
        print("❌ Capture failed")
        return 1
    
    return 0

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description=f"AuthRecorder Pro Enhanced v{VERSION} - Advanced Authentication Capture Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--target-url", required=True, help="Target URL to capture")
    parser.add_argument("--output", default="outputs", help="Output directory")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], 
                       default="INFO", help="Log level")
    parser.add_argument("--intercept-rules", help="JSON interception rules")
    parser.add_argument("--store-credentials", action="store_true", 
                       help="Store credentials in vault")
    
    args = parser.parse_args()
    
    return run_cli_enhanced(args)

if __name__ == "__main__":
    sys.exit(main())
