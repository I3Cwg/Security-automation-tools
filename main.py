#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Tool - Main Entry Point
Tool for security analysis, reputation checks, and IOC sanitization.
"""

import os
import sys
import logging
from pathlib import Path

# Add root directory to Python path
ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))

from config.api_manager import APIManager
from config.settings import Settings
from utils.helpers import setup_logging, print_banner, clear_screen
# from modules.reputation_checker import ReputationChecker
# from modules.dns_lookup import DNSLookup
# from modules.email_analyzer import EmailAnalyzer
# from modules.url_decoder import URLDecoder
# from modules.sandbox import SandboxAnalyzer
# from modules.ioc_sanitizer import IOCSanitizer
# from modules.brand_monitor import BrandMonitor


class SecurityTool:
    """Main class to control the entire security tool"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.api_manager = APIManager()
        self.settings = Settings()

        # Initialize modules
        # self.reputation_checker = ReputationChecker(self.api_manager)
        # self.dns_lookup = DNSLookup()
        # self.email_analyzer = EmailAnalyzer(self.api_manager)
        # self.url_decoder = URLDecoder()
        # self.sandbox = SandboxAnalyzer(self.api_manager)
        # self.ioc_sanitizer = IOCSanitizer()
        # self.brand_monitor = BrandMonitor(self.api_manager)
    
    def show_main_menu(self):
        """Display main menu"""
        menu_options = [
            "1. Reputation/Blocklist Check (IP/Domain/URL/Hash)",
            "2. DNS/WHOIS Lookup", 
            "3. Email Security Analysis",
            "4. URL Decoding & Analysis",
            "5. File Sandbox Analysis",
            "6. IOC Sanitization",
            "7. Brand Monitoring & Analysis",
            "8. Configuration & API Keys",
            "9. Help & Documentation",
            "0. Exit"
        ]
        
        print("\n" + "="*60)
        print("🛡️  SECURITY ANALYSIS TOOL")
        print("="*60)
        for option in menu_options:
            print(f"   {option}")
        print("="*60)
    
    def handle_reputation_check(self):
        """Handle reputation check"""
        print("\n🔍 REPUTATION/BLOCKLIST CHECK")
        print("-" * 40)
        print("1. Check IP Address")
        print("2. Check Domain")
        print("3. Check URL")
        print("4. Check File Hash")
        print("5. Bulk Check (from file)")
        print("0. Back to main menu")
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == "1":
            ip = input("Enter IP address: ").strip()
            if ip:
                result = self.reputation_checker.check_ip(ip)
                self.display_results("IP Reputation", result)
        elif choice == "2":
            domain = input("Enter domain: ").strip()
            if domain:
                result = self.reputation_checker.check_domain(domain)
                self.display_results("Domain Reputation", result)
        elif choice == "3":
            url = input("Enter URL: ").strip()
            if url:
                result = self.reputation_checker.check_url(url)
                self.display_results("URL Reputation", result)
        elif choice == "4":
            hash_value = input("Enter file hash: ").strip()
            if hash_value:
                result = self.reputation_checker.check_hash(hash_value)
                self.display_results("Hash Reputation", result)
        elif choice == "5":
            file_path = input("Enter path to file with IOCs: ").strip()
            if os.path.exists(file_path):
                result = self.reputation_checker.bulk_check(file_path)
                self.display_results("Bulk Check Results", result)
        elif choice == "0":
            return
    
    def handle_dns_lookup(self):
        """Handle DNS lookup"""
        print("\n🌐 DNS/WHOIS LOOKUP")
        print("-" * 40)
        print("1. DNS Lookup")
        print("2. Reverse DNS")
        print("3. WHOIS Lookup")
        print("4. ISP Information")
        print("0. Back to main menu")
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == "1":
            domain = input("Enter domain: ").strip()
            if domain:
                result = self.dns_lookup.dns_lookup(domain)
                self.display_results("DNS Lookup", result)
        elif choice == "2":
            ip = input("Enter IP address: ").strip()
            if ip:
                result = self.dns_lookup.reverse_dns(ip)
                self.display_results("Reverse DNS", result)
        elif choice == "3":
            domain = input("Enter domain: ").strip()
            if domain:
                result = self.dns_lookup.whois_lookup(domain)
                self.display_results("WHOIS Information", result)
        elif choice == "4":
            ip = input("Enter IP address: ").strip()
            if ip:
                result = self.dns_lookup.get_isp_info(ip)
                self.display_results("ISP Information", result)
        elif choice == "0":
            return
    
    def handle_email_analysis(self):
        """Handle email analysis"""
        print("\n📧 EMAIL SECURITY ANALYSIS")
        print("-" * 40)
        print("1. Analyze Email Headers")
        print("2. Check Email Address Reputation")
        print("3. Analyze Phishing Indicators")
        print("4. Sandbox Email Attachments")
        print("0. Back to main menu")
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == "1":
            email_file = input("Enter path to email file (.eml): ").strip()
            if os.path.exists(email_file):
                result = self.email_analyzer.analyze_headers(email_file)
                self.display_results("Email Header Analysis", result)
        elif choice == "2":
            email = input("Enter email address: ").strip()
            if email:
                result = self.email_analyzer.check_email_reputation(email)
                self.display_results("Email Reputation", result)
        elif choice == "3":
            email_file = input("Enter path to email file (.eml): ").strip()
            if os.path.exists(email_file):
                result = self.email_analyzer.analyze_phishing(email_file)
                self.display_results("Phishing Analysis", result)
        elif choice == "0":
            return
    
    def handle_url_decoding(self):
        """Handle URL decoding"""
        print("\n🔗 URL DECODING & ANALYSIS")
        print("-" * 40)
        print("1. Decode Base64 URL")
        print("2. Decode Office365 SafeLink")
        print("3. Unshorten URL")
        print("4. Decode UTF-8 URL")
        print("5. Full URL Analysis")
        print("0. Back to main menu")
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == "1":
            encoded_url = input("Enter Base64 encoded URL: ").strip()
            if encoded_url:
                result = self.url_decoder.decode_base64(encoded_url)
                self.display_results("Base64 Decoded URL", result)
        elif choice == "2":
            safelink = input("Enter Office365 SafeLink: ").strip()
            if safelink:
                result = self.url_decoder.decode_safelink(safelink)
                self.display_results("SafeLink Decoded", result)
        elif choice == "3":
            short_url = input("Enter shortened URL: ").strip()
            if short_url:
                result = self.url_decoder.unshorten_url(short_url)
                self.display_results("Unshortened URL", result)
        elif choice == "5":
            url = input("Enter URL for full analysis: ").strip()
            if url:
                result = self.url_decoder.full_analysis(url)
                self.display_results("Full URL Analysis", result)
        elif choice == "0":
            return
    
    def handle_configuration(self):
        """Handle API keys configuration"""
        print("\n⚙️  CONFIGURATION & API KEYS")
        print("-" * 40)
        print("1. Add/Update API Keys")
        print("2. View Current Configuration")
        print("3. Test API Connections")
        print("4. Reset Configuration")
        print("0. Back to main menu")
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == "1":
            self.api_manager.setup_api_keys()
        elif choice == "2":
            self.api_manager.show_configuration()
        elif choice == "3":
            self.api_manager.test_connections()
        elif choice == "4":
            confirm = input("Are you sure you want to reset all configuration? (yes/no): ").strip().lower()
            if confirm == "yes":
                self.api_manager.reset_configuration()
        elif choice == "0":
            return
    
    def display_results(self, title, results):
        """Display analysis results"""
        print(f"\n📊 {title}")
        print("=" * (len(title) + 4))
        
        if isinstance(results, dict):
            for key, value in results.items():
                print(f"{key}: {value}")
        elif isinstance(results, list):
            for item in results:
                print(f"• {item}")
        else:
            print(results)
        
        input("\nPress Enter to continue...")
    
    def run(self):
        """Run the main application"""
        try:
            # Setup logging
            setup_logging()

            # Check and setup API keys for the first time
            if not self.api_manager.has_api_keys():
                print("🔑 First time setup - Please configure your API keys")
                self.api_manager.setup_api_keys()
            
            while True:
                clear_screen()
                print_banner()
                self.show_main_menu()
                
                choice = input("\nEnter your choice (0-9): ").strip()
                
                if choice == "1":
                    self.handle_reputation_check()
                elif choice == "2":
                    self.handle_dns_lookup()
                elif choice == "3":
                    self.handle_email_analysis()
                elif choice == "4":
                    self.handle_url_decoding()
                elif choice == "5":
                    print("🗂️ File Sandbox Analysis - Coming soon!")
                    input("Press Enter to continue...")
                elif choice == "6":
                    print("🧹 IOC Sanitization - Coming soon!")
                    input("Press Enter to continue...")
                elif choice == "7":
                    print("🏢 Brand Monitoring - Coming soon!")
                    input("Press Enter to continue...")
                elif choice == "8":
                    self.handle_configuration()
                elif choice == "9":
                    self.show_help()
                elif choice == "0":
                    print("\n👋 Thank you for using Security Tool!")
                    break
                else:
                    print("❌ Invalid choice. Please try again.")
                    input("Press Enter to continue...")
        
        except KeyboardInterrupt:
            print("\n\n👋 Tool interrupted by user. Goodbye!")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            print(f"❌ An error occurred: {e}")
    
    def show_help(self):
        """Display help"""
        help_text = """
🛡️  SECURITY TOOL HELP

This tool provides comprehensive security analysis capabilities:

1. REPUTATION CHECK
   - Check IP addresses, domains, URLs, and file hashes
   - Uses multiple threat intelligence sources
   - Supports bulk checking from files

2. DNS/WHOIS LOOKUP
   - Standard DNS lookups and reverse DNS
   - WHOIS information retrieval
   - ISP and geolocation data

3. EMAIL ANALYSIS
   - Email header analysis
   - Phishing detection
   - Attachment sandbox analysis

4. URL DECODING
   - Base64, SafeLink decoding
   - URL unshortening
   - Full URL analysis

5. CONFIGURATION
   - Manage API keys securely
   - Test API connections
   - View current settings

For more information, visit the GitHub repository or documentation.
        """
        print(help_text)
        input("\nPress Enter to continue...")


def main():
    """Entry point chính"""
    tool = SecurityTool()
    tool.run()


if __name__ == "__main__":
    main()