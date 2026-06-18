#!/usr/bin/env python3
import asyncio
import ipaddress
import sys
import os
import time
import urllib.request
from datetime import datetime

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
WHITE = '\033[97m'
RESET = '\033[0m'

COUNTRY_URLS = {
    '1': 'https://www.ipdeny.com/ipblocks/data/countries/bh.zone',
    '2': 'https://www.ipdeny.com/ipblocks/data/countries/cn.zone',
    '3': 'https://www.ipdeny.com/ipblocks/data/countries/fr.zone',
    '4': 'https://www.ipdeny.com/ipblocks/data/countries/de.zone',
    '5': 'https://www.ipdeny.com/ipblocks/data/countries/hk.zone',
    '6': 'https://www.ipdeny.com/ipblocks/data/countries/in.zone',
    '7': 'https://www.ipdeny.com/ipblocks/data/countries/ir.zone',
    '8': 'https://www.ipdeny.com/ipblocks/data/countries/iq.zone',
    '9': 'https://www.ipdeny.com/ipblocks/data/countries/il.zone',
    '10': 'https://www.ipdeny.com/ipblocks/data/countries/jp.zone',
    '11': 'https://www.ipdeny.com/ipblocks/data/countries/ng.zone',
    '12': 'https://www.ipdeny.com/ipblocks/data/countries/no.zone',
    '13': 'https://www.ipdeny.com/ipblocks/data/countries/ro.zone',
    '14': 'https://www.ipdeny.com/ipblocks/data/countries/es.zone',
    '15': 'https://www.ipdeny.com/ipblocks/data/countries/tr.zone',
    '16': 'https://www.ipdeny.com/ipblocks/data/countries/ua.zone',
    '17': 'https://www.ipdeny.com/ipblocks/data/countries/gb.zone',
    '18': 'https://www.ipdeny.com/ipblocks/data/countries/us.zone',
    '19': 'https://www.ipdeny.com/ipblocks/data/countries/ve.zone',
    '20': 'https://www.ipdeny.com/ipblocks/data/countries/ye.zone',
}

class UltraFastScanner:
    def __init__(self, port, max_concurrent=1000, timeout=1.5):
        self.port = port
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.open_ips = []
        self.total_ips = 0
        self.scanned = 0
        self.open_count = 0
        self.closed_count = 0
        self.error_count = 0
        self.start_time = None
        self.lock = asyncio.Lock()
        self.output_file = "open.txt"
        self.service_name = "RDP" if port == 3389 else "SSH"
        
        with open(self.output_file, 'w') as f:
            f.write(f"# {self.service_name} Open Ports Scanner Results\n")
            f.write(f"# Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Port: {self.port}\n")
            f.write(f"{'='*60}\n\n")
    
    async def check_port(self, ip):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), self.port),
                timeout=self.timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            
            async with self.lock:
                self.open_count += 1
                self.open_ips.append(str(ip))
                with open(self.output_file, 'a') as f:
                    f.write(f"{ip}\n")
            return True
        except:
            async with self.lock:
                self.closed_count += 1
            return False
    
    async def worker(self, ip_queue, semaphore):
        while True:
            try:
                ip = await ip_queue.get()
            except asyncio.QueueEmpty:
                break
            
            async with semaphore:
                await self.check_port(ip)
            
            async with self.lock:
                self.scanned += 1
            
            ip_queue.task_done()
    
    async def live_stats(self):
        while self.scanned < self.total_ips:
            await asyncio.sleep(0.5)
            
            async with self.lock:
                elapsed = time.time() - self.start_time
                if elapsed == 0:
                    elapsed = 0.001
                progress = (self.scanned / self.total_ips * 100) if self.total_ips > 0 else 0
                speed = self.scanned / elapsed if elapsed > 0 else 0
                remaining = (self.total_ips - self.scanned) / speed if speed > 0 else 0
                
                line = (
                    f"{CYAN}[*]{RESET} "
                    f"Scanned: {self.scanned}/{self.total_ips} ({progress:.1f}%) | "
                    f"{GREEN}Open: {self.open_count}{RESET} | "
                    f"{RED}Closed: {self.closed_count}{RESET} | "
                    f"{MAGENTA}Speed: {speed:.0f} IP/s{RESET} | "
                    f"ETA: {remaining:.0f}s"
                )
                
                sys.stdout.write(f"\r\033[K{line}")
                sys.stdout.flush()
        
        sys.stdout.write(f"\r\033[K")
        sys.stdout.flush()
    
    def download_ranges(self, url):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
                return [line.strip() for line in data.split('\n') if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{RED}[-] Error downloading: {e}{RESET}")
            return None
    
    def load_ranges_from_file(self, filename):
        try:
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{RED}[-] Error reading file: {e}{RESET}")
            return None
    
    async def scan_ranges(self, ranges):
        print(f"\n{YELLOW}{'='*65}{RESET}")
        print(f"{YELLOW}  ULTRA-FAST {self.service_name} SCANNER{RESET}")
        print(f"{YELLOW}{'='*65}{RESET}")
        print(f"{CYAN}[*] Port: {self.port} ({self.service_name}){RESET}")
        print(f"{CYAN}[*] Max Concurrent: {self.max_concurrent}{RESET}")
        print(f"{CYAN}[*] Timeout: {self.timeout}s{RESET}")
        print(f"{YELLOW}{'='*65}{RESET}\n")
        
        print(f"{CYAN}[*] Loading IP ranges...{RESET}")
        all_ips = set()
        total_ranges = len(ranges)
        
        for idx, cidr in enumerate(ranges, 1):
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                ips = list(network.hosts())
                all_ips.update(ips)
                
                if idx <= 5:
                    print(f"    {WHITE}{cidr} -> {len(ips)} IPs{RESET}")
            except:
                pass
        
        if total_ranges > 5:
            print(f"    {WHITE}... and {total_ranges - 5} more ranges{RESET}")
        
        self.total_ips = len(all_ips)
        
        if self.total_ips == 0:
            print(f"{RED}[-] No valid IPs found!{RESET}")
            return
        
        print(f"\n{GREEN}[+] Total: {total_ranges} ranges -> {self.total_ips} unique IPs{RESET}")
        print(f"{GREEN}[+] Results saved to: {os.path.abspath(self.output_file)}{RESET}")
        print(f"\n{YELLOW}[*] Starting scan...{RESET}\n")
        
        ip_queue = asyncio.Queue()
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        for ip in all_ips:
            await ip_queue.put(ip)
        
        self.start_time = time.time()
        
        stats_task = asyncio.create_task(self.live_stats())
        
        num_workers = min(100, self.total_ips)
        workers = []
        
        for _ in range(num_workers):
            task = asyncio.create_task(self.worker(ip_queue, semaphore))
            workers.append(task)
        
        await ip_queue.join()
        
        for w in workers:
            w.cancel()
        
        await asyncio.gather(*workers, return_exceptions=True)
        
        stats_task.cancel()
        try:
            await stats_task
        except:
            pass
        
        elapsed = time.time() - self.start_time
        
        print(f"\n{YELLOW}{'='*65}{RESET}")
        print(f"{YELLOW}  SCAN COMPLETED!{RESET}")
        print(f"{YELLOW}{'='*65}{RESET}")
        print(f"{CYAN}[*] Total Scanned: {self.scanned} IPs{RESET}")
        print(f"{GREEN}[+] Open Ports: {self.open_count}{RESET}")
        print(f"{RED}[-] Closed Ports: {self.closed_count}{RESET}")
        print(f"{MAGENTA}[*] Duration: {elapsed:.2f} seconds{RESET}")
        print(f"{MAGENTA}[*] Speed: {self.scanned/elapsed:.0f} IPs/second{RESET}")
        
        if self.open_count > 0:
            print(f"\n{GREEN}[+] Results saved to: {WHITE}{self.output_file}{RESET}")
            print(f"{GREEN}[+] Open IPs ({self.open_count}):{RESET}")
            display_ips = sorted(self.open_ips, key=lambda x: ipaddress.ip_address(x))[:20]
            for ip in display_ips:
                print(f"    {WHITE}{ip}{RESET}")
            if self.open_count > 20:
                print(f"    {WHITE}... and {self.open_count - 20} more{RESET}")
        else:
            print(f"\n{RED}[-] No open ports found!{RESET}")
        
        print(f"\n{YELLOW}{'='*65}{RESET}")
        print(f"{GREEN}  Output file: {os.path.abspath(self.output_file)}{RESET}")
        print(f"{YELLOW}{'='*65}{RESET}\n")

async def main():
    BANNER = f"""
    {RED}██╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
    {RED}██║██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
    {RED}██║██████╔╝███████╗██║     ███████║██╔██╗ ██║
    {RED}██║██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
    {RED}██║██║     ███████║╚██████╗██║  ██║██║ ╚████║
    {RED}╚═╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    {RESET}
    {GREEN}              IPSCAN v3.0 - Fast Port Scanner{RESET}
    {YELLOW}                      Coded by: S1A7ASH{RESET}
    {CYAN}                 github.com/+=Soon | t.me/BLACKCAT_TM{RESET}
    """
    print(BANNER)
    print(f"{YELLOW}[?] Select option:{RESET}\n")
    print(f"{CYAN}[0] {WHITE}Load from file (local IP ranges file){RESET}")
    print(f"{CYAN}[1] {WHITE}BAHRAIN (BH){RESET}")
    print(f"{CYAN}[2] {WHITE}CHINA (CN){RESET}")
    print(f"{CYAN}[3] {WHITE}FRANCE (FR){RESET}")
    print(f"{CYAN}[4] {WHITE}GERMANY (DE){RESET}")
    print(f"{CYAN}[5] {WHITE}HONG KONG (HK){RESET}")
    print(f"{CYAN}[6] {WHITE}INDIA (IN){RESET}")
    print(f"{CYAN}[7] {WHITE}IRAN (IR){RESET}")
    print(f"{CYAN}[8] {WHITE}IRAQ (IQ){RESET}")
    print(f"{CYAN}[9] {WHITE}ISRAEL (IL){RESET}")
    print(f"{CYAN}[10] {WHITE}JAPAN (JP){RESET}")
    print(f"{CYAN}[11] {WHITE}NIGERIA (NG){RESET}")
    print(f"{CYAN}[12] {WHITE}NORWAY (NO){RESET}")
    print(f"{CYAN}[13] {WHITE}ROMANIA (RO){RESET}")
    print(f"{CYAN}[14] {WHITE}SPAIN (ES){RESET}")
    print(f"{CYAN}[15] {WHITE}TURKEY (TR){RESET}")
    print(f"{CYAN}[16] {WHITE}UKRAINE (UA){RESET}")
    print(f"{CYAN}[17] {WHITE}UNITED KINGDOM (GB){RESET}")
    print(f"{CYAN}[18] {WHITE}USA (US){RESET}")
    print(f"{CYAN}[19] {WHITE}VENEZUELA (VE){RESET}")
    print(f"{CYAN}[20] {WHITE}YEMEN (YE){RESET}")
    
    ranges = None
    
    while True:
        choice = input(f"\n{YELLOW}[?] Enter choice (0-20): {WHITE}").strip()
        
        if choice == '0':
            filename = input(f"{YELLOW}[?] Enter IP ranges file path: {WHITE}").strip()
            if not os.path.exists(filename):
                print(f"{RED}[-] File not found!{RESET}\n")
                continue
            temp_scanner = UltraFastScanner(port=3389)
            ranges = temp_scanner.load_ranges_from_file(filename)
            if ranges:
                print(f"{GREEN}[+] Loaded {len(ranges)} IP ranges from file{RESET}")
            break
            
        elif choice in COUNTRY_URLS:
            print(f"\n{CYAN}[*] Downloading IP ranges...{RESET}")
            url = COUNTRY_URLS[choice]
            temp_scanner = UltraFastScanner(port=3389)
            ranges = temp_scanner.download_ranges(url)
            if ranges:
                print(f"{GREEN}[+] Downloaded {len(ranges)} IP ranges{RESET}")
            break
        else:
            print(f"{RED}[-] Invalid choice! Please enter 0-20{RESET}\n")
    
    if not ranges:
        print(f"{RED}[-] Failed to get IP ranges!{RESET}")
        return
    
    print(f"\n{CYAN}[1] RDP (Port 3389){RESET}")
    print(f"{CYAN}[2] SSH (Port 22){RESET}")
    print(f"{CYAN}[3] Custom Port{RESET}")
    
    while True:
        port_choice = input(f"\n{YELLOW}[?] Select option (1-3): {WHITE}").strip()
        if port_choice == '1':
            port = 3389
            break
        elif port_choice == '2':
            port = 22
            break
        elif port_choice == '3':
            try:
                port = int(input(f"{YELLOW}[?] Enter port number: {WHITE}").strip())
                if 1 <= port <= 65535:
                    break
                else:
                    print(f"{RED}[-] Port must be between 1-65535!{RESET}\n")
            except ValueError:
                print(f"{RED}[-] Invalid port number!{RESET}\n")
        else:
            print(f"{RED}[-] Invalid choice!{RESET}\n")
    
    print()
    
    while True:
        try:
            threads = int(input(f"{YELLOW}[?] Number of concurrent connections (100-2000): {WHITE}").strip())
            if 100 <= threads <= 2000:
                break
            else:
                print(f"{RED}[-] Please enter a number between 100-2000!{RESET}\n")
        except ValueError:
            print(f"{RED}[-] Invalid number!{RESET}\n")
    
    print()
    
    service_name = "RDP" if port == 3389 else "SSH"
    print(f"{CYAN}{'-'*65}{RESET}")
    print(f"{CYAN}  Scan Configuration:{RESET}")
    print(f"{CYAN}  Port: {WHITE}{port} ({service_name}){RESET}")
    print(f"{CYAN}  Threads: {WHITE}{threads}{RESET}")
    print(f"{CYAN}  Ranges loaded: {WHITE}{len(ranges)}{RESET}")
    print(f"{CYAN}{'-'*65}{RESET}")
    
    confirm = input(f"\n{YELLOW}[?] Start scan? (y/n): {WHITE}").strip().lower()
    
    if confirm != 'y':
        print(f"{RED}[-] Scan cancelled!{RESET}")
        return
    
    scanner = UltraFastScanner(port=port, max_concurrent=threads, timeout=1.5)
    await scanner.scan_ranges(ranges)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[!] Scan interrupted by user!{RESET}")
        print(f"{CYAN}[*] Open IPs saved to open.txt{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[-] Error: {e}{RESET}")
        sys.exit(1)