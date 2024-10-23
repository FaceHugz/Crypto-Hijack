import asyncio
import aiohttp
import random
import time
import logging
import os
import string
from bitcoinlib.wallets import Wallet
from eth_keys import keys
from eth_utils import decode_hex
from threading import Lock
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from dotenv import load_dotenv
import signal
from tenacity import retry, wait_exponential, stop_after_attempt


load_dotenv()


API_KEYS = {
    'blockcypher': os.getenv(""),  
}


from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler('wallet_scanner.log', maxBytes=5 * 1024 * 1024, backupCount=5)
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)


ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)


file_lock = Lock()


conn = sqlite3.connect('wallets.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS wallets (
        currency TEXT,
        address TEXT UNIQUE,
        private_key TEXT,
        balance REAL
    )
''')
conn.commit()


def handle_exit(sig, frame):
    logging.info("Terminating the script gracefully...")
    conn.close()
    exit(0)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)


def validate_private_key(private_key):
    return len(private_key) == 64 and all(c in '0123456789abcdef' for c in private_key)


def generate_wallet():
    try:
        btc_wallet = Wallet.create('Temporary Bitcoin Wallet')
        btc_private_key = btc_wallet.get_key().private_hex
        btc_address = btc_wallet.get_key().address

        eth_private_key = ''.join([random.choice('0123456789abcdef') for _ in range(64)])
        eth_private_key_bytes = decode_hex(eth_private_key)
        eth_key = keys.PrivateKey(eth_private_key_bytes)
        eth_address = eth_key.public_key.to_checksum_address()

        return {
            'btc': {'private_key': btc_private_key, 'address': btc_address},
            'eth': {'private_key': eth_private_key, 'address': eth_address}
        }
    except Exception as e:
        logging.error(f"Error generating wallet: {e}")
        return None


@retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(3))
async def check_balance(session, address, currency='btc'):
    if currency == 'btc':
        url = f"https://api.coingeek.com/address/{address}/balance?key={API_KEYS['coingeek']}"
    elif currency == 'eth':
        url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={API_KEYS['etherscan']}"

    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                data = await response.json()
                balance = float(data.get('balance', 0)) if currency == 'eth' else float(data.get('confirmed', 0)) / (10**8)
                if balance > 0:
                    return balance
    except Exception as e:
        logging.error(f"Error checking balance for {currency.upper()} address {address}: {e}")
    
    return 0


def encrypt_private_key(private_key):
    return cipher_suite.encrypt(private_key.encode()).decode()


def save_wallet_to_db(wallet_info):
    with file_lock:
        try:
            encrypted_key = encrypt_private_key(wallet_info['private_key'])
            cursor.execute('''
                INSERT OR REPLACE INTO wallets (currency, address, private_key, balance)
                VALUES (?, ?, ?, ?)
            ''', (wallet_info['currency'], wallet_info['address'], encrypted_key, wallet_info['balance']))
            conn.commit()
            logging.info(f"Wallet saved: {wallet_info['address']} with balance {wallet_info['balance']} {wallet_info['currency']}")
        except sqlite3.Error as e:
            logging.error(f"Error saving wallet to database: {e}")


def brute_force_wallet(target_address, max_attempts=1000000):
    chars = string.ascii_letters + string.digits
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(generate_and_check_wallet, target_address, chars) for _ in range(max_attempts)]
        for future in futures:
            result = future.result()
            if result:
                return result
    return None

def generate_and_check_wallet(target_address, chars):
    private_key = ''.join(random.choice(chars) for _ in range(64))
    wallet = generate_wallet_from_private_key(private_key)
    if wallet:
        if wallet['btc']['address'] == target_address or wallet['eth']['address'].lower() == target_address.lower():
            return wallet
    return None


def generate_wallet_from_private_key(private_key):
    if not validate_private_key(private_key):
        return None
    try:
        btc_wallet = Wallet.create('Temporary Bitcoin Wallet', keys=private_key)
        btc_address = btc_wallet.get_key().address

        eth_private_key_bytes = decode_hex(private_key)
        eth_key = keys.PrivateKey(eth_private_key_bytes)
        eth_address = eth_key.public_key.to_checksum_address()

        return {
            'btc': {'private_key': private_key, 'address': btc_address},
            'eth': {'private_key': private_key, 'address': eth_address}
        }
    except Exception as e:
        logging.error(f"Error generating wallet from private key: {e}")
        return None

async def scan_wallets(num_wallets=100):
    wallets = [generate_wallet() for _ in range(num_wallets)]
    wallets = [w for w in wallets if w] 

    async with aiohttp.ClientSession() as session:
        tasks = []
        for wallet in wallets:
            tasks.append(check_balance(session, wallet['btc']['address'], 'btc'))
            tasks.append(check_balance(session, wallet['eth']['address'], 'eth'))
        
        results = await asyncio.gather(*tasks)
        
        found_wallets = []
        for idx, wallet in enumerate(wallets):
            btc_balance = results[2 * idx]
            eth_balance = results[2 * idx + 1]
            if btc_balance > 0:
                wallet['btc']['balance'] = btc_balance
                found_wallets.append(wallet['btc'])
            if eth_balance > 0:
                wallet['eth']['balance'] = eth_balance
                found_wallets.append(wallet['eth'])
                
        return found_wallets

def main():
    try:
        while True:
            loop = asyncio.get_event_loop()
            found_wallets = loop.run_until_complete(scan_wallets())

            for wallet_info in found_wallets:
                wallet_info['currency'] = 'BTC' if len(wallet_info['address']) == 34 else 'ETH'
                print(f"Found {wallet_info['currency']} wallet with balance: {wallet_info['address']}")
                save_wallet_to_db(wallet_info)

                brute_forced_wallet = brute_force_wallet(wallet_info['address'])
                if brute_forced_wallet:
                    logging.info(f"Successfully brute-forced wallet: {wallet_info['address']}")
                    save_wallet_to_db(brute_forced_wallet[wallet_info['currency'].lower()])
            
            sleep_duration = random.randint(60, 300)
            logging.info(f"Sleeping for {sleep_duration} seconds before the next scan.")
            time.sleep(sleep_duration)
    except KeyboardInterrupt:
        logging.info("Script terminated by user.")
    except Exception as e:
        logging.error(f"Unexpected error in main loop: {e}")

if __name__ == "__main__":
    main()
