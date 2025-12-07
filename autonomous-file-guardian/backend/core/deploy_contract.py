"""
Deploy FileGuardian smart contract to Ganache
Run: python deploy_contract.py
"""

import json
from web3 import Web3 # type: ignore
from solcx import compile_source, install_solc # type: ignore
import os
from pathlib import Path

install_solc('0.8.0')

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))

if not w3.is_connected():
    raise Exception("Failed to connect to Ganache. Make sure it's running on port 8545")

print(f"✅ Connected to Ganache")
print(f"📊 Chain ID: {w3.eth.chain_id}")


accounts = w3.eth.accounts
print(f"🔑 Available accounts: {len(accounts)}")
print(f"💰 Deployer account: {accounts[0]}")
print(f"💰 Balance: {w3.eth.get_balance(accounts[0]) / 10**18} ETH")


contract_path = Path(__file__).parent / 'FileGuardian.sol'
with open(contract_path, 'r') as f:
    contract_source = f.read()


print("\n🔨 Compiling contract...")
compiled_sol = compile_source(
    contract_source,
    output_values=['abi', 'bin'],
    solc_version='0.8.0' # Specify version to avoid potential issues
)


contract_id, contract_interface = compiled_sol.popitem()
bytecode = contract_interface['bin']
abi = contract_interface['abi']


print("🚀 Deploying contract...")
FileGuardian = w3.eth.contract(abi=abi, bytecode=bytecode)


tx_hash = FileGuardian.constructor().transact({
    'from': accounts[0],
    'gas': 5000000
})


tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
contract_address = tx_receipt.contractAddress

print(f"\n✅ Contract deployed successfully!")
print(f"📍 Contract address: {contract_address}")
print(f"⛽ Gas used: {tx_receipt.gasUsed}")


contract_data = {
    'address': contract_address,
    'abi': abi,
    'deployer': accounts[0],
    'network': 'ganache',
    'chain_id': w3.eth.chain_id
}


output_dir = Path(__file__).parent / 'blockchain_data'
output_dir.mkdir(exist_ok=True)

with open(output_dir / 'contract.json', 'w') as f:
    json.dump(contract_data, f, indent=2)

print(f"\n💾 Contract data saved to: {output_dir / 'contract.json'}")


env_path = Path(__file__).parent.parent / '.env'


existing_content = ""
if env_path.exists():
    with open(env_path, 'r') as f:
        lines = f.readlines()
        
        for line in lines:
            if not (line.strip().startswith('BLOCKCHAIN_PROVIDER_URL=') or \
                    line.strip().startswith('BLOCKCHAIN_PRIVATE_KEY=') or \
                    line.strip().startswith('CONTRACT_ADDRESS=') or \
                    line.strip().startswith('BLOCKCHAIN_NETWORK=')):
                existing_content += line


if existing_content and not existing_content.endswith('\n'):
    existing_content += '\n'

new_content = f"""
# Blockchain Configuration
BLOCKCHAIN_PROVIDER_URL=http://127.0.0.1:8545
BLOCKCHAIN_PRIVATE_KEY={accounts[0]}
CONTRACT_ADDRESS={contract_address}
BLOCKCHAIN_NETWORK=ganache
"""


with open(env_path, 'w') as f:
    f.write(existing_content.strip() + new_content.strip())

print(f"✅ Environment file updated: {env_path}")


print("\n🧪 Testing contract...")
contract = w3.eth.contract(address=contract_address, abi=abi)


test_hash = "0x" + "a" * 64
metadata = json.dumps({"name": "test.txt", "size": 1024})
test_ipfs_cid = "QmPlaceholderCidForTest12345" # Added placeholder CID

tx_hash = contract.functions.registerFile(
    test_hash, 
    metadata, 
    test_ipfs_cid  # Pass the new argument
).transact({
    'from': accounts[0]
})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)


print(f"✅ Test file registered - Gas used: {tx_receipt.gasUsed}")


file_count = contract.functions.fileCount().call()
print(f"📁 Total files on blockchain: {file_count}")

print("\n" + "="*60)
print("🎉 DEPLOYMENT COMPLETE!")
print("="*60)
print("\nNext steps:")
print("1. Update your blockchain-viewer.html with the new ABI and Address")
print("   (Address: " + contract_address + ")")
print("2. Run: python manage.py migrate (if you changed models.py)")
print("3. Start your application: python manage.py runserver")
print("\nContract Address:", contract_address)
print("="*60)