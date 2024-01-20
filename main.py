import hmac
import hashlib

from embit.liquid.addresses import address as liquid_address
from embit.liquid.networks import NETWORKS
from embit.ec import PrivateKey
from embit.descriptor import Descriptor


# Your wallet descriptor
desc_segwit = "wpkh([e735329e/84'/0'/0']xpub6CKejrPcekTUiTgAA6fH9iiQHSiCV4zyqcdFcbeHw8muGSwjv1dqmar3EK6mFv59nkYBaTtEFanQecokpacCjUVeGixpr46WmzvWMiEGHhr/0/*)#rseyw2cw"

# Parse the descriptor to get the scriptPubKey
descriptor = Descriptor.from_string(desc_segwit)
script_pubkey = descriptor.script_pubkey()

# Your master blinding key in hex
master_blinding_key_hex = "b857dcc8ef935e82b81f71fe157ecbf2f8885ce7278d9a82a20f45dde84cb3d6"

# Convert hex to bytes and create a PrivateKey object
master_blinding_key = PrivateKey(bytes.fromhex(master_blinding_key_hex))

# Generate the blinded address
network = NETWORKS["liquidv1"]  # Use the appropriate network
blinded_address = liquid_address(script_pubkey, master_blinding_key, network)

print(blinded_address)

key = master_blinding_key.secret

blinded_addresses = []
for i in range(3):
	derived_descriptor = descriptor.derive(i)
	script_pubkey = derived_descriptor.script_pubkey()
	blinding_key_hex = hmac.new(key, script_pubkey.data, hashlib.sha256).hexdigest()
	blinding_key = PrivateKey(bytes.fromhex(blinding_key_hex))
	blinded_address = liquid_address(script_pubkey, blinding_key, network)
	blinded_addresses.append({blinded_address, blinding_key_hex})
	

for address,bkey in blinded_addresses:
	print(f"Address: {address}")
	print(f"Blinding Key: {bkey}")
	