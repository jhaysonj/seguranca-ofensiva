import base64

"""
 
Example
python3 hash_pbkdf2$50000$50_decrypt.py

Digite o número de iterações: 50000
Digite o salt em hexadecimal: 8bf3e3452b78544f8bee9400d6936d34
Digite o hash em hexadecimal: e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56

Bash example:
sqlite3 file.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes 

"""

def hex_to_base64(hex_string):
    """Converte uma string hexadecimal para Base64."""
    return base64.b64encode(bytes.fromhex(hex_string)).decode('utf-8')

# read input values
iterations = input("Digite o número de iterações: ")
hex_salt = input("Digite o salt em hexadecimal: ")
hex_hash = input("Digite o hash em hexadecimal: ")

# Convert salt and hash to Base64
base64_salt = hex_to_base64(hex_salt)
base64_hash = hex_to_base64(hex_hash)

# show the formation results
formatted_string = f"sha256:{iterations}:{base64_salt}:{base64_hash}"
print("String formatada:", formatted_string)
