import time
import requests
import random
import os
import base64
import datetime

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, SHAKE128
from Crypto.Cipher import ChaCha20
from Crypto.Protocol import DH

host = "http://localhost:5000"

#---Generación de llaves de curva elíptica

#privada
private_key = ECC.generate(curve='P-256')
with open("private_key.pem", "wt") as f:
    f.write(private_key.export_key(format="PEM"))

#pública
public_key = private_key.public_key()
with open("public_key.pem", "wt") as f:
    f.write(public_key.export_key(format="PEM"))

sensor_id = 0

#---Este es el envío de la llave pública al servidor. Es un poco incorrecto hacerlo de esta forma.

response = requests.post(
    host + "/register-key",
    json={"public_key": public_key.export_key(format="PEM")}
)
data = response.json()
print(data)
sensor_id = data['sensor_id']

# Obtener la clave pública de la base station
key_response = requests.get(f"{host}/get-public-key")
base_station_public_key = ECC.import_key(key_response.json()["public_key"])
print("Clave pública de la base station recibida.")

# Deriva clave compartida con la base station
shared_secret = DH.key_agreement(static_priv=private_key, static_pub=base_station_public_key, kdf=lambda x:SHAKE128.new(x).read(32))
shared_secret_hash = SHA256.new(shared_secret).digest()
print("Clave compartida derivada con éxito.")

# Firmador de mensajes
signer = DSS.new(private_key, 'fips-186-3')


# Loop para enviar mensaje cada x tiempo [s]

x = 30
while True:

    # Mensaje 

    message = f'Temperatura;{random.uniform(0, 40)};{datetime.datetime.now()}'
    message = bytes(message, 'utf8')

    # Encriptación del mensaje
    nonce = os.urandom(12)
    cipher = ChaCha20.new(key = shared_secret_hash, nonce = nonce)
    ciphertext = cipher.encrypt(message)
    
    # Hash de la encriptación del mensaje
    hash = SHA256.new(ciphertext)

    # Firma del Hash de la encriptación del mensaje
    signature = signer.sign(hash)


    ciphertext = base64.b64encode(ciphertext)
    response = requests.post(
        f"{host}/receive-data",
        json={"sensor_id": str(sensor_id),
              "message": ciphertext.decode(),                    # Envía mensaje encriptado
              "signature": signature.hex(),                      # Envía firma del hash de la encriptación del mensajje
              "nonce": base64.b64encode(nonce).decode("utf-8")
        }
    )
    data = response.json()
    print(data)
    print(response.text)
    time.sleep(x)