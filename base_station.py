from flask import Flask, request, jsonify
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, SHAKE128
from Crypto.Cipher import ChaCha20
from Crypto.Protocol import DH
import base64
import uuid


app = Flask(__name__)

# Almacenamiento provisorio de datos
recieved_data = {}
sensors_keys = {}


# Generación de llaves
priv_key = ECC.generate(curve="P-256")
pub_key = priv_key.public_key().export_key(format="PEM")


# Métodos get

@app.route('/data', methods = ['GET'])
def get_data():
    response = jsonify(recieved_data)
    return response

@app.route('/', methods=['GET'])
def test():
		response = 'The best sensor Criptosystem right here!'
		return response

@app.route('/get-public-key', methods = ['GET'])
def get_public_key():
    return jsonify({"public_key": pub_key}), 200


# Métodos POST para recibir datos y llaves

@app.route('/register-key', methods = ['POST'])
def register_key():
    try:
        data = request.json
        sensor_public_key = data.get('public_key')
        if not sensor_public_key:
            return jsonify({"status": "error", "message": "No se recibió una clave pública"}), 400
        sensor_id = str(uuid.uuid4())
        sensors_keys[sensor_id] = sensor_public_key
        return jsonify({"status": "success", "message": "Clave registrada", "sensor_id": sensor_id}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route('/receive-data', methods = ['POST'])
def receive_data():

    try:   
        
        data = request.json
        sensor_id = data.get('sensor_id')
        encrypted = base64.b64decode(data.get('message')) # Encriptación del mensaje
        signature = bytes.fromhex(data.get('signature')) # Firma del Hash de la encriptación del mensaje
        nonce = base64.b64decode(data.get('nonce'))

        # 1 Verificación de la firma

        if sensor_id not in sensors_keys:
            return jsonify({"status": "error", "message": "Sensor no registrado"}), 400
        

        sensor_public_key = ECC.import_key(sensors_keys[sensor_id])
        hash = SHA256.new(encrypted)   # Hash de la encriptación del mensaje

        print(encrypted)

        verifier = DSS.new(sensor_public_key, "fips-186-3")
        verifier.verify(hash, signature) # Verificación del Hash de la encriptación del mensaje con la firma del Hash de la encriptación del mensaje
        
        # Deriva clave compartida
        shared_secret = DH.key_agreement(static_priv = priv_key, static_pub = sensor_public_key, kdf = lambda x : SHAKE128.new(x).read(32))
        shared_secret_hash = SHA256.new(shared_secret).digest()
        print(f"Clave compartida sensor {sensor_id} derivada con éxito.")

        cipher = ChaCha20.new(key = shared_secret_hash, nonce = nonce)
        decrypted = cipher.decrypt(encrypted)

        if sensor_id not in recieved_data:
            recieved_data[sensor_id] = []


        m = decrypted.decode("utf-8").split(';')

        recieved_data[sensor_id].append({
            "temperature": m[1],
            "timestamp": m[2]
        })

        print(f"Mensaje recibido y descifrado: {decrypted.decode('utf-8')}")
        return jsonify({"status": "success", "message": "Datos recibidos correctamente"}), 200
    
    except ValueError:
        return jsonify({"status": "error", "message": "Firma o datos inválidos"}), 400
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)