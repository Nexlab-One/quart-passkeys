from quart import Quart, render_template, request, jsonify
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.utils import random
from nacl.secret import SecretBox

app = Quart(__name__)

# In-memory storage for user credentials and encrypted data
users = {}
encrypted_keys = {}

# Constants
RP_ID = "localhost"
RP_NAME = "SimpleWebAuthn Example"

@app.route('/')
async def index():
    return await render_template('index.html')

@app.route('/register', methods=['POST'])
async def register():
    data = await request.json
    username = data['username']
    prf_result = base64.urlsafe_b64decode(data['prfResult'] + '==')
    
    if username in users:
        return jsonify({'error': 'User already exists'}), 400
    
    challenge = os.urandom(32)
    user_id = os.urandom(32)
    
    # Generate a new symmetric key for the user
    symmetric_key = random(SecretBox.KEY_SIZE)
    
    # Derive encryption key from PRF result
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SecretBox.KEY_SIZE,
        salt=b'',
        info=b'key encryption key'
    )
    key_encryption_key = hkdf.derive(prf_result)
    
    # Encrypt the symmetric key
    box = SecretBox(key_encryption_key)
    encrypted_key = box.encrypt(symmetric_key)
    
    users[username] = {
        'id': user_id,
        'challenge': challenge,
        'credentials': []
    }
    encrypted_keys[username] = encrypted_key
    
    return jsonify({'status': 'success'})

@app.route('/register/options', methods=['POST'])
async def register_options():
    data = await request.json
    username = data['username']
    
    if username in users:
        return jsonify({'error': 'User already exists'}), 400
    
    challenge = os.urandom(32)
    user_id = os.urandom(32)
    
    options = {
        'challenge': base64.urlsafe_b64encode(challenge).decode('ascii').rstrip('='),
        'rp': {'name': RP_NAME, 'id': RP_ID},
        'user': {
            'id': base64.urlsafe_b64encode(user_id).decode('ascii').rstrip('='),
            'name': username,
            'displayName': username
        },
        'pubKeyCredParams': [
            {'alg': -8, 'type': 'public-key'},
            {'alg': -7, 'type': 'public-key'},
            {'alg': -257, 'type': 'public-key'}
        ],
        'authenticatorSelection': {'userVerification': 'required'},
        'extensions': {'prf': {'eval': {'first': base64.urlsafe_b64encode(bytes([1]*32)).decode('ascii').rstrip('=')}}}
    }
    
    return jsonify(options)

@app.route('/authenticate', methods=['POST'])
async def authenticate():
    data = await request.json
    username = data['username']
    
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    challenge = os.urandom(32)
    users[username]['challenge'] = challenge
    
    options = {
        'challenge': base64.urlsafe_b64encode(challenge).decode('ascii').rstrip('='),
        'rpId': RP_ID,
        'allowCredentials': [
            {
                'type': 'public-key',
                'id': base64.urlsafe_b64encode(cred['id']).decode('ascii').rstrip('=')
            } for cred in users[username]['credentials']
        ],
        'userVerification': 'required',
        'extensions': {'prf': {'eval': {'first': base64.urlsafe_b64encode(bytes([1]*32)).decode('ascii').rstrip('=')}}}
    }
    
    return jsonify(options)

@app.route('/authenticate/complete', methods=['POST'])
async def authenticate_complete():
    data = await request.json
    username = data['username']
    prf_result = base64.urlsafe_b64decode(data['prfResult'] + '==')
    
    if username not in users or username not in encrypted_keys:
        return jsonify({'error': 'User or encrypted key not found'}), 404
    
    # Derive encryption key from PRF result
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SecretBox.KEY_SIZE,
        salt=b'',
        info=b'key encryption key'
    )
    key_encryption_key = hkdf.derive(prf_result)
    
    # Decrypt the symmetric key
    box = SecretBox(key_encryption_key)
    try:
        decrypted_key = box.decrypt(encrypted_keys[username])
        return jsonify({'status': 'success', 'message': 'Authentication successful and symmetric key decrypted'})
    except:
        return jsonify({'status': 'error', 'message': 'Failed to decrypt symmetric key'})

@app.route('/remove_passkey', methods=['POST'])
async def remove_passkey():
    data = await request.json
    username = data['username']
    credential_id = data['credentialId']
    
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    # Find and remove the credential
    users[username]['credentials'] = [cred for cred in users[username]['credentials'] if cred['id'] != credential_id]
    
    return jsonify({'status': 'success', 'message': 'Passkey removed successfully'})

@app.route('/get_passkeys', methods=['POST'])
async def get_passkeys():
    data = await request.json
    username = data['username']
    
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    passkeys = [{'id': cred['id']} for cred in users[username]['credentials']]
    return jsonify({'passkeys': passkeys})

@app.route('/exclude_credential', methods=['POST'])
async def exclude_credential():
    data = await request.json
    username = data['username']
    credential_id = data['credentialId']
    
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    challenge = os.urandom(32)
    
    options = {
        'challenge': base64.urlsafe_b64encode(challenge).decode('ascii').rstrip('='),
        'rp': {'name': RP_NAME, 'id': RP_ID},
        'user': {
            'id': base64.urlsafe_b64encode(users[username]['id']).decode('ascii').rstrip('='),
            'name': username,
            'displayName': username
        },
        'pubKeyCredParams': [
            {'alg': -8, 'type': 'public-key'},
            {'alg': -7, 'type': 'public-key'},
            {'alg': -257, 'type': 'public-key'}
        ],
        'excludeCredentials': [{
            'type': 'public-key',
            'id': credential_id
        }],
        'authenticatorSelection': {'userVerification': 'required'},
        'attestation': 'none'
    }
    
    return jsonify(options)

if __name__ == '__main__':
    app.run(debug=True)