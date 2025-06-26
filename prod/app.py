from flask import Flask, request, send_file, render_template, url_for
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

app = Flask(__name__)

# ------------------ Ensure required folders exist ------------------
os.makedirs("keys", exist_ok=True)
os.makedirs("uploads", exist_ok=True)
os.makedirs("encrypted_files", exist_ok=True)
os.makedirs("encrypted_keys", exist_ok=True)

# ------------------ RSA Key Management ------------------
def load_or_generate_keys():
    private_key_path = os.path.join("keys", "server_private_key.pem")
    public_key_path = os.path.join("keys", "server_public_key.pem")

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"MyStrongPassword")
        )
        with open(private_key_path, "wb") as f:
            f.write(private_pem)

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, "wb") as f:
            f.write(public_pem)
    else:
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

    return public_key

# Load public key on startup
public_key = load_or_generate_keys()

# ------------------ AES Encryption ------------------
def encrypt_file_with_password(file_data, password):
    key = password.encode('utf-8').ljust(32, b'\0')[:32]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    return iv + ciphertext

# ------------------ RSA Encryption of Password ------------------
def encrypt_password_with_rsa(password):
    encrypted_password = public_key.encrypt(
        password.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_password

# ------------------ Flask Routes ------------------

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/sender')
def sender():
    return render_template('index.html')

@app.route('/receiver')
def receiver():
    return render_template('decrypt.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    file = request.files['file']
    password = request.form['password']
    file_data = file.read()

    upload_path = os.path.join("uploads", file.filename)
    with open(upload_path, "wb") as f:
        f.write(file_data)

    encrypted_file_data = encrypt_file_with_password(file_data, password)
    encrypted_password = encrypt_password_with_rsa(password)

    encrypted_file_path = os.path.join("encrypted_files", f"encrypted_{file.filename}")
    encrypted_password_path = os.path.join("encrypted_keys", f"{file.filename}_password.bin")

    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_file_data)
    with open(encrypted_password_path, "wb") as f:
        f.write(encrypted_password)

    return f'''
        <h3>Encryption Complete</h3>
        <a href="/download/{encrypted_file_path}">Download Encrypted File</a><br>
        <a href="/download/{encrypted_password_path}">Download Encrypted Password</a>
    '''

@app.route('/download/<path:filename>')
def download(filename):
    return send_file(filename, as_attachment=True)

# ------------------ RSA Decryption ------------------
def load_private_key():
    private_key_path = os.path.join("keys", "server_private_key.pem")
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=b"MyStrongPassword")
    return private_key

def decrypt_password_with_rsa(encrypted_password):
    private_key = load_private_key()
    return private_key.decrypt(
        encrypted_password,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_file_with_password(encrypted_file_data, password):
    iv = encrypted_file_data[:16]
    ciphertext = encrypted_file_data[16:]
    key = password.ljust(32, b'\0')[:32]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# ------------------ Decryption Routes ------------------

@app.route('/decrypt_page')
def decrypt_page():
    return render_template('decrypt.html')

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    encrypted_file = request.files['encrypted_file']
    encrypted_password = request.files['encrypted_password']

    encrypted_file_data = encrypted_file.read()
    encrypted_password_data = encrypted_password.read()

    decrypted_password = decrypt_password_with_rsa(encrypted_password_data)
    decrypted_file_data = decrypt_file_with_password(encrypted_file_data, decrypted_password)

    decrypted_file_path = os.path.join("uploads", f"decrypted_{encrypted_file.filename}")
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_file_data)

    return f'''
        <h3>Decryption Complete</h3>
        <a href="/download/{decrypted_file_path}">Download Decrypted File</a>
    '''

# ------------------ Run Flask App ------------------

if __name__ == '__main__':
    app.run(debug=True)
