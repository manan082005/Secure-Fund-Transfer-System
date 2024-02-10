from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
#from Crypto.Random import get_random_bytes
from twilio.rest import Client
import random import randint

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

account_sid = 'ACfb327291ad650eabe24ded460f7bcb93'
auth_token = '5f8d402b854e70778533d66c21eb793e'
twilio_phone_number = '9413846208'

users = {
    'user1': {'password': 'prtscrq9', 'balance': 1000.0, 'recipient_phone_number':'946007344'},
    'user2': {'password': 'scrollpause4', 'balance': 1500.0, 'recipient_phone_number':'9462380344'},
}

def generate_otp():
    return str(randint(100000, 999999))

def send_otp_twilio(recipient_phone_number, otp):
    client = Client(account_sid, auth_token)
    message = client.messages.create(
        to=recipient_phone_number,
        from_=twilio_phone_number,
        body=f'Your OTP for fund transfer is: {otp}'
    )
    return message.sid

def des_encrypt(key, plaintext):
    key = key[:8]
    cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.DES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

#def generate_otp(length=6):
    #digits = '0123456789'
    #return ''.join(random.choice(digits) for _ in range(length))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username]['password'] == password:
            #users[username]['otp'] = generate_otp()
            flash(f'Login Successful','success')
            #flash(f'Login successful! OTP sent to your registered mobile number: {users[username]["otp"]}', 'success')
            return redirect(url_for('transfer'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('index.html')

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if request.method == 'POST':
        recipient = request.form['recipient']
        amount = float(request.form['amount'])
        #entered_otp = request.form['otp']
        
        otp = generate_otp()
        send_otp_twilio('recipient_phone_number', otp)
        
        if recipient in users and amount > 0 and users['user1']['balance'] >= amount:
            users['user1']['balance'] -= amount
            users[recipient]['balance'] += amount
            flash(f'OTP sent. Check your phone to complete the transfer.')
            #flash(f'Transfer to {recipient} successful.', 'success')
        else:
            flash('Invalid recipient or insufficient funds.', 'error')

    return render_template('transfer.html')

if __name__ == '__main__':
    app.run(debug=True)
