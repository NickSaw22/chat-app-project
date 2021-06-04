from cryptography.fernet import Fernet


# Generating the key and writing it to a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
        print('key is generated')


def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(message):
    key = load_key()
    encoded_msg = message.encode()
    f = Fernet(key)
    encrypted_msg = f.encrypt(encoded_msg)
    return encrypted_msg

def decrypt_message(enc_msg):
    key = load_key()
    f = Fernet(key)
    dec_msg = f.decrypt(enc_msg)
    return dec_msg.decode()
m='this is nikhil 22'
enc = encrypt_message(m)
print(enc)
dec = decrypt_message(enc)
print(dec)
dec = decrypt_message(b'gAAAAABguMn8M8d4sQo1JdHI0CNZHLx5JfJqM_9um_glhenSx-pYP09BdcoXA2h4Vj3brB9eFni62Hf43QO7fMWUEuC60xr4O3z6lD8iyT6YZUJK2wpzt0o3UHEFfGLTRQtzA0mbC1TA0ddcw6-5QXF8mfw8ZCgMYBOqBVUzypikvx_ndJCrFw2TWNiBtKzX4Rwez5_Lxn4q80KjdhzRv0DbMJWM5G1PfzTXB8BPdf0YwhJbmO77ddJofvDD84IEhJAojpE_1d2nKl3oxAwS_K9kt3LJE1o4ckszTGmVLB7g2s6uoQimEmcqgiKjaTF5dYTnb2Od9icZs9yvMi6MaF2NldcbdtrmHFR9HqovVSe8VbjeasiUkYpJdQymXwQxs3GTLg0GSpFxNqs9UhO5_rRbmk5c0Vu3ymDRu_GKhB1RNJFIDJZscwgxz-5Ec1xfe3Zm5T_RNjGnn-AYPs8QvN_EdT4cykyauQ==')
print(dec)
