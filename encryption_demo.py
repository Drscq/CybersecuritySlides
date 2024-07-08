import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def symmetric_encryption(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def symmetric_decryption(iv, ciphertext, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def asymmetric_encryption(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode('utf-8')

def asymmetric_decryption(ciphertext, private_key):
    ciphertext = base64.b64decode(ciphertext)
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

def display_key(key):
    key_str = key.export_key().decode('utf-8')
    return '\n'.join([key_str[i:i+64] for i in range(0, len(key_str), 64)])

# Set page width
st.set_page_config(layout="wide")

st.title("Encryption and Decryption Demo")

st.sidebar.header("Operations")
operation = st.sidebar.radio("Select Operation", ("Key Generation", "Encryption", "Decryption"))

st.header("Input Plaintext")
plaintext = st.text_input("Enter the plaintext to be encrypted:", key="plaintext")

col1, col2 = st.columns(2)

if operation == "Key Generation":
    with col1:
        st.subheader("Symmetric Encryption")
        if st.button("Generate Symmetric Key"):
            symmetric_key = get_random_bytes(16)
            st.session_state.symmetric_key = symmetric_key
            st.write("Symmetric Key Generated:")
            st.code(base64.b64encode(symmetric_key).decode('utf-8'))
    
    with col2:
        st.subheader("Asymmetric Encryption")
        if st.button("Generate Asymmetric Keys"):
            key_pair = RSA.generate(2048)
            st.session_state.public_key = key_pair.publickey()
            st.session_state.private_key = key_pair
            st.write("Public Key Generated:")
            st.code(display_key(st.session_state.public_key))
            st.write("Private Key Generated:")
            st.code(display_key(st.session_state.private_key))

elif operation == "Encryption":
    if "symmetric_key" in st.session_state and plaintext:
        with col1:
            st.subheader("Symmetric Encryption")
            iv, symmetric_ciphertext = symmetric_encryption(plaintext, st.session_state.symmetric_key)
            st.write("Encrypted Text:")
            st.code(symmetric_ciphertext)
            st.write("IV:")
            st.code(iv)
            st.session_state.iv = iv
            st.session_state.symmetric_ciphertext = symmetric_ciphertext

    if "public_key" in st.session_state and plaintext:
        with col2:
            st.subheader("Asymmetric Encryption")
            asymmetric_ciphertext = asymmetric_encryption(plaintext, st.session_state.public_key)
            st.write("Encrypted Text:")
            st.code(asymmetric_ciphertext)
            st.session_state.asymmetric_ciphertext = asymmetric_ciphertext

elif operation == "Decryption":
    if "symmetric_key" in st.session_state:
        with col1:
            st.subheader("Symmetric Encryption")
            if "iv" in st.session_state and "symmetric_ciphertext" in st.session_state:
                symmetric_decrypted_text = symmetric_decryption(st.session_state.iv, st.session_state.symmetric_ciphertext, st.session_state.symmetric_key)
                st.write("Decrypted Text:")
                st.code(symmetric_decrypted_text)

    if "private_key" in st.session_state:
        with col2:
            st.subheader("Asymmetric Encryption")
            if "asymmetric_ciphertext" in st.session_state:
                asymmetric_decrypted_text = asymmetric_decryption(st.session_state.asymmetric_ciphertext, st.session_state.private_key)
                st.write("Decrypted Text:")
                st.code(asymmetric_decrypted_text)

if operation == "Encryption":
    if "symmetric_key" in st.session_state and plaintext:
        st.session_state.iv, st.session_state.symmetric_ciphertext = symmetric_encryption(plaintext, st.session_state.symmetric_key)
    if "public_key" in st.session_state and plaintext:
        st.session_state.asymmetric_ciphertext = asymmetric_encryption(plaintext, st.session_state.public_key)
