import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Generate RSA Keys
@st.cache_resource
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_keys()

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Home", "View Keys"])

# Home Page
if page == "Home":
    st.title("Digital Signature Demo")

    # Message Input
    st.subheader("Enter a message to sign")
    message = st.text_area("Message", "Hello, this is a test message!")

    # Sign the message
    if st.button("Sign Message"):
        message_bytes = message.encode('utf-8')
        signature = private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        st.subheader("Generated Signature")
        st.code(signature.hex())

    # Verify the message
    st.subheader("Verify the Signature")
    signature_input = st.text_area("Enter the signature to verify", "")
    if st.button("Verify Signature"):
        try:
            public_key.verify(
                bytes.fromhex(signature_input),
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            st.success("The signature is valid!")
        except InvalidSignature:
            st.error("The signature is invalid.")

# View Keys Page
elif page == "View Keys":
    st.title("RSA Keys")

    st.subheader("Private Key")
    st.code(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8'))

    st.subheader("Public Key")
    st.code(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8'))
