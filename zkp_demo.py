import streamlit as st
import random
import hashlib

def hash_function(data):
    return hashlib.sha256(data.encode()).hexdigest()

st.title("Zero-Knowledge Proof Demo with Jack")

st.write("""
This demo shows a simple Zero-Knowledge Proof where Jack (Prover) proves to Bob (Verifier) that he knows a secret number without revealing it.
""")

secret_number = st.text_input("Jack's Secret Number", type="password")
if not secret_number:
    st.warning("Please enter a secret number to continue.")
    st.stop()

if st.button("Start Zero-Knowledge Proof"):
    # Jack generates the hashed secret
    hashed_secret = hash_function(secret_number)
    
    # Bob sends a random challenge
    challenge = random.randint(0, 1)
    st.write(f"Bob's Challenge: {'Prove you know the secret' if challenge == 0 else 'Prove you know something else'}")
    
    # Jack responds
    if challenge == 0:
        response = hashed_secret
    else:
        response = hash_function(secret_number[::-1])  # Example: different proof, reversing the secret

    st.write(f"Jack's Response: {response}")

    # Bob verifies the response
    if challenge == 0:
        verification = response == hashed_secret
    else:
        verification = response == hash_function(secret_number[::-1])
    
    if verification:
        st.success("Bob is convinced that Jack knows the secret!")
    else:
        st.error("Verification failed. Bob is not convinced.")
