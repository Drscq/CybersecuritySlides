import streamlit as st
import hashlib

# Function to calculate hash
def calculate_hash(input_text, algorithm):
    if algorithm == 'MD5':
        return hashlib.md5(input_text.encode()).hexdigest()
    elif algorithm == 'SHA-1':
        return hashlib.sha1(input_text.encode()).hexdigest()
    elif algorithm == 'SHA-256':
        return hashlib.sha256(input_text.encode()).hexdigest()
    elif algorithm == 'SHA-512':
        return hashlib.sha512(input_text.encode()).hexdigest()
    else:
        return 'Unsupported Algorithm'

# Streamlit app layout
st.title('Hash Function Demo')
st.write('Enter text to see its hash value using different algorithms.')

# User input
input_text = st.text_input('Enter text here:')

# Algorithm selection
algorithm = st.selectbox('Choose hash algorithm:', ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'])

# Calculate hash
if input_text:
    hash_value = calculate_hash(input_text, algorithm)
    st.write(f'Hash value using {algorithm}:')
    st.code(hash_value)
