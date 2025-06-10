import streamlit as st
import tenseal as ts
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import binascii
import os

# =================== Configuration ====================
CORRECT_USERNAME = "user1"
CORRECT_PASSWORD = "pass123"
weights = [0.8, -0.2, 0.1]  # Weight failed attempts strongly
# =======================================================

st.title("🔐 Encrypted Login + Homomorphic Risk Detection")

# Initialize session variables
if "failed_logins" not in st.session_state:
    st.session_state.failed_logins = 0

if "aes_key" not in st.session_state:
    st.session_state.aes_key = None

# AES utility functions
def aes_encrypt(data: str, key: bytes) -> str:
    backend = default_backend()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(data_b64: str, key: bytes) -> str:
    backend = default_backend()
    data = base64.b64decode(data_b64)
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    return plain.decode()

# Setup TenSEAL context
@st.cache_resource
def create_context():
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    context.generate_galois_keys()
    context.global_scale = 2 ** 40
    return context

context = create_context()

# =================== UI TABS ====================
tab1, tab2 = st.tabs(["🔑 AES Key Setup", "🔐 Encrypted Login + Classification"])

# ========== Tab 1: AES Key Entry ==========
with tab1:
    st.subheader("🔑 Enter or Generate AES Key")

    key_input = st.text_input("Enter a 32-character AES key (for AES-256)", type="password")

    # Button to set AES key
if st.button("Set AES Key"):
    if not key_input:
        st.error("Please enter a key.")
    else:
        try:
            # Check if the input is in base64 format
            if len(key_input) == 44:  # 32 bytes in base64 form
                aes_key = base64.b64decode(key_input)
                if len(aes_key) == 32:
                    st.session_state.aes_key = aes_key
                    st.success("AES key set successfully!")
                else:
                    st.error("Base64 key must represent exactly 32 bytes.")
            else:
                # Treat input as a plain string
                if len(key_input.encode()) == 32:
                    st.session_state.aes_key = key_input.encode()
                    st.success("AES key set successfully!")
                else:
                    st.error("Key must be exactly 32 bytes (characters) long.")
        except (binascii.Error, ValueError):
            st.error("Invalid key format.")

# Button to generate random AES key
if st.button("Generate Random AES Key"):
    random_key = os.urandom(32)
    st.session_state.aes_key = random_key
    st.success("Random AES key generated and stored.")

    # Display base64 encoded key
    encoded_key = base64.b64encode(random_key).decode()
    st.code(encoded_key, language="text")


    if st.session_state.aes_key:
        st.info("✅ AES key is currently set.")

# ========== Tab 2: Login & Classification ==========
with tab2:
    st.subheader("🔐 Encrypted Login Form")

    if not st.session_state.aes_key:
        st.warning("Please enter or generate an AES key in the first tab.")
    else:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        st.subheader("🔎 Context Features")
        time_since_login = st.number_input("Time Since Last Login (days)", min_value=0.0, value=1.0)
        frequency = st.number_input("Login Frequency (per week)", min_value=0.0, value=2.0)

        if st.button("Login"):
            # Encrypt credentials
            aes_key = st.session_state.aes_key
            enc_username = aes_encrypt(username, aes_key)
            enc_password = aes_encrypt(password, aes_key)

            st.markdown("✅ Encrypted Username & Password")
            st.code(enc_username, language="text")
            st.code(enc_password, language="text")

            if username == CORRECT_USERNAME and password == CORRECT_PASSWORD:
                st.success("✅ Login successful!")
                st.session_state.failed_logins = 0
            else:
                st.session_state.failed_logins += 1
                st.error(f"❌ Login failed. Failed attempts: {st.session_state.failed_logins}")

                # Token vector: [failed_logins, time_since_login, frequency]
                input_vector = [
                    float(st.session_state.failed_logins),
                    time_since_login,
                    frequency
                ]
                st.write("🔢 Input Vector:", input_vector)

                # Encrypt with TenSEAL
                enc_input = ts.ckks_vector(context, input_vector)
                weights_vector = ts.ckks_vector(context, weights)
                enc_result = (enc_input * weights_vector).sum()

                # Decrypt dot product result
                dot_result = enc_result.decrypt()[0]
                st.write(f"🔓 Decrypted Dot Product: `{dot_result:.4f}`")

                # Classification based on dot product
                if dot_result > 5:
                    risk = "High Risk"
                elif dot_result > 1:
                    risk = "Medium Risk"
                else:
                    risk = "Low Risk"

                st.markdown(f"### 🚨 Risk Classification: **{risk}**")

                # Optional encrypted LLM result
                enc_hex = enc_result.serialize().hex()
                st.text_area("Encrypted LLM Layer Result (Hex)", enc_hex, height=150)
