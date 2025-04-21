import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import json
import os

# File to store encrypted data permanently
DATA_FILE = "secure_data.json"

# Load stored data from file if it exists
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Function to save stored data to file
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# Function to generate encryption key
def generate_key(passkey):
    # Hash the passkey using SHA-256 to make it a valid Fernet key
    hashed = hashlib.sha256(passkey.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(hashed))

# Use base64 to format hashed key into Fernet-compatible key
import base64

st.title("Secure Data Encryption System")

# Tabs for storing and retrieving data
tab1, tab2 = st.tabs(["Store Data", "Retrieve Data"])

with tab1:
    st.subheader("Store Encrypted Data")

    key = st.text_input("Enter a Passkey", type="password")
    data = st.text_area("Enter Data to Encrypt")
    name = st.text_input("Enter a Unique Name for the Data")

    if st.button("Encrypt and Store"):
        if key and data and name:
            try:
                fernet = generate_key(key)  # Create Fernet object with passkey
                encrypted = fernet.encrypt(data.encode()).decode()  # Encrypt the data

                stored_data[name] = {
                    "key": hashlib.sha256(key.encode()).hexdigest(),  # Store hashed passkey
                    "data": encrypted  # Store encrypted data
                }

                save_data()  # Save updated data to file

                st.success("Data encrypted and stored successfully!")
            except Exception as e:
                st.error(f"Encryption failed: {e}")
        else:
            st.warning("Please fill all fields.")

with tab2:
    st.subheader("🔓 Retrieve Decrypted Data")

    name = st.text_input("Enter the Data Name to Retrieve")
    key = st.text_input("Enter the Passkey", type="password")

    if st.button("Decrypt and Retrieve"):
        if name in stored_data:
            try:
                entered_key_hash = hashlib.sha256(key.encode()).hexdigest()  # Hash entered key
                saved_key_hash = stored_data[name]["key"]  # Get saved hashed key

                if entered_key_hash == saved_key_hash:
                    fernet = generate_key(key)  # Generate Fernet object
                    decrypted = fernet.decrypt(stored_data[name]["data"].encode()).decode()  # Decrypt

                    st.success("Decrypted Data:")
                    st.code(decrypted)
                else:
                    st.error("Wrong passkey! Access denied.")
            except Exception as e:
                st.error(f"Decryption failed: {e}")
        else:
            st.warning("Data not found. Please check the name.")
