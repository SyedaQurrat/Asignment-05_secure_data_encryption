
# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet

# # Generate a symmetric encryption key (stored in memory for now)
# KEY = Fernet.generate_key()
# cipher = Fernet(KEY)

# # In-memory storage (no database used)
# stored_data = {}  # Format: {encrypted_text: {"encrypted_text": ..., "passkey": ...}}
# failed_attempts = st.session_state.get("failed_attempts", 0)  # Use session state for persistence

# # Function to hash passkey using SHA-256
# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# # Function to encrypt user data
# def encrypt_data(text):
#     return cipher.encrypt(text.encode()).decode()

# # Function to decrypt data only if passkey matches
# def decrypt_data(encrypted_text, passkey):
#     global stored_data
#     hashed_pass = hash_passkey(passkey)
#     record = stored_data.get(encrypted_text)

#     if record and record["passkey"] == hashed_pass:
#         st.session_state["failed_attempts"] = 0  # Reset on success
#         return cipher.decrypt(encrypted_text.encode()).decode()
#     else:
#         st.session_state["failed_attempts"] += 1
#         return None

# # App Title
# st.title("🛡️ Secure Data Encryption System")

# # Sidebar Navigation
# menu = ["Home", "Store Data", "Retrieve Data", "Login"]
# choice = st.sidebar.radio("Navigation", menu)

# # 1. Home Page
# if choice == "Home":
#     st.subheader("🏠 Welcome")
#     st.info("Store and retrieve data securely using encrypted keys and passphrases.")

# # 2. Store Data Page
# elif choice == "Store Data":
#     st.subheader("📂 Store New Data")
#     user_text = st.text_area("Enter Text to Encrypt:")
#     passkey = st.text_input("Enter Passkey:", type="password")

#     if st.button("Encrypt & Save"):
#         if user_text and passkey:
#             hashed = hash_passkey(passkey)
#             encrypted = encrypt_data(user_text)
#             stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
#             st.success("✅ Data encrypted and stored successfully!")
#             st.code(encrypted, language="text")  # Show encrypted text for later retrieval
#         else:
#             st.warning("⚠️ Please fill in all fields.")

# # 3. Retrieve Data Page
# elif choice == "Retrieve Data":
#     st.subheader("🔍 Retrieve Encrypted Data")
    
#     # Check if max attempts reached
#     if st.session_state.get("failed_attempts", 0) >= 3:
#         st.warning("🔐 Too many failed attempts. Please reauthorize.")
#         st.switch_page("Login")

#     encrypted_input = st.text_area("Paste Encrypted Text:")
#     passkey_input = st.text_input("Enter Passkey:", type="password")

#     if st.button("Decrypt"):
#         if encrypted_input and passkey_input:
#             result = decrypt_data(encrypted_input, passkey_input)
#             if result:
#                 st.success("✅ Decrypted Text:")
#                 st.code(result, language="text")
#             else:
#                 attempts_left = 3 - st.session_state.get("failed_attempts", 0)
#                 st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
#                 if st.session_state["failed_attempts"] >= 3:
#                     st.warning("🔐 Redirecting to login page...")
#                     st.experimental_rerun()
#         else:
#             st.warning("⚠️ Please fill in both fields.")

# # 4. Login Page
# elif choice == "Login":
#     st.subheader("🔑 Reauthorize Access")
#     login_password = st.text_input("Enter Master Password:", type="password")

#     if st.button("Login"):
#         if login_password == "admin123":  # Demo password, replace with env/config in real apps
#             st.session_state["failed_attempts"] = 0  # Reset failed attempts
#             st.success("✅ Login successful! You may now try again.")
#         else:
#             st.error("❌ Wrong password. Try again.")






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

st.title("🔐 Secure Data Encryption System")

# Tabs for storing and retrieving data
tab1, tab2 = st.tabs(["Store Data", "Retrieve Data"])

with tab1:
    st.subheader("🔒 Store Encrypted Data")

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
