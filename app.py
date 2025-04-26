import streamlit as st
import hashlib from cryptography.fernet import Fernet

# Generate and initialize encryption key
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data and state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True  # assume authorized initially


# Hash passkey with SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


# Encrypt plain text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()


# Decrypt ciphertext
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text:
            if value["passkey"] == hashed_passkey:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
            else:
                st.session_state.failed_attempts += 1
                return None
    st.session_state.failed_attempts += 1
    return None


# UI Navigation
st.set_page_config(page_title="Secure Data Encryption", layout="centered")
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# ------------------ Home ------------------
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Use this tool to **encrypt** your sensitive data and **retrieve** it securely using your private passkey.")

# ------------------ Store Data ------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_text = st.text_area("Enter the text to encrypt:")
    user_passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_text and user_passkey:
            encrypted = encrypt_data(user_text)
            hashed_key = hash_passkey(user_passkey)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed_key,
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.write("Save this encrypted data for retrieval:")
            st.code(encrypted)
        else:
            st.error("⚠️ Both fields are required!")

# ------------------ Retrieve Data ------------------
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Access denied. Please login again.")
        st.switch_page("Login")

    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("Paste your encrypted data:")
    user_passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and user_passkey:
            result = decrypt_data(encrypted_input, user_passkey)
            attempts_left = 3 - st.session_state.failed_attempts

            if result:
                st.success("✅ Decryption Successful!")
                st.code(result)
            else:
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("⛔ Too many failed attempts! Redirecting to login...")
                    st.experimental_rerun()
                else:
                    st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
        else:
            st.error("⚠️ Please provide both fields.")

# ------------------ Login ------------------
elif choice == "Login":
    st.subheader("🔑 Login to Continue")
    login_input = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_input == "admin123":  # In production, use secure auth
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Logged in successfully!")
            st.info("Now go back to the Retrieve Data page.")
        else:
            st.error("❌ Incorrect password.")
