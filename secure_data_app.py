import streamlit as st
import hashlib
import json
import time
import os
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# -------------------- Configuration --------------------
DATA_FILE = 'data.json'
LOCKOUT_TIME = 30  # seconds

# Key generation for Fernet encryption
if not os.path.exists('secret.key'):
    with open('secret.key', 'wb') as f:
        f.write(Fernet.generate_key())
with open('secret.key', 'rb') as f:
    KEY = f.read()

cipher = Fernet(KEY)

# -------------------- Utilities --------------------

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    else:
        return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def hash_passkey(passkey, salt=b'salt1234'):
    return pbkdf2_hmac('sha256', passkey.encode(), salt, 100000).hex()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# -------------------- Session Initialization --------------------

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_start_time' not in st.session_state:
    st.session_state.lockout_start_time = None
if 'logged_in_user' not in st.session_state:
    st.session_state.logged_in_user = None


stored_data = load_data()

# -------------------- Custom CSS for Styling --------------------
st.markdown("""
    <style>
    body {background-color: #f5f7fa;}
    .stButton>button {
        background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.5em 2em;
        font-size: 1em;
        font-weight: bold;
        transition: 0.4s;
    }
    .stButton>button:hover {
        background: linear-gradient(90deg, #43e97b 0%, #38f9d7 100%);
        transform: scale(1.05);
    }
    .block-container {
        padding-top: 3rem;
        padding-bottom: 3rem;
    }
    .stTextInput>div>div>input, .stTextArea>div>textarea {
        border-radius: 10px;
        padding: 10px;
    }
    </style>
""", unsafe_allow_html=True)

# -------------------- Streamlit App --------------------

st.title("🛡️ Secure Multi-User Data Encryption System")

menu = ["🏠 Home", "📝 Register", "🔑 Login", "📂 Store Data", "🔍 Retrieve Data", "🚪 Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# -------------------- Lockout System --------------------
def is_locked_out():
    if st.session_state.lockout_start_time:
        elapsed = time.time() - st.session_state.lockout_start_time
        if elapsed < LOCKOUT_TIME:
            st.warning(f"⏳ Locked out! Wait {int(LOCKOUT_TIME - elapsed)} seconds.")
            return True
        else:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_start_time = None
            return False
    return False

# -------------------- Pages --------------------

if choice == "🏠 Home":
    st.subheader("🏠 Welcome to Secure Data System")
    st.write("Please **Register** or **Login** to access your secure vault! 🔒")

elif choice == "📝 Register":
    st.subheader("Create a New Account 🚀")

    with st.form(key='register_form', clear_on_submit=True):
        username = st.text_input("Choose a Username")
        password = st.text_input("Choose a Password", type="password")
        submit_button = st.form_submit_button("Register")

    if submit_button:
        if username and password:
            if username in stored_data:
                st.error("🚫 Username already exists! Please try another.")
            else:
                hashed_password = hash_passkey(password)
                stored_data[username] = {"password": hashed_password, "data": []}
                save_data(stored_data)
                st.success("✅ Registered Successfully! Now login.")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "🔑 Login":
    st.subheader("Welcome Back! 👋")

    if is_locked_out():
        st.stop()

    with st.form(key='login_form'):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_submit = st.form_submit_button("Login")

    if login_submit:
        if username in stored_data:
            hashed_input = hash_passkey(password)
            if stored_data[username]['password'] == hashed_input:
                st.success(f"✅ Logged in as {username}")
                st.balloons()
                st.session_state.logged_in_user = username
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error(f"❌ Incorrect password! Attempts left: {3 - st.session_state.failed_attempts}")
        else:
            st.error("🚫 Username not found!")

        if st.session_state.failed_attempts >= 3:
            st.warning("🔒 Too many failed attempts! Temporary lockout initiated.")
            st.session_state.lockout_start_time = time.time()

elif choice == "📂 Store Data":
    if not st.session_state.logged_in_user:
        st.warning("⚠️ You must login first.")
    else:
        st.subheader("Save your Secret Notes ✏️")
        user_data = st.text_area("Enter your confidential data:")

        if st.button("Encrypt & Save 🔐"):
            if user_data:
                encrypted_text = encrypt_data(user_data)
                stored_data[st.session_state.logged_in_user]['data'].append(encrypted_text)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
                st.snow()
            else:
                st.error("⚠️ Data field cannot be empty.")

elif choice == "🔍 Retrieve Data":
    if not st.session_state.logged_in_user:
        st.warning("⚠️ You must login first.")
    else:
        st.subheader("Retrieve Your Secret Data 🔍")
        user_entries = stored_data[st.session_state.logged_in_user]['data']
        if user_entries:
            selected_data = st.selectbox("Select encrypted data to decrypt:", user_entries)

            if st.button("Decrypt 🔓"):
                try:
                    decrypted_text = decrypt_data(selected_data)
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                except Exception as e:
                    st.error("❌ Decryption failed. Please try again.")
        else:
            st.info("ℹ️ No data stored yet. Add some!")

elif choice == "🚪 Logout":
    st.session_state.logged_in_user = None
    st.success("👋 Logged out successfully.")
