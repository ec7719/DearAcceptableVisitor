import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# AES encryption and decryption functions (same as before)
def encrypt_data(key, data):
  iv = get_random_bytes(AES.block_size)

  cipher = AES.new(key, AES.MODE_CBC, iv)

  padded_data = pad(data.encode('utf-8'), AES.block_size)

  ciphertext = iv + cipher.encrypt(padded_data)

  return ciphertext

def decrypt_data(key, ciphertext):
  iv = ciphertext[:AES.block_size]

  cipher = AES.new(key, AES.MODE_CBC, iv)

  decrypted_data = unpad(cipher.decrypt(ciphertext[AES.block_size:]),
                         AES.block_size)

  return decrypted_data.decode('utf-8')



# Streamlit app
def main():
    st.title("AES Encryption and Decryption")

    # Input text box for the user to enter the encryption key
    encryption_key = st.text_input("Enter Encryption Key:", type="password")

    # Input text box for the user to enter the data to encrypt
    data_to_encrypt = st.text_area("Enter Data to Encrypt:")

    # Encrypt button
    if st.button("Encrypt"):
        if encryption_key and data_to_encrypt:
            encryption_key_bytes = encryption_key.encode('utf-8')
            encrypted_data = encrypt_data(encryption_key_bytes, data_to_encrypt)
            st.success(f"Encrypted Data: {encrypted_data.hex()}")

    # Input text box for the user to enter the data to decrypt
    data_to_decrypt = st.text_area("Enter Data to Decrypt:")

    # Decrypt button
    if st.button("Decrypt"):
        if encryption_key and data_to_decrypt:
            try:
                decryption_key_bytes = encryption_key.encode('utf-8')
                data_to_decrypt_bytes = bytes.fromhex(data_to_decrypt)
                decrypted_data = decrypt_data(decryption_key_bytes, data_to_decrypt_bytes)
                st.success(f"Decrypted Data: {decrypted_data}")
            except ValueError:
                st.error("Decryption failed. Please check the encryption key or data.")

if __name__ == "__main__":
    main()
