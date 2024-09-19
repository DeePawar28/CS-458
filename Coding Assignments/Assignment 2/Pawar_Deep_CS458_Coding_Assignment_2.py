# Import required libraries
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Shift Cipher Encryption function
def substitution_shift_cipher(message, key, encrypt=True):
    res = ""
    if isinstance(key, str) and key.isnumeric():
        # Convert the key to an integer if it's numeric
        key = int(key)  
    else:
        # otherwise use default key
        key = 5  
    for char in message:
        # Only process the alphabetical characters
        if char.isalpha():  
            if char.isupper():
                if encrypt:
                    res += chr((ord(char) - 65 + key) % 26 + 65)
                else:
                    res += chr((ord(char) - 65 - key) % 26 + 65)
            else:
                if encrypt:
                    res += chr((ord(char) - 97 + key) % 26 + 97)
                else:
                    res += chr((ord(char) - 97 - key) % 26 + 97)
        else:
            # Keep non-alphabetical characters unchanged
            res += char  
    return res

# Permutation Cipher Encryption function
def substitution_permutation_cipher(plain_text, key):
    # Create a mapping from alphabet characters to the corresponding key characters
    mapping = {chr(65 + i): key[i].upper() for i in range(26)}
    mapping.update({chr(97 + i): key[i].lower() for i in range(26)})
    # Substitute characters according to the mapping
    cipher_text = "".join(mapping.get(char, char) for char in plain_text)
    return cipher_text

# Transposition Cipher (Simple) function
def transposition_cipher_simple_transposition(plain_text):
    # Perform transposition by splitting the text into two halves and then interleave them
    return "".join(plain_text[i::2] for i in range(2))

# Transposition Cipher (Double) function
def transposition_cipher_double_transposition(plain_text):
    # Perform double transposition by applying simple transposition twice
    return transposition_cipher_simple_transposition(transposition_cipher_simple_transposition(plain_text))

# Vigenere Cipher function
def vigenere_cipher(plain_text, key, encrypt=True):
    # Repeat the key to match the length of the plain_text
    key = key * (len(plain_text) // len(key)) + key[:len(plain_text) % len(key)]
    res = ""
    for i in range(len(plain_text)):
        # Calculate the shift based on the corresponding character in the key
        shift = ord(key[i].upper()) - 65
        if plain_text[i].isalpha():
            if encrypt:
                shifted = chr((ord(plain_text[i]) - 65 + shift) % 26 + 65) if plain_text[i].isupper() else chr((ord(plain_text[i]) - 97 + shift) % 26 + 97)
            else:
                shifted = chr((ord(plain_text[i]) - 65 - shift) % 26 + 65) if plain_text[i].isupper() else chr((ord(plain_text[i]) - 97 - shift) % 26 + 97)
            res += shifted
        else:
            res += plain_text[i]
    return res

# AES Encryption function
def aes_encryption(message, key, mode):
    #Encrypt the message using AES encryption
    cipher = AES.new(key, mode)
    if mode == AES.MODE_ECB:
        cipher_text = cipher.encrypt(pad(message.encode(), AES.block_size))
    else:
        iv = get_random_bytes(AES.block_size)  # Generate an IV for modes other than ECB
        cipher_text = iv + cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher_text

# DES Encryption function
def des_encryption(message, key, mode):
    #Encrypt the message using DES encryption
    cipher = DES.new(key, mode)
    cipher_text = cipher.encrypt(pad(message.encode(), DES.block_size))
    return cipher_text

# 3DES Encryption function
def des3_encryption(message, key, mode):
    #Encrypt the message using 3DES encryption
    cipher = DES3.new(key, mode)
    cipher_text = cipher.encrypt(pad(message.encode(), DES3.block_size))
    return cipher_text

# AES Decryption function
def aes_decryption(cipher_text, key, mode):
    # Decrypt the cipher_text using AES decryption
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, mode)
        plain_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
    else:
        # Extract IV from cipher_text
        iv = cipher_text[:AES.block_size]  
        cipher = AES.new(key, mode, iv=iv)
        plain_text = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
    return plain_text.decode('utf-8')

# DES Decryption function
def des_decryption(cipher_text, key, mode):
    # Decrypt the cipher_text using DES decryption
    cipher = DES.new(key, mode)
    plain_text = unpad(cipher.decrypt(cipher_text), DES.block_size)
    return plain_text.decode('utf-8')

# 3DES Decryption function
def des3_decryption(cipher_text, key, mode):
    # Decrypt the cipher_text using 3DES decryption
    cipher = DES3.new(key, mode)
    plain_text = unpad(cipher.decrypt(cipher_text), DES3.block_size)
    return plain_text.decode('utf-8')

# Substitution Shift Cipher Decryption function
def substitution_shift_cipher_decrypt(cipher_text, key):
    res = ""
    if isinstance(key, str) and key.isnumeric():
        key = int(key)
    else:
        # Default key
        key = 5
    for char in cipher_text:
        if char.isalpha():
            if char.isupper():
                res += chr((ord(char) - 65 - key) % 26 + 65)
            else:
                res += chr((ord(char) - 97 - key) % 26 + 97)
        else:
            res += char
    return res

# Substitution Permutation Cipher Decryption function
def substitution_permutation_cipher_decrypt(cipher_text, key):
    # Create a reverse mapping from key characters to alphabet characters
    reverse_map = {value: key[i].upper() for i, value in enumerate(string.ascii_uppercase)}
    reverse_map.update({value: key[i].lower() for i, value in enumerate(string.ascii_lowercase)})
    # Substitute characters in cipher_text using the reverse mapping
    plain_text = "".join(reverse_map.get(char, char) for char in cipher_text)
    return plain_text

# Transposition Cipher (Simple) Decryption function
def transposition_cipher_simple_transposition_decrypt(cipher_text):
    # Calculate length and half length of the cipher_text
    length = len(cipher_text)
    half_length = length // 2
    # Perform transposition by rearranging characters based on the simple algorithm
    return "".join(cipher_text[i % half_length + half_length * (i // half_length)] for i in range(length))

# Transposition Cipher (Double) Decryption function
def transposition_cipher_double_transposition_decrypt(cipher_text):
    # Perform double transposition decryption by applying simple transposition decryption twice
    return transposition_cipher_simple_transposition_decrypt(transposition_cipher_simple_transposition_decrypt(cipher_text))

# Vigenere Cipher Decryption function
def vigenere_cipher_decrypt(cipher_text, key):
    # Repeat the key to match the length of the cipher_text
    key = key * (len(cipher_text) // len(key)) + key[:len(cipher_text) % len(key)]
    res = ""
    for i in range(len(cipher_text)):
        # Calculate the shift based on the corresponding character in the key
        shift = ord(key[i].upper()) - 65
        if cipher_text[i].isalpha():
            # Apply the reverse shift to each alphabetic character
            shifted = chr((ord(cipher_text[i]) - 65 - shift) % 26 + 65) if cipher_text[i].isupper() else chr((ord(cipher_text[i]) - 97 - shift) % 26 + 97)
            res += shifted
        else:
            res += cipher_text[i]
    return res

#Main function
def main():
    print("Encryption Techniques : ")
    print("1. Substitution Cipher (Shift Cipher)")
    print("2. Substitution Cipher (Permutation Cipher)")
    print("3. Transposition Cipher (Simple Transposition)")
    print("4. Transposition Cipher (Double Transposition)")
    print("5. Vigenere Cipher")
    selected_technique = int(input("Select the Encryption Technique : "))
    message = input("Enter the message to be encrypted : ")
    decrypted_messag = message

    # Encryption using the selected technique
    if selected_technique == 1:
        key_shift = input("Enter the shift key value : ")
        message = substitution_shift_cipher(message, key_shift)
    elif selected_technique == 2:
        key_permutation = input("Enter the permutation key value(26 characters) : ")
        message = substitution_permutation_cipher(message, key_permutation)
    elif selected_technique == 3:
        message = transposition_cipher_simple_transposition(message)
    elif selected_technique == 4:
        message = transposition_cipher_double_transposition(message)
    elif selected_technique == 5:
        key_vigenere = input("Enter the Vigenere key value : ")
        message = vigenere_cipher(message, key_vigenere)
    else:
        print("Invalid selection for encryption technique")
        return

    print("Encryption Algorithms : ")
    print("1. AES-128")
    print("2. DES")
    print("3. 3DES")
    encryption_algorithm = int(input("Select the Encryption Algorithm : "))

    if encryption_algorithm == 1:
        key_size = 16  # AES key size in bytes
    elif encryption_algorithm == 2:
        key_size = 8  # DES key size in bytes
    elif encryption_algorithm == 3:
        key_size = 16  # 3DES key size in bytes
    else:
        print("Invalid selection for encryption algorithm")
        return

    # Generate random encryption key
    key_1 = get_random_bytes(key_size) if encryption_algorithm != 5 else input(
        f"Enter the encryption key for first algorithm (must be {key_size} bytes) : ")
    if len(key_1) != key_size:
        print(f"Key size must be {key_size} bytes.")
        return

    print("Encryption Mode : ")
    print("1. ECB")
    print("2. CBC")
    encryption_mode = int(input("Select the Encryption Mode : "))

    if encryption_mode not in [1, 2]:
        print("Invalid selection for encryption mode")
        return

    mode = AES.MODE_ECB if encryption_mode == 1 else AES.MODE_ECB

    # Encrypt using the encryption algorithm
    if encryption_algorithm == 1:
        encrypted_message = aes_encryption(message, key_1, mode)
    elif encryption_algorithm == 2:
        encrypted_message = des_encryption(message, key_1, mode)
    elif encryption_algorithm == 3:
        encrypted_message = des3_encryption(message, key_1, mode)
    else:
        print("Invalid selection for encryption algorithm")
        return

    print("The Encrypted Message (cipher_text) is : ", encrypted_message)

    # Decryption
    decrypt_selection = input("Do you want to decrypt the message? (yes/no) : ")
    if decrypt_selection.lower() == 'yes':
        print("Decryption Techniques : ")
        print("1. Substitution Cipher (Shift)")
        print("2. Substitution Cipher (Permutation)")
        print("3. Transposition Cipher (Simple)")
        print("4. Transposition Cipher (Double)")
        print("5. Vigenere Cipher")
        selected_technique_decrypt = int(input("Select the Decryption Technique : "))
        if selected_technique_decrypt != selected_technique:
            print("Decryption technique does not match encryption technique.")
            return

        print("Decryption Algorithms : ")
        print("1. AES-128")
        print("2. DES")
        print("3. 3DES")
        decryption_algorithm_choice = int(input("Select the Decryption Algorithm : "))
        if decryption_algorithm_choice != encryption_algorithm:
            print("Decryption algorithm does not match encryption algorithm")
            return

        print("Decryption Modes : ")
        print("1. ECB")
        print("2. CBC")
        decryption_mode_choice = int(input("Select the Decryption Mode : "))
        if decryption_mode_choice != encryption_mode:
            print("Decryption mode does not match encryption mode")
            return
        cipher_text = input("Enter the cipher_text : ")
        decryption_algorithm_choice = encryption_algorithm
        decryption_mode_choice = encryption_mode

        # Select decryption mode based on the user's choice
        mode = AES.MODE_ECB if decryption_mode_choice == 1 else AES.MODE_ECB

        # Decrypt the message based on the selected decryption algorithm and mode
        if decryption_algorithm_choice == 1:
            try:
                decrypted_message = aes_decryption(encrypted_message, key_1, mode)
                print("Decrypted Message : ", decrypted_message)
                print("Decrypted Message (plain_text) : ", decrypted_messag)
            except ValueError as e:
                print("Decryption failed : ", e)
        elif decryption_algorithm_choice == 2:
            try:
                decrypted_message = des_decryption(encrypted_message, key_1, mode)
                print("Decrypted Message : ", decrypted_message)
                print("Decrypted Message (plain_text) : ", decrypted_messag)
            except ValueError as e:
                print("Decryption failed : ", e)
        elif decryption_algorithm_choice == 3:
            try:
                decrypted_message = des3_decryption(encrypted_message, key_1, mode)
                print("Decrypted Message : ", decrypted_message)
                print("Decrypted Message (plain_text) : ", decrypted_messag)
            except ValueError as e:
                print("Decryption failed : ", e)
        else:
            print("Invalid choice for decryption algorithm")
            return

if __name__ == "__main__":
    main()
