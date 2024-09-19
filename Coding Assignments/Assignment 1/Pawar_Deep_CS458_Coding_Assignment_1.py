#Aim: To implement encryption and decryption program using Shift cipher 

#Function to encrypt the given text using Shift Cipher with the specified key
def encrypt(plain_text, key):
        cipher_text = ""
        for char in plain_text:
    
                #Checking if the character is an alphabet letter
                if char.isalpha():
                        #Calculating the shifted ASCII value based on the key
                        shift = ord(char) + key
                        if char.isupper():
                                #Ensuring the shifted value is wrapped within the uppercase alphabet using modulo 26
                                cipher_text = cipher_text + chr((shift - ord('A')) % 26 + ord('A'))
                        elif char.islower():
                                #Ensuring the shifted value is wrapped within the lowercase alphabet using modulo 26
                                cipher_text = cipher_text + chr((shift - ord('a')) % 26 + ord('a'))
                else:
                        cipher_text = cipher_text + char

        #Returning the final encrypted text
        return cipher_text

#Function to decrypt the given cipher_text using Shift Cipher with the specified key
def decrypt(cipher_text, key):
        decrypted_plain_text = ""
        for char in cipher_text:

                #Checking if the character is an alphabet letter
                if char.isalpha():
                      #Calculating the shifted ASCII value based on the key
                        shift = ord(char) - key
                        if char.isupper():
                                #For uppercase letters the character is decrypted using the following formula
                                decrypted_plain_text = decrypted_plain_text + chr((shift - ord('A')) % 26 + ord('A'))
                        elif char.islower():
                                #For lowercase letters the character is decrypted using the following formula
                                decrypted_plain_text = decrypted_plain_text + chr((shift - ord('a')) % 26 + ord('a'))
                else:
                        decrypted_plain_text = decrypted_plain_text + char

        #Returning the final decrypted text
        return decrypted_plain_text

#Function to perform brute force attack 
def brute_force_attack(cipher_text):
        for key in range(1, 26):
                decrypted_plain_text = decrypt(cipher_text, key)
                print(f"For Key {key} : Decrypted Text is {decrypted_plain_text}")

#Main function to handle inputs from the user and execute the selected operation
def main():
        print("Choose an option:")
        print("1. Encryption")
        print("2. Decryption")
        print("3. Brute Force Attack")

        choice = input("Enter your choice (1/2/3) : ")

        #Encryption
        if choice == '1':
                plain_text = input("Enter the Plain text : ")
                if not plain_text:
                        print("Error: Plain text cannot be empty. Please enter some text.")
                        return
                input_key = input("Enter the key : ")
    
                #try-expect for error handling
                try:
                        key = int(input_key)
                except ValueError:
                        print("Error: Invalid key input. Please enter a numeric key value.")
                        return

                cipher_text = encrypt(plain_text, key)
                print(f"Cipher text : {cipher_text}")

        #Decryption
        elif choice == '2':
                cipher_text = input("Enter the Cipher text : ")
                if not cipher_text:
                        print("Error: Cipher text cannot be empty. Please enter some text.")
                        return
                input_key = input("Enter the key : ")

                #try-expect for error handling
                try:
                        key = int(input_key)
                except ValueError:
                        print("Invalid key input. Please enter a numeric key value.")
                        return

                decrypted_plain_text = decrypt(cipher_text, key)
                print(f"Decrypted Text : {decrypted_plain_text}")

        #Brute Force Attack
        elif choice == '3':
                cipher_text = input("Enter the Cipher text : ")
                if not cipher_text:
                        print("Error: Cipher text cannot be empty. Please enter some text.")
                        return
                print("Possible Decryption texts : ")
                brute_force_attack(cipher_text)

        else:
                print("Invalid choice entered. Please enter between 1, 2, or 3.")

if __name__ == "__main__":
        main()
