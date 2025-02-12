import sys
import getpass
from cryptography.fernet import Fernet  # type: ignore
import boto3

# AWS KMS imports (to be added)


# AWS S3 imports (to be added)
# import boto3

# print(sys.argv)

def get():
    email = sys.argv[2]

    while True:
        password = getpass.getpass("Create a password: ")
        confirm_password = getpass.getpass("Confirm your password: ")
        
        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Try again.")

    # Print password in green

    print(f"{email}")

def put():

    email = sys.argv[2]
    message = sys.argv[3]

    while True:
        password = getpass.getpass("Create a password: ")
        confirm_password = getpass.getpass("Confirm your password: ")
        
        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Try again.")

    # Print password in green

    print(f"{email}, {message}")

    # Replace Fernet key generation with AWS KMS
    # key = Fernet.generate_key()  # This will be replaced by a KMS key

    # Use AWS KMS to encrypt the message
    # kms_client = boto3.client('kms')
    # key_id = 'alias/your-kms-key'  # Replace with your actual KMS key alias or key ID

    # Encrypt the message using AWS KMS
    # response = kms_client.encrypt(
    #     KeyId=key_id,
    #     Plaintext=message.encode()
    # )
    # encrypted_message = response['CiphertextBlob']

    # Temporary Fernet encryption for now
    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    print(f"encrypted: {encrypted_message}")

    # Decrypt the message using AWS KMS
    # response = kms_client.decrypt(
    #     CiphertextBlob=encrypted_message
    # )
    # decrypted_message = response['Plaintext'].decode()

    # Temporary Fernet decryption for now
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    print(f"decrypted: {decrypted_message}")



# Send the encrypted string to an S3 bucket
# s3_client = boto3.client('s3')
# bucket_name = 'your-s3-bucket-name'  # Replace with your actual S3 bucket name
# object_key = 'encrypted_data.txt'  # Define the object key (file name) in S3

# Upload the encrypted message to S3
# s3_client.put_object(Bucket=bucket_name, Key=object_key, Body=encrypted_message)

# Print confirmation
# print(f"Encrypted data successfully uploaded to S3 bucket: {bucket_name}/{object_key}")

command = sys.argv[1]

if command == "get":
    get()
elif command == "put":
    put()
else:
    print('wrong command. run again with get or put.')