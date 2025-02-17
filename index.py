import sys
import getpass
import boto3
import os
from dotenv import load_dotenv
from time import sleep
import hmac
import hashlib
import base64

# Load environment variables
load_dotenv()

# AWS Cognito client setup
cognito_client = boto3.client('cognito-idp', region_name='us-east-2')
COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
COGNITO_CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')
BUCKET_NAME = os.getenv("AWS_BUCKET_NAME")
kms_key_id = os.getenv("KMS_KEY_ID")
kms_client = boto3.client('kms', region_name='us-east-2')
s3 = boto3.client("s3")

def compute_secret_hash(username):
    """Compute secret hash using HMAC-SHA256"""
    message = username + COGNITO_CLIENT_ID
    digest = hmac.new(
        COGNITO_CLIENT_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode()

def user_exists(email):
    try:
        # Check if the user exists in Cognito
        response = cognito_client.admin_get_user(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=email
        )
        return True
    except cognito_client.exceptions.UserNotFoundException:
        # If user is not found, return False
        return False

def sign_up(email):
    # Prompt for password and confirm password
    secret_hash = compute_secret_hash(email)
    while True:
        password = getpass.getpass("Create a password: ")
        confirm_password = getpass.getpass("Confirm your password: ")
        
        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Try again.")

    # Create user in Cognito
    try:
        response = cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=email,
            Password=password,
            SecretHash=secret_hash
        )
        print(f"Account created for {email}. Please check your email to verify the account.")
        print("Once verified, please try again.")
        return response 
    except cognito_client.exceptions.NotAuthorizedException as e:
        print("Not authorized:", e)
    except Exception as e:
        print("Error:", e)
def sign_in(email, password):
    try:
        # Attempt to log in the user
        response = cognito_client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            ClientId=COGNITO_CLIENT_ID,
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password
            }
        )
        print("Login successful!")
        return response['AuthenticationResult']
    except cognito_client.exceptions.NotAuthorizedException:
        print("Incorrect password.")
        return None
    except cognito_client.exceptions.UserNotFoundException:
        print("User not found.")
        return None

def handle_put(email, datatype, data):
    # Put (upload) data
    response = kms_client.encrypt(
        KeyId=kms_key_id,
        Plaintext=data.encode()  # Assuming data is a string
    )
    encrypted = response['CiphertextBlob']
    
    # Upload encrypted data to S3
    s3.put_object(Bucket=BUCKET_NAME, Key=f"{email}/message", Body=encrypted)
    print(f"Data uploaded successfully to {email}/message.")

def handle_get(email):
    # Get (retrieve) data
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=f"{email}/message")
        encrypted_data = response['Body'].read()
        decrypted = kms_client.decrypt(CiphertextBlob=encrypted_data)
        decrypted_data = decrypted['Plaintext'].decode()

        print("Retrieved data:")
        print(decrypted_data)
    except s3.exceptions.NoSuchKey:
        print(f"No data found for {email}.")

def handle_user_action():
    if len(sys.argv) < 3:
        print("Usage: python3 index.py get <email> OR python3 index.py put <email> <datatype> <data>")
        return

    action = sys.argv[1]  # "get" or "put"
    email = sys.argv[2]

    if not user_exists(email):
        print(f"No account found for {email}. Please create an account.")
        # Create account process
        sign_up(email)
        return
    
    # Proceed with action if user exists
    if action == 'get':
        handle_get(email)
    elif action == 'put' and len(sys.argv) == 5:
        datatype = sys.argv[3]
        data = sys.argv[4]
        handle_put(email, datatype, data)
    else:
        print("Invalid usage. For 'put', please provide datatype and data.")

if __name__ == "__main__":
    handle_user_action()
