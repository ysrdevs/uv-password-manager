import string
import random
import pyperclip
import os
import json
import pyotp
import qrcode
from simple_term_menu import TerminalMenu
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import csv
import io
import zipfile
import tempfile
import pyminizip
import getpass
import requests
import hashlib

ACCOUNTS_FILE = "accounts.encrypted"
SALT_FILE = "salt.txt"
POLICIES_FILE = "password_policies.json"
VERSION = "2.2"

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_key(password, salt):
    """Generate a key from the master password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data, key):
    """Encrypt the data using the provided key."""
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted_data, key):
    """Decrypt the data using the provided key."""
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted_data).decode())

def save_to_file(accounts, key):
    """Save the encrypted accounts to a file."""
    encrypted_data = encrypt_data(accounts, key)
    with open(ACCOUNTS_FILE, "wb") as file:
        file.write(encrypted_data)

def load_accounts(key):
    """Load and decrypt accounts from the file."""
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, "rb") as file:
            encrypted_data = file.read()
        return decrypt_data(encrypted_data, key)
    return {}

def generate_password(length=16):
    """Generate a random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def get_totp_code(secret):
    """Get the current TOTP code."""
    totp = pyotp.TOTP(secret)
    return totp.now()

def get_master_password():
    """Prompt the user for the master password."""
    while True:
        password = getpass.getpass("Enter your master password: ")
        if len(password) >= 12:
            return password
        print("Password must be at least 12 characters long.")

def setup_first_time():
    """Set up the password manager for first-time use."""
    clear_screen()
    print("Welcome to UV's Password Manager!")
    print("This appears to be your first time using the manager.")
    print("Please set up a master password to secure your accounts.")
    print("Make sure to remember this password, as it cannot be recovered!")
    
    master_password = get_master_password()
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as salt_file:
        salt_file.write(salt)
    
    key = generate_key(master_password, salt)
    save_to_file({}, key)
    print("\nMaster password set successfully!")
    input("\nPress Enter to continue...")
    return key

def login():
    """Log in to the password manager."""
    if not os.path.exists(SALT_FILE) or not os.path.exists(ACCOUNTS_FILE):
        return setup_first_time()
    
    with open(SALT_FILE, "rb") as salt_file:
        salt = salt_file.read()
    
    attempts = 3
    while attempts > 0:
        master_password = get_master_password()
        key = generate_key(master_password, salt)
        try:
            load_accounts(key)
            return key
        except:
            attempts -= 1
            if attempts > 0:
                print(f"Incorrect password. {attempts} attempts remaining.")
            else:
                print("Too many failed attempts. Exiting for security reasons.")
                exit()

def show_password_and_totp(account_data):
    """Display the password and TOTP with options to view or copy."""
    menu_items = ["View password (WARNING: DISPLAYS PASSWORD)", "Copy password to clipboard"]
    if account_data.get('totp_secret'):
        menu_items.extend(["View TOTP code", "Copy TOTP code to clipboard", "Show TOTP QR code"])
    menu_items.append("Return to main menu")
    
    menu = TerminalMenu(menu_items)
    while True:
        clear_screen()
        print(f"Options for account: {account_data['name']}")
        choice = menu.show()
        
        if choice == 0:  # View password
            print(f"\nPassword: {account_data['password']}")
            input("\nPress Enter to continue...")
        elif choice == 1:  # Copy password
            pyperclip.copy(account_data['password'])
            print("\nPassword copied to clipboard.")
            input("\nPress Enter to continue...")
        elif choice == 2 and account_data.get('totp_secret'):  # View TOTP
            totp_code = get_totp_code(account_data['totp_secret'])
            print(f"\nTOTP Code: {totp_code}")
            input("\nPress Enter to continue...")
        elif choice == 3 and account_data.get('totp_secret'):  # Copy TOTP
            totp_code = get_totp_code(account_data['totp_secret'])
            pyperclip.copy(totp_code)
            print("\nTOTP code copied to clipboard.")
            input("\nPress Enter to continue...")
        elif choice == 4 and account_data.get('totp_secret'):  # Show TOTP QR code
            totp_uri = pyotp.totp.TOTP(account_data['totp_secret']).provisioning_uri(account_data['name'], issuer_name="UV's Password Manager")
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            print("\nQR Code for TOTP:")
            qr.print_ascii()
            input("\nPress Enter to continue...")
        elif choice == len(menu_items) - 1 or choice is None:  # Return to main menu
            break

def select_account(accounts):
    """Let user select an account using arrow keys."""
    if not accounts:
        print("No accounts found. Please create a new account first.")
        input("\nPress Enter to return to the main menu...")
        return None
    menu = TerminalMenu(accounts, title="Select an account:")
    choice = menu.show()
    return None if choice is None else list(accounts)[choice]

def list_accounts(accounts):
    """List all accounts with additional details."""
    clear_screen()
    if accounts:
        print("List of accounts:")
        for account, data in accounts.items():
            totp_status = "2FA Enabled" if data.get('totp_secret') else "No 2FA"
            print(f"- {account} ({totp_status})")
    else:
        print("No accounts found. Please create a new account to get started.")
    input("\nPress Enter to continue...")

def export_accounts(accounts, key):
    """Export accounts to a file or a password-protected zip file."""
    clear_screen()
    export_formats = ["CSV (Standard)", "JSON (UV's Password Manager)", "LastPass CSV", "Proton Pass CSV"]
    format_menu = TerminalMenu(export_formats, title="Select export format:")
    format_choice = format_menu.show()

    if format_choice is None:
        print("Export cancelled.")
        input("\nPress Enter to continue...")
        return

    export_data = io.StringIO()

    if format_choice == 0:  # CSV (Standard)
        writer = csv.writer(export_data)
        writer.writerow(["name", "password", "totp_secret"])
        for account, data in accounts.items():
            writer.writerow([data['name'], data['password'], data.get('totp_secret', '')])
        file_extension = "csv"
    elif format_choice == 1:  # JSON (UV's Password Manager)
        json.dump(accounts, export_data, indent=2)
        file_extension = "json"
    elif format_choice == 2:  # LastPass CSV
        writer = csv.writer(export_data)
        writer.writerow(["url", "username", "password", "totp", "extra", "name", "grouping", "fav"])
        for account, data in accounts.items():
            writer.writerow(["", data['name'], data['password'], data.get('totp_secret', ''), "", account, "", "0"])
        file_extension = "csv"
    elif format_choice == 3:  # Proton Pass CSV
        writer = csv.writer(export_data)
        writer.writerow(["name", "username", "password", "totp_secret"])
        for account, data in accounts.items():
            writer.writerow([account, data['name'], data['password'], data.get('totp_secret', '')])
        file_extension = "csv"

    format_names = ["standard", "uv", "lastpass", "protonpass"]
    filename = f"exported_accounts_{format_names[format_choice]}.{file_extension}"

    use_zip = input("Do you want to create a password-protected zip file? (y/n): ").lower() == 'y'

    if use_zip:
        zip_filename = f"{filename}.zip"
        zip_password = input("Enter a password for the zip file: ")
        while not zip_password:
            print("Password cannot be empty for a secure export.")
            zip_password = input("Enter a password for the zip file: ")

        # Write the export data to a temporary file
        with open(filename, 'w', newline='') as temp_file:
            temp_file.write(export_data.getvalue())

        try:
            # Create the password-protected zip file
            pyminizip.compress(filename, None, zip_filename, zip_password, 0)
            print(f"Accounts exported to password-protected '{zip_filename}'")
            print(f"Use the password you entered to open the zip file.")
        finally:
            # Remove the temporary file
            os.remove(filename)
    else:
        with open(filename, 'w', newline='') as file:
            file.write(export_data.getvalue())
        print(f"Accounts exported to '{filename}'")

    print("WARNING: This file contains sensitive information. Please keep it secure.")
    input("\nPress Enter to continue...")
        
def import_accounts(current_accounts, key):
    """Import accounts from a secure, encrypted file with format options."""
    clear_screen()
    import_formats = ["CSV (Standard)", "JSON (UV's Password Manager)", "LastPass CSV", "Proton Pass CSV"]
    format_menu = TerminalMenu(import_formats, title="Select import format:")
    format_choice = format_menu.show()

    if format_choice is None:
        print("Import cancelled.")
        input("\nPress Enter to continue...")
        return

    filename = input("Enter the name of the file to import: ")
    if not os.path.exists(filename):
        print(f"File '{filename}' not found.")
        input("\nPress Enter to continue...")
        return

    import_key = input("Enter the decryption key for the imported file: ").encode()
    
    try:
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        
        decrypted_data = decrypt_data(encrypted_data, import_key)
        imported_accounts = {}

        if format_choice == 0:  # CSV (Standard)
            reader = csv.DictReader(io.StringIO(decrypted_data))
            for row in reader:
                imported_accounts[row['name']] = {
                    'name': row['name'],
                    'password': row['password'],
                    'totp_secret': row['totp_secret'] if row['totp_secret'] else None
                }
        elif format_choice == 1:  # JSON (UV's Password Manager)
            imported_accounts = json.loads(decrypted_data)
        elif format_choice == 2:  # LastPass CSV
            reader = csv.DictReader(io.StringIO(decrypted_data))
            for row in reader:
                imported_accounts[row['name']] = {
                    'name': row['username'],
                    'password': row['password'],
                    'totp_secret': row['totp'] if row['totp'] else None
                }
        elif format_choice == 3:  # Proton Pass CSV
            reader = csv.DictReader(io.StringIO(decrypted_data))
            for row in reader:
                imported_accounts[row['name']] = {
                    'name': row['username'],
                    'password': row['password'],
                    'totp_secret': row['totp_secret'] if row['totp_secret'] else None
                }

        for account, data in imported_accounts.items():
            if account in current_accounts:
                choice = input(f"Account '{account}' already exists. Overwrite? (y/n): ").lower()
                if choice != 'y':
                    continue
            current_accounts[account] = data
        
        save_to_file(current_accounts, key)
        print("Accounts imported successfully!")
    except Exception as e:
        print(f"Import failed: {str(e)}")
    
    input("\nPress Enter to continue...")

def delete_account(accounts, key):
    """Delete an existing account."""
    clear_screen()
    if not accounts:
        print("No accounts found. Please create a new account first.")
        input("\nPress Enter to continue...")
        return

    account = select_account(accounts)
    if account:
        confirm = input(f"Are you sure you want to delete the account '{account}'? (y/n): ").lower()
        if confirm == 'y':
            del accounts[account]
            save_to_file(accounts, key)
            print(f"\nAccount '{account}' has been deleted.")
        else:
            print("\nDeletion cancelled.")
    input("\nPress Enter to continue...")

def check_password_breach(password):
    """Check if a password has been involved in a data breach using the HIBP API."""
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    hashes = (line.split(':') for line in response.text.splitlines())
    count = next((int(count) for t, count in hashes if t == suffix), 0)
    return count

def check_account_breaches(accounts):
    """Check all accounts for password breaches."""
    clear_screen()
    print("Checking for password breaches...")
    breached_accounts = []
    for account, data in accounts.items():
        count = check_password_breach(data['password'])
        if count > 0:
            breached_accounts.append((account, count))
    
    if breached_accounts:
        print("\nThe following accounts have passwords that appear in known data breaches:")
        for account, count in breached_accounts:
            print(f"- {account}: Found in {count} breaches")
        print("\nConsider updating these passwords as soon as possible.")
    else:
        print("\nGood news! None of your passwords appear in known data breaches.")
    
    input("\nPress Enter to continue...")

def load_password_policies():
    """Load password policies from file."""
    if os.path.exists(POLICIES_FILE):
        with open(POLICIES_FILE, 'r') as f:
            return json.load(f)
    return {
        "default": {
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special_chars": True
        }
    }

def save_password_policies(policies):
    """Save password policies to file."""
    with open(POLICIES_FILE, 'w') as f:
        json.dump(policies, f, indent=2)

def check_password_strength(password, policy):
    """Check if a password meets the specified policy."""
    if len(password) < policy['min_length']:
        return False
    if policy['require_uppercase'] and not any(c.isupper() for c in password):
        return False
    if policy['require_lowercase'] and not any(c.islower() for c in password):
        return False
    if policy['require_digits'] and not any(c.isdigit() for c in password):
        return False
    if policy['require_special_chars'] and not any(c in string.punctuation for c in password):
        return False
    return True

def generate_password_with_policy(policy):
    """Generate a password that meets the specified policy."""
    while True:
        password = generate_password(policy['min_length'])
        if check_password_strength(password, policy):
            return password

def manage_password_policies(policies):
    """Manage password policies."""
    while True:
        clear_screen()
        print("Password Policy Management")
        print("1. View policies")
        print("2. Add/Edit policy")
        print("3. Delete policy")
        print("4. Return to main menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            for name, policy in policies.items():
                print(f"\nPolicy: {name}")
                for key, value in policy.items():
                    print(f"  {key}: {value}")
            input("\nPress Enter to continue...")
        elif choice == '2':
            name = input("Enter policy name (or 'default' for the default policy): ")
            min_length = int(input("Minimum password length: "))
            require_uppercase = input("Require uppercase? (y/n): ").lower() == 'y'
            require_lowercase = input("Require lowercase? (y/n): ").lower() == 'y'
            require_digits = input("Require digits? (y/n): ").lower() == 'y'
            require_special_chars = input("Require special characters? (y/n): ").lower() == 'y'
            
            policies[name] = {
                "min_length": min_length,
                "require_uppercase": require_uppercase,
                "require_lowercase": require_lowercase,
                "require_digits": require_digits,
                "require_special_chars": require_special_chars
            }
            save_password_policies(policies)
            print("Policy updated successfully.")
            input("\nPress Enter to continue...")
        elif choice == '3':
            name = input("Enter the name of the policy to delete: ")
            if name in policies and name != 'default':
                del policies[name]
                if len(policies) == 0:
                    # If all policies were deleted, recreate the default policy
                    policies['default'] = {
                        "min_length": 12,
                        "require_uppercase": True,
                        "require_lowercase": True,
                        "require_digits": True,
                        "require_special_chars": True
                    }
                save_password_policies(policies)
                print("Policy deleted successfully.")
            else:
                print("Policy not found or cannot delete default policy.")
            input("\nPress Enter to continue...")
        elif choice == '4':
            break

    # Ensure there's always at least one policy
    if len(policies) == 0:
        policies['default'] = {
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special_chars": True
        }
        save_password_policies(policies)
def add_or_update_account(accounts, key, existing_account=None):
    """Add a new account or update an existing one with policy check."""
    clear_screen()
    policies = load_password_policies()
    
    if existing_account:
        print(f"Updating account: {existing_account}")
        account_name = existing_account
        current_password = accounts[account_name]['password']
        current_totp_secret = accounts[account_name].get('totp_secret')
    else:
        account_name = input("Enter the account name: ")
        current_password = None
        current_totp_secret = None
    
    # Select password policy
    policy_names = list(policies.keys())
    if not policy_names:
        print("No password policies found. Using default policy.")
        selected_policy = {
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special_chars": True
        }
        policy_name = "default"
    else:
        policy_menu = TerminalMenu(policy_names, title="Select password policy:")
        policy_choice = policy_menu.show()
        policy_name = policy_names[policy_choice]
        selected_policy = policies[policy_name]

    if existing_account:
        password_choice = input("Do you want to change the password? (y/n): ").lower()
        if password_choice == 'y':
            password_gen_choice = input("Generate a new password? (y/n): ").lower()
            if password_gen_choice == 'y':
                password = generate_password_with_policy(selected_policy)
                print(f"Generated password: {password}")
            else:
                while True:
                    password = input("Enter the new password: ")
                    if check_password_strength(password, selected_policy):
                        break
                    print("Password does not meet the selected policy requirements. Please try again.")
        else:
            password = current_password
    else:
        password_gen_choice = input("Generate a new password? (y/n): ").lower()
        if password_gen_choice == 'y':
            password = generate_password_with_policy(selected_policy)
            print(f"Generated password: {password}")
        else:
            while True:
                password = input("Enter the password: ")
                if check_password_strength(password, selected_policy):
                    break
                print("Password does not meet the selected policy requirements. Please try again.")
    
    if existing_account and current_totp_secret:
        totp_choice = input("Do you want to change the TOTP (2FA) settings? (y/n): ").lower()
    else:
        totp_choice = input("Add TOTP (2FA) to this account? (y/n): ").lower()
    
    if totp_choice == 'y':
        totp_secret = input("Enter the TOTP secret key provided by the website: ").strip()
        try:
            # Validate the TOTP secret
            pyotp.TOTP(totp_secret).now()
        except:
            print("Invalid TOTP secret. TOTP will not be added to this account.")
            totp_secret = None
        else:
            print("TOTP secret is valid.")
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(account_name, issuer_name="UV's Password Manager")
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            print("\nQR Code for TOTP:")
            qr.print_ascii()
            print("\nYou can scan this QR code with your authenticator app if needed.")
    elif existing_account:
        totp_secret = current_totp_secret
    else:
        totp_secret = None
    
    accounts[account_name] = {
        'name': account_name,
        'password': password,
        'totp_secret': totp_secret,
        'policy': policy_name
    }
    save_to_file(accounts, key)
    print(f"\nAccount '{account_name}' has been {'updated' if existing_account else 'added'}.")
    input("\nPress Enter to continue...")
def main_menu(key):
    """Display the main menu and handle user input."""
    while True:
        clear_screen()
        accounts = load_accounts(key)
        policies = load_password_policies()
        print(f"UV's Password Manager (v{VERSION})")
        if not accounts:
            print("There are currently no accounts stored.")
            print("Select 'Add a new account' to get started.\n")

        menu_items = [
            "Add a new account",
            "Retrieve an existing account",
            "Update an existing account",
            "List all accounts",
            "Delete an account",
            "Export accounts",
            "Import accounts",
            "Check for password breaches",
            "Manage password policies",
            "Quit"
        ]
        menu = TerminalMenu(menu_items, title="Main Menu")
        choice = menu.show()

        if choice == 0:  # Add a new account
            add_or_update_account(accounts, key)
        elif choice == 1:  # Retrieve an existing account
            clear_screen()
            if not accounts:
                print("No accounts found. Please create a new account first.")
                input("\nPress Enter to continue...")
                continue
            account = select_account(accounts)
            if account:
                show_password_and_totp(accounts[account])
        elif choice == 2:  # Update an existing account
            clear_screen()
            if not accounts:
                print("No accounts found. Please create a new account first.")
                input("\nPress Enter to continue...")
                continue
            account = select_account(accounts)
            if account:
                add_or_update_account(accounts, key, existing_account=account)
        elif choice == 3:  # List all accounts
            list_accounts(accounts)
        elif choice == 4:  # Delete an account
            delete_account(accounts, key)
        elif choice == 5:  # Export accounts
            export_accounts(accounts, key)
        elif choice == 6:  # Import accounts
            import_accounts(accounts, key)
        elif choice == 7:  # Check for password breaches
            check_account_breaches(accounts)
        elif choice == 8:  # Manage password policies
            manage_password_policies(policies)
        elif choice == 9 or choice is None:  # Quit
            clear_screen()
            print("Thank you for using UV's Password Manager. Stay secure!")
            break

if __name__ == "__main__":
    key = login()
    main_menu(key)
