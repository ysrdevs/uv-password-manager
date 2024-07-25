# UV's Password Manager

This is a secure password manager that generates, stores, and manages passwords for your various accounts. It provides a command-line interface for easy interaction and management of your passwords.

## Features

- Generate secure random passwords
- Store account information (username, password, and TOTP secret if applicable)
- Retrieve stored passwords and copy them to clipboard
- List all stored accounts
- Export account data in various formats (CSV, JSON, LastPass CSV, Proton Pass CSV)
- Optional password-protected zip export for added security
- Two-factor authentication (2FA) support with TOTP
- Secure storage of account information in an encrypted file

## Requirements

- Python 3.6 or higher
- Required Python packages:
  - pyperclip
  - tkinter (usually comes pre-installed with Python)
  - cryptography
  - pyotp
  - qrcode
  - simple_term_menu
  - pyminizip

You can install the required packages using pip:

```
pip install pyperclip cryptography pyotp qrcode simple-term-menu pyminizip
```

Note: `tkinter` is usually included with Python installations. If it's missing, you may need to install it separately depending on your operating system.

## Usage

1. Run the script:
   ```
   python uv.py
   ```

2. On first run, you'll be prompted to set up a master password.

3. Use the menu to navigate through different options:
   - Add a new account
   - Retrieve an existing account (copies password to clipboard)
   - Update an existing account
   - List all accounts
   - Delete an account
   - Export accounts
   - Quit

## Security Notes

- All account information is stored in an encrypted file (`accounts.encrypted`).
- The master password is used to derive the encryption key.
- Exported files can be optionally secured with password-protected zip encryption.
- Always keep your master password and export passwords secure and never share them.

## Data Storage

- Encrypted account data is stored in `accounts.encrypted`
- A salt for key derivation is stored in `salt.txt`

## Export Formats and Security Options

When exporting, you can choose from the following formats:
1. CSV (Standard)
2. JSON (UV's Password Manager format)
3. LastPass CSV
4. Proton Pass CSV

After selecting the format, you'll be asked if you want to secure the export with a password:

- If you choose to secure it:
  1. You'll be prompted to enter a password for the zip file.
  2. A password-protected zip file will be created containing your export.
  3. Use the password you set to open the zip file and access the exported data.

- If you choose not to secure it:
  1. The file will be exported directly in the chosen format (e.g., CSV, JSON).
  2. A warning will be displayed reminding you that the file contains sensitive information in plain text.

## Clipboard Functionality

When retrieving a password, it is automatically copied to your clipboard for easy pasting into login forms.

## Contributing

Feel free to fork this project and submit pull requests for any enhancements you develop.

## Disclaimer

This password manager is a personal project and may not be suitable for enterprise or high-security environments. Use at your own risk.
