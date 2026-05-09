# Copyright (c) 2026 Ayaan Khan
# Licensed under the MIT License

import os
import base64
import struct
import getpass
import traceback
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type

# ================= CONSTANTS =================
MAGIC         = b"SCRY"          # magic bytes embedded in every payload
VERSION       = b"\x03"          # version byte embedded in every payload
HEADER        = MAGIC + VERSION  # 5 bytes prepended before salt+IV+ciphertext
MIN_PW_LEN    = 3                # minimum password length
MAX_PW_LEN    = 1024             # cap absurdly long passwords before Argon2 sees them
MAX_NAME_LEN  = 4096             # upper bound on embedded filename length field

# ================= ABOUT =================
ABOUT_TEXT = """
  Tool    : SCRY — Encryption Container for Text & Files					       R[f/B8aVG1
  												     t+alES@M64p5%6
  Version : 3.0											    hug          FR?
  												   xDg            L4K
  Released: 2026-05-09										   btE    SCRY    (Vx 
  												   gk3            h7>
  Authors : Ayaan Khan, Rajesh Patel, Suleiman Sheikh						   v3M            cuZ
  												[nWKWmZ3hBza8bNkqNU6Cv-y
  GitHub  : https://github.com/xayaank/SCRY							Araa7A-OqV&gi+E9mS0p!1QI   
 												moPCy78tMoWeFV(tS@q8NbgQ   
========================================================================  			AyMt&q(V9QsW19GW41akvhPb
												71*h4d&iMId  KSUGH8W2)K5
  SCRY uses AES-256-GCM for authenticated encryption and Argon2id				xPLJ74W8gv    p7C#P8LX7%   
  for key derivation. Every encrypted payload is self-identifying via				?W4PS7MB)$H  e/07Rxw7P53
  a magic header and includes the original filename so files are				wn*4dWSxr9I  4oHQ7$AcIZf
  restored correctly on decryption.								AWUMQD@h8PwLYcn2V%&AR$Kn
												HYM9H6aQwhV)DP2eNa4G#k8F
  This project was oringinally intended for personal use 					>4Ka9&E4kFg518R8JXH[0#8Q
  before it was published on GitHub.

========================================================================

  DISCLAIMER!!!

  SCRY is provided "as is", without warranty of any kind, express or implied,
  including but not limited to merchantability, fitness for a particular purpose,
  or noninfringement.

  This software has not undergone independent security auditing and should not be
  considered guaranteed protection against all threats, attacks, data corruption,
  or loss. Use at your own risk.

  Always keep backups of important files before encryption or decryption.

  The authors are not responsible for lost data, forgotten passwords, damaged
  files, misuse of the software, or modified/tampered builds obtained from
  unofficial sources.

  Official releases and source code are distributed only through the official
  GitHub repository.

  Copyright (c) 2026 Ayaan Khan.
  Licensed under the MIT License.

"""

# ================= ARGON2 KEY =================
def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )

# ================= PASSWORD VALIDATION =================
def validate_password_length(pw: str) -> str | None:
    """Return an error string if the password violates length rules, else None."""
    if len(pw) < MIN_PW_LEN:
        return f"Password too short (minimum {MIN_PW_LEN} characters)."
    if len(pw) > MAX_PW_LEN:
        return f"Password too long (maximum {MAX_PW_LEN} characters)."
    return None

# ================= PASSWORD PROMPT HELPERS =================
def prompt_password_encrypt(label="Password") -> str:
    """Prompt for a new password with confirmation and length enforcement."""
    while True:
        pw = getpass.getpass(f"{label}: ")
        # Report length errors after the first entry so the full password is typed
        err = validate_password_length(pw)
        if err:
            print(err + " Try again.")
            continue
        pw2 = getpass.getpass(f"Confirm {label}: ")
        if pw == pw2:
            return pw
        print("Passwords do not match. Try again.")

def prompt_password_decrypt(label="Password") -> str:
    """Prompt for an existing password and enforce length rules."""
    while True:
        pw = getpass.getpass(f"{label}: ")
        err = validate_password_length(pw)
        if err:
            print(err + " Try again.")
            continue
        return pw

# ================= AES ENCRYPT =================
def encrypt_bytes(data: bytes, password: str) -> bytes:
    err = validate_password_length(password)
    if err:
        raise ValueError(err)

    salt = os.urandom(16)
    key  = derive_key(password, salt)
    iv   = os.urandom(12)

    # AESGCM.encrypt appends the 16-byte auth tag automatically
    ct_and_tag = AESGCM(key).encrypt(iv, data, None)

    # Prepend magic header so files are self-identifying regardless of filename
    return HEADER + salt + iv + ct_and_tag

# ================= AES DECRYPT =================
def decrypt_bytes(raw: bytes, password: str) -> bytes:
    err = validate_password_length(password)
    if err:
        raise ValueError(err)

    # Validate magic bytes first
    if not raw.startswith(MAGIC):
        raise ValueError(
            "Not a valid SCRY file (missing magic header). "
            "File may be corrupted or not encrypted by SCRY."
        )

    # Validate version byte separately so version mismatches are clearly reported
    if raw[len(MAGIC):len(HEADER)] != VERSION:
        found = raw[len(MAGIC):len(HEADER)].hex()
        expected = VERSION.hex()
        raise ValueError(
            f"Unsupported SCRY version (found 0x{found}, expected 0x{expected}). "
            "This file may have been created by a different version of SCRY."
        )

    raw = raw[len(HEADER):]  # strip the 5-byte header

    if len(raw) < 44:
        raise ValueError("Data too short to be a valid SCRY payload.")

    salt       = raw[:16]
    iv         = raw[16:28]
    ct_and_tag = raw[28:]    # ciphertext + 16-byte tag (AESGCM expects them joined)

    key = derive_key(password, salt)

    # InvalidTag raised automatically by AESGCM on wrong password or tampered data
    return AESGCM(key).decrypt(iv, ct_and_tag, None)

# ================= SCRY PACK FORMAT =================
# Layout: [4-byte big-endian filename length][filename bytes][file data]

def pack_file(filename: str, data: bytes) -> bytes:
    name_bytes = filename.encode("utf-8")
    return struct.pack("!I", len(name_bytes)) + name_bytes + data

def unpack_file(data: bytes) -> tuple:
    if len(data) < 4:
        raise ValueError("Packed data too short.")
    name_len = struct.unpack("!I", data[:4])[0]
    # Guard against implausibly large name_len before slicing
    if name_len > MAX_NAME_LEN:
        raise ValueError(
            f"Filename length field ({name_len}) exceeds maximum ({MAX_NAME_LEN}). "
            "Data is likely corrupted."
        )
    if 4 + name_len > len(data):
        raise ValueError("Corrupted name length field.")
    try:
        name = data[4:4 + name_len].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Corrupted filename in packed data (invalid UTF-8).")
    # Strip directory components to prevent path traversal on restore
    name = os.path.basename(name)
    if not name:
        raise ValueError("Filename in packed data is empty or invalid.")
    content = data[4 + name_len:]
    return name, content

# ================= SAFE OUTPUT PATH =================
def safe_output_path(directory: str, base: str, ext: str) -> str:
    """
    Return a path that did not exist at the moment this function claimed it.
    Uses O_CREAT | O_EXCL to close the TOCTOU window between the existence
    check and the caller's write; the placeholder file is created here and
    the caller overwrites it immediately with real content.
    """
    candidate = os.path.join(directory, f"{base}{ext}")
    counter = 1
    while True:
        try:
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return candidate
        except FileExistsError:
            candidate = os.path.join(directory, f"{base}({counter}){ext}")
            counter += 1

# ================= NORMALIZE PATH =================
def normalize_path(path: str) -> str:
    # Expand ~ and resolve to absolute path so ~/file.txt works correctly
    return os.path.abspath(os.path.expanduser(path.strip().strip('"')))

# ================= ENCRYPT FILE =================
def encrypt_file(path: str) -> None:
    """Prompt for a password internally and encrypt the file at path."""
    path = normalize_path(path)

    if not os.path.exists(path):
        print("File not found. Returning to menu.")
        return

    try:
        password = prompt_password_encrypt()
    except KeyboardInterrupt:
        print("\nCancelled.")
        return

    try:
        with open(path, "rb") as f:
            file_data = f.read()

        filename  = os.path.basename(path)
        packed    = pack_file(filename, file_data)
        encrypted = encrypt_bytes(packed, password)

        base     = os.path.splitext(path)[0]
        out_path = safe_output_path(
            os.path.dirname(path) or ".",
            os.path.basename(base) + "SCRYv3",
            ".SCRY"
        )

        with open(out_path, "wb") as f:
            f.write(encrypted)

        print(f"\nFile sealed → {out_path}")

    except OSError as e:
        print(f"File error: {e}")
    except Exception as e:
        print(f"Encryption failed: {e}")
        traceback.print_exc()

# ================= DECRYPT FILE =================
def decrypt_file(path: str) -> None:
    """Prompt for a password internally and decrypt the SCRY file at path."""
    path = normalize_path(path)

    if not os.path.exists(path):
        print("File not found. Returning to menu.")
        return

    try:
        password = prompt_password_decrypt()
    except KeyboardInterrupt:
        print("\nCancelled.")
        return

    try:
        with open(path, "rb") as f:
            raw = f.read()

        try:
            decrypted = decrypt_bytes(raw, password)
        except InvalidTag:
            print("Wrong password or file has been tampered with.")
            return

        original_name, file_data = unpack_file(decrypted)
        stem, ext = os.path.splitext(original_name)

        # Show the original extension before asking so the user can make
        # an informed choice rather than answering blind
        print(f"\nOriginal file detected: {original_name}")
        print(f"  → Restore as: {stem}{ext}  |  Decline to use: {stem}.restored")
        confirm = input("Restore original file extension? (y/n): ").strip().lower()

        out_ext  = ext if confirm == "y" else ".restored"
        out_path = safe_output_path(os.path.dirname(path) or ".", stem, out_ext)

        with open(out_path, "wb") as f:
            f.write(file_data)

        print(f"\nFile restored → {out_path}")

    except OSError as e:
        print(f"File error: {e}")
    except ValueError as e:
        print(f"Corrupted data: {e}")
    except Exception as e:
        print(f"Decryption failed: {e}")
        traceback.print_exc()

# ================= TEXT MODE =================
def encrypt_text(msg: str, password: str) -> str:
    return base64.b64encode(encrypt_bytes(msg.encode(), password)).decode()

def decrypt_text(token: str, password: str) -> str:
    # Catch malformed base64 with a clean error instead of a raw crash
    try:
        raw = base64.b64decode(token.encode(), validate=True)
    except Exception:
        raise ValueError("Invalid base64 input — cipher text is malformed.")
    plaintext_bytes = decrypt_bytes(raw, password)
    # Safely handle non-UTF-8 bytes rather than crashing blindly
    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "Decrypted content is not valid UTF-8 text. "
            "This payload may be a file — use option 4 (Decrypt file) instead."
        )

# ================= MENU =================
if __name__ == "__main__":
    while True:
        print("\n=== SCRY SYSTEM v3  -  ENCRYPTION CONTAINER FOR TEXT & FILES ===")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. Encrypt file")
        print("4. Decrypt file")
        print("5. About")
        print("6. Exit")

        # Catch Ctrl+C gracefully instead of dumping a raw traceback
        try:
            choice = input("> ").strip()
        except KeyboardInterrupt:
            print("\nExiting.")
            break

        if choice == "1":
            try:
                msg = input("Message: ")
                pw  = prompt_password_encrypt()
                print("\nEncrypted:\n", encrypt_text(msg, pw))
            except KeyboardInterrupt:
                print("\nCancelled.")
            except Exception as e:
                print(f"Encryption failed: {e}")
                traceback.print_exc()

        elif choice == "2":
            try:
                msg = input("Cipher: ")
                pw  = prompt_password_decrypt()
                print("\nDecrypted:\n", decrypt_text(msg, pw))
            except KeyboardInterrupt:
                print("\nCancelled.")
            except InvalidTag:
                print("Wrong password or corrupted data.")
            except ValueError as e:
                print(f"Decryption failed: {e}")
            except Exception as e:
                print(f"Decryption failed: {e}")
                traceback.print_exc()

        elif choice == "3":
            try:
                path = input("File path: ")
                encrypt_file(path)
            except KeyboardInterrupt:
                print("\nCancelled.")

        elif choice == "4":
            try:
                path = input("SCRY file path: ")
                decrypt_file(path)
            except KeyboardInterrupt:
                print("\nCancelled.")

        elif choice == "5":
            print(ABOUT_TEXT)

        elif choice == "6":
            break

        else:
            print("Invalid option.")