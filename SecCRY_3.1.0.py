# Copyright (c) 2026 Ayaan Khan
# Licensed under the PolyForm Noncommercial 1.0.0 License

import os
import sys
import base64
import struct
import traceback
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type

# ================= PLATFORM DETECTION =================
_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    import msvcrt
else:
    import termios
    import tty
    import select as _select

# ================= CONSTANTS =================
MAGIC         = b"SCRY"
VERSION       = b"\x03"
HEADER        = MAGIC + VERSION
MIN_PW_LEN    = 3
MAX_PW_LEN    = 1024
MAX_NAME_LEN  = 4096

# ---- Default Argon2id parameters ----
# Stored in-band in every payload so any future build can always decrypt past files.
# Reduced from time_cost=12/256MiB to time_cost=4/64MiB for interactive speed.
# Old files encrypted at higher params are fully compatible (params read from payload).
KDF_TIME_COST    = 4
KDF_MEM_COST_KIB = 64 * 1024
KDF_PARALLELISM  = 2
KDF_HASH_LEN     = 32

# Byte offsets inside the stripped (post-HEADER) raw payload:
_OFF_SALT_END = 16   # [0:16]   salt
_OFF_IV_END   = 28   # [16:28]  IV
_OFF_TC_END   = 30   # [28:30]  time_cost uint16 BE
_OFF_MC_END   = 34   # [30:34]  memory_cost_kib uint32 BE
_OFF_PAR_END  = 35   # [34:35]  parallelism uint8
                     # [35:]    ciphertext + 16-byte GCM tag

# ================= ABOUT =================
ABOUT_TEXT = """
  Tool    : SecCRY — Encryption Container for Text & Files					       R[f/B8aVG1
  												     t+alES@M64p5%6
  Version : 3.1.0										    hug          FR?
  												   xDg            L4K
  Released: 2026-05-12										   btE   SecCRY   (Vx 
  												   gk3            h7>
  Authors : Ayaan Khan, Rajesh Patel, Suleiman Sheikh						   v3M            cuZ
  												[nWKWmZ3hBza8bNkqNU6Cv-y
  GitHub  : https://github.com/xayaank/SecCRY							Araa7A-OqV&gi+E9mS0p!1QI   
 												moPCy78tMoWeFV(tS@q8NbgQ   
========================================================================  			AyMt&q(V9QsW19GW41akvhPb
												71*h4d&iMId  KSUGH8W2)K5
  SecCRY uses AES-256-GCM for authenticated encryption and Argon2id				xPLJ74W8gv    p7C#P8LX7%   
  for key derivation. Every encrypted payload is self-identifying via				?W4PS7MB)$H  e/07Rxw7P53
  a magic header and includes the original filename so files are				wn*4dWSxr9I  4oHQ7$AcIZf
  restored correctly on decryption.								AWUMQD@h8PwLYcn2V%&AR$Kn
												HYM9H6aQwhV)DP2eNa4G#k8F
  This project was originally intended for personal use 					>4Ka9&E4kFg518R8JXH[0#8Q
  before it was published on GitHub.

========================================================================

  DISCLAIMER!!!

  SecCRY is provided "as is", without warranty of any kind, express or implied,
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
  Licensed under the PolyForm Noncommercial 1.0.0 License.

"""

# ================= CANCELLATION =================
class CancelledError(Exception):
    """Raised when the user presses ESC to cancel the current operation."""


# =================================================================================
# TERMINAL RAW MODE — UNIX
# =================================================================================
# Design rationale for all three issues:
#
# Issue 1 (garbled D&D / paste):  The previous design ran a background thread
# that called os.read() on the same stdin fd as the main thread.  No lock can
# fully close the race because the kernel decides which thread wins each byte.
# The only correct fix is: ONE thread owns stdin at ALL times.  The background
# watcher thread is gone entirely.  D&D burst detection now happens inline
# inside _menu_input_loop() on the main thread — the only place where stdin is
# read at menu level — so there is never concurrent fd access anywhere.
#
# Issue 2 (input lag / Enter delay):  The old code called tcgetattr+setraw+
# tcsetattr on every prompt, and used a 50 ms select() timeout, adding up to
# 50 ms of latency to every character.  Now raw mode is entered once at startup
# and left once at exit (_RawTerminal.enter/leave).  All reads use a 1 ms
# select() timeout so keystrokes are acted on within 1 ms.
# =================================================================================

_BURST_TIMEOUT = 0.08   # seconds; chars arriving faster than this = burst (D&D/paste)
_BURST_MIN_LEN = 2      # ignore 1-char bursts


class _RawTerminal:
    """
    Unix-only.  Puts the terminal in raw mode once for the program lifetime
    and provides the single stdin-reading primitive used by all input helpers.
    Windows uses msvcrt directly.
    """
    def __init__(self):
        self._fd  = None
        self._old = None

    def enter(self):
        if not sys.stdin.isatty():
            return
        self._fd  = sys.stdin.fileno()
        self._old = termios.tcgetattr(self._fd)
        tty.setraw(self._fd)

    def leave(self):
        if self._fd is not None and self._old is not None:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)

    def read_byte(self, timeout: float) -> bytes | None:
        """Block for up to `timeout` seconds; return one byte or None on timeout."""
        if self._fd is None:
            ch = sys.stdin.read(1)
            return ch.encode() if ch else None
        ready = _select.select([self._fd], [], [], timeout)[0]
        if not ready:
            return None
        try:
            return os.read(self._fd, 1)
        except OSError:
            return None

    def drain_escape(self):
        """Consume trailing bytes of an escape sequence (arrow keys etc.)."""
        if self._fd is None:
            return
        while _select.select([self._fd], [], [], 0.05)[0]:
            os.read(self._fd, 8)


_term = _RawTerminal()   # singleton; enter()/leave() called in __main__


# =================================================================================
# LOW-LEVEL LINE READER  (prompt_input / prompt_secret)
# =================================================================================

def _read_line(prompt: str, echo: bool) -> str:
    """
    Read a line of input one character at a time.
    Unix: terminal already in raw mode (entered once at startup).
    Windows: uses msvcrt.getwch().

    ESC       → CancelledError
    Enter/CR  → end of line
    Ctrl-C    → KeyboardInterrupt
    Ctrl-D    → EOFError  (Unix)
    Backspace → erase last character
    Arrow/F-keys → ignored
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    buf: list[str] = []

    if not _IS_WINDOWS and not sys.stdin.isatty():
        line = sys.stdin.readline()
        if line == "":
            raise EOFError
        return line.rstrip("\n")

    while True:
        if _IS_WINDOWS:
            ch = msvcrt.getwch()
            if ch == "\x1b":
                raise CancelledError
            elif ch in ("\r", "\n"):
                sys.stdout.write("\n"); sys.stdout.flush()
                break
            elif ch == "\x03":
                raise KeyboardInterrupt
            elif ch in ("\x00", "\xe0"):
                msvcrt.getwch()   # consume extended-key suffix
                continue
            elif ch == "\x08":
                if buf:
                    buf.pop()
                    if echo:
                        sys.stdout.write("\b \b"); sys.stdout.flush()
                continue
            char = ch
        else:
            raw = _term.read_byte(0.001)   # 1 ms poll — imperceptible lag
            if raw is None:
                continue
            if raw == b"\x1b":
                _term.drain_escape()
                raise CancelledError
            elif raw in (b"\r", b"\n"):
                sys.stdout.write("\n"); sys.stdout.flush()
                break
            elif raw == b"\x03":
                raise KeyboardInterrupt
            elif raw == b"\x04":
                raise EOFError
            elif raw in (b"\x7f", b"\x08"):
                if buf:
                    buf.pop()
                    if echo:
                        sys.stdout.write("\b \b"); sys.stdout.flush()
                continue
            try:
                char = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue

        buf.append(char)
        if echo:
            sys.stdout.write(char); sys.stdout.flush()

    if not echo:
        sys.stdout.write("\n"); sys.stdout.flush()
    return "".join(buf)


def prompt_input(prompt: str) -> str:
    """Plain visible input with ESC-to-cancel."""
    return _read_line(prompt, echo=True)


def prompt_secret(prompt: str) -> str:
    """Hidden password input with ESC-to-cancel."""
    return _read_line(prompt, echo=False)


# =================================================================================
# MENU — in-place reprint + single-threaded D&D burst detection
# =================================================================================
# No background thread touches stdin.  D&D is detected by timing: characters
# arriving within _BURST_TIMEOUT of each other form a burst.  When the burst
# ends (timeout expires or \n received) we test whether the accumulated string
# is a valid filesystem path.  If yes → D&D.  If no → treat first char as the
# menu choice.  This runs entirely on the main thread; concurrent fd access is
# impossible by construction.

_MENU_BODY = [
    "=== SecCRY SYSTEM v3  -  ENCRYPTION CONTAINER FOR TEXT & FILES ===",
    "1. Encrypt text",
    "2. Decrypt text",
    "3. Encrypt file",
    "4. Decrypt file",
    "5. About",
    "6. Exit",
    "(Drag and drop a file into the terminal at any time)",
]
_MENU_PROMPT = "> "
# Total lines printed by one menu frame = body lines + 1 prompt line.
# To reprint in-place we move the cursor up by len(_MENU_BODY) lines
# (the prompt line is on the current line so it doesn't count for cursor-up).
_MENU_BODY_HEIGHT = len(_MENU_BODY)


def _menu_print(first: bool) -> None:
    """
    Print (or overwrite in-place) the menu.
    Uses ANSI escape codes:
      \x1b[{n}A  — cursor up n lines
      \x1b[K     — erase to end of line
    """
    if not first:
        # Move up past all body lines; cursor is currently at the start of the
        # prompt line, which we'll overwrite too.
        sys.stdout.write(f"\x1b[{_MENU_BODY_HEIGHT}A\r")

    for line in _MENU_BODY:
        sys.stdout.write(f"{line}\x1b[K\n")

    # Prompt stays on current line, no trailing newline.
    sys.stdout.write(f"\x1b[K{_MENU_PROMPT}")
    sys.stdout.flush()


def _try_dnd(raw: str) -> str | None:
    """Return the resolved path if `raw` is an existing filesystem path, else None."""
    candidate = raw.strip().strip('"').strip("'")
    if len(candidate) < _BURST_MIN_LEN:
        return None
    expanded = os.path.abspath(os.path.expanduser(candidate))
    return expanded if os.path.exists(expanded) else None


def _menu_input_loop() -> str:
    """
    Read one menu choice, with D&D burst detection.

    Returns:
      "_DND_:<path>"  if a drag-and-drop path was detected
      ""              on ESC (caller redraws)
      A digit string  for a normal menu choice
    Raises KeyboardInterrupt on Ctrl-C.

    Characters arriving within _BURST_TIMEOUT of each other are collected into
    a burst buffer.  After the burst ends we test for a D&D path.  Single
    characters typed at human speed are echoed and returned on Enter normally.
    """
    buf:            list[str] = []
    last_char_time: float     = 0.0
    in_burst:       bool      = False

    while True:
        now = time.monotonic()

        # ---- Burst timeout: burst started but nothing new has arrived ----
        if in_burst and buf and (now - last_char_time) > _BURST_TIMEOUT:
            candidate = "".join(buf)
            path = _try_dnd(candidate)
            buf.clear()
            in_burst = False
            if path:
                return f"_DND_:{path}"
            # Not a path: use the first character as the menu choice.
            return candidate[0] if candidate else ""

        # ---- Read next byte (1 ms timeout) ----
        if _IS_WINDOWS:
            if not msvcrt.kbhit():
                time.sleep(0.001)
                continue
            ch = msvcrt.getwch()

            if ch == "\x1b":
                buf.clear(); in_burst = False
                return ""
            elif ch == "\x03":
                raise KeyboardInterrupt
            elif ch in ("\x00", "\xe0"):
                msvcrt.getwch()
                continue
            elif ch in ("\r", "\n"):
                sys.stdout.write("\n"); sys.stdout.flush()
                choice = "".join(buf).strip()
                buf.clear(); in_burst = False
                return choice
            elif ch == "\x08":
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b"); sys.stdout.flush()
                continue
            char = ch
        else:
            raw_byte = _term.read_byte(0.001)
            if raw_byte is None:
                continue

            if raw_byte == b"\x1b":
                _term.drain_escape()
                buf.clear(); in_burst = False
                return ""
            elif raw_byte == b"\x03":
                raise KeyboardInterrupt
            elif raw_byte == b"\x04":
                raise EOFError
            elif raw_byte in (b"\r", b"\n"):
                sys.stdout.write("\n"); sys.stdout.flush()
                choice = "".join(buf).strip()
                buf.clear(); in_burst = False
                return choice
            elif raw_byte in (b"\x7f", b"\x08"):
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b"); sys.stdout.flush()
                continue
            try:
                char = raw_byte.decode("utf-8")
            except UnicodeDecodeError:
                continue

        # ---- Accumulate ----
        char_time = time.monotonic()
        if buf:
            # Check gap since last character to determine if we're in a burst.
            gap = char_time - last_char_time
            if gap < _BURST_TIMEOUT:
                in_burst = True
            else:
                # Gap too long — flush previous char as choice, start fresh.
                prev = buf[0]
                buf.clear()
                in_burst = False
                # If previous lone char was typed and Enter never came, treat it
                # as the choice now and put the new char back conceptually by
                # processing it next iteration — but since we already have char,
                # just return prev and let the caller see the next char on redraw.
                # Only do this if prev is a printable non-whitespace choice.
                if prev.strip():
                    # Push `char` into a fresh buf so it isn't lost.
                    buf.append(char)
                    last_char_time = char_time
                    sys.stdout.write(char); sys.stdout.flush()
                    return prev
        last_char_time = char_time
        buf.append(char)
        sys.stdout.write(char); sys.stdout.flush()


def handle_dnd_file(path: str) -> None:
    """Interactively ask what to do with a drag-and-dropped file."""
    sys.stdout.write("\n")
    print(f"  ↓  File detected: {path}")
    print("  What would you like to do with this file?")
    print("  1. Encrypt")
    print("  2. Decrypt")
    print("  (ESC or any other key to dismiss)")
    try:
        choice = prompt_input("  > ").strip()
    except (CancelledError, KeyboardInterrupt):
        print("  Dismissed.")
        return
    if choice == "1":
        encrypt_file(path)
    elif choice == "2":
        decrypt_file(path)
    else:
        print("  Dismissed.")


# =================================================================================
# ARGON2 KEY DERIVATION  (with progress spinner)
# =================================================================================

def derive_key(
    password: str,
    salt: bytes,
    time_cost: int   = KDF_TIME_COST,
    memory_cost: int = KDF_MEM_COST_KIB,
    parallelism: int = KDF_PARALLELISM,
) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KDF_HASH_LEN,
        type=Type.ID,
    )


def _run_spinner(label: str, stop_event: threading.Event) -> None:
    frames = ["|", "/", "-", "\\"]
    i = 0
    sys.stdout.write(f"  {label} {frames[0]}")
    sys.stdout.flush()
    while not stop_event.is_set():
        time.sleep(0.1)
        i = (i + 1) % len(frames)
        sys.stdout.write(f"\r  {label} {frames[i]}")
        sys.stdout.flush()
    sys.stdout.write(f"\r  {label} done\n")
    sys.stdout.flush()


def derive_key_with_spinner(
    password: str,
    salt: bytes,
    time_cost: int   = KDF_TIME_COST,
    memory_cost: int = KDF_MEM_COST_KIB,
    parallelism: int = KDF_PARALLELISM,
) -> bytes:
    """Run Argon2 on a worker thread; show a spinner on the main thread."""
    result:  list = []
    exc_box: list = []
    stop = threading.Event()

    def worker():
        try:
            result.append(derive_key(password, salt, time_cost, memory_cost, parallelism))
        except Exception as e:
            exc_box.append(e)
        finally:
            stop.set()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    _run_spinner("Deriving key...", stop)
    t.join()
    if exc_box:
        raise exc_box[0]
    return result[0]


# =================================================================================
# PASSWORD VALIDATION & PROMPTS
# =================================================================================

def validate_password_length(pw: str) -> str | None:
    if len(pw) < MIN_PW_LEN:
        return f"Password too short (minimum {MIN_PW_LEN} characters)."
    if len(pw) > MAX_PW_LEN:
        return f"Password too long (maximum {MAX_PW_LEN} characters)."
    return None


def prompt_password_encrypt(label: str = "Password") -> str:
    while True:
        pw = prompt_secret(f"{label} (ESC to cancel): ")
        err = validate_password_length(pw)
        if err:
            print(err + " Try again.")
            continue
        pw2 = prompt_secret(f"Confirm {label}: ")
        if pw == pw2:
            return pw
        print("Passwords do not match. Try again.")


def prompt_password_decrypt(label: str = "Password") -> str:
    while True:
        pw = prompt_secret(f"{label} (ESC to cancel): ")
        err = validate_password_length(pw)
        if err:
            print(err + " Try again.")
            continue
        return pw


# =================================================================================
# AES-256-GCM ENCRYPT / DECRYPT
# =================================================================================

def encrypt_bytes(data: bytes, password: str) -> bytes:
    err = validate_password_length(password)
    if err:
        raise ValueError(err)
    salt       = os.urandom(16)
    iv         = os.urandom(12)
    kdf_params = struct.pack("!HIB", KDF_TIME_COST, KDF_MEM_COST_KIB, KDF_PARALLELISM)
    key        = derive_key_with_spinner(password, salt)
    ct_and_tag = AESGCM(key).encrypt(iv, data, None)
    return HEADER + salt + iv + kdf_params + ct_and_tag


def decrypt_bytes(raw: bytes, password: str) -> bytes:
    err = validate_password_length(password)
    if err:
        raise ValueError(err)
    if not raw.startswith(MAGIC):
        raise ValueError(
            "Not a valid SCRY file (missing magic header). "
            "File may be corrupted or not encrypted by SecCRY."
        )
    if raw[len(MAGIC):len(HEADER)] != VERSION:
        found    = raw[len(MAGIC):len(HEADER)].hex()
        expected = VERSION.hex()
        raise ValueError(
            f"Unsupported SCRY version (found 0x{found}, expected 0x{expected}). "
            "This file may have been created by a different version of SCRY."
        )
    raw = raw[len(HEADER):]
    if len(raw) < 51:
        raise ValueError("Data too short to be a valid SCRY payload.")
    salt = raw[:_OFF_SALT_END]
    iv   = raw[_OFF_SALT_END:_OFF_IV_END]
    time_cost, mem_cost_kib, parallelism = struct.unpack(
        "!HIB", raw[_OFF_IV_END:_OFF_PAR_END]
    )
    ct_and_tag = raw[_OFF_PAR_END:]
    key = derive_key_with_spinner(
        password, salt,
        time_cost=time_cost,
        memory_cost=mem_cost_kib,
        parallelism=parallelism,
    )
    return AESGCM(key).decrypt(iv, ct_and_tag, None)


# =================================================================================
# SCRY FILE PACKING
# =================================================================================

def pack_file(filename: str, data: bytes) -> bytes:
    name_bytes = filename.encode("utf-8")
    return struct.pack("!I", len(name_bytes)) + name_bytes + data


def unpack_file(data: bytes) -> tuple:
    if len(data) < 4:
        raise ValueError("Packed data too short.")
    name_len = struct.unpack("!I", data[:4])[0]
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
    name = os.path.basename(name)
    if not name:
        raise ValueError("Filename in packed data is empty or invalid.")
    return name, data[4 + name_len:]


# =================================================================================
# SAFE OUTPUT PATH
# =================================================================================

def safe_output_path(directory: str, base: str, ext: str) -> str:
    """Collision-free output path using O_CREAT|O_EXCL (closes TOCTOU window)."""
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


# =================================================================================
# NORMALIZE PATH
# =================================================================================

def normalize_path(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path.strip().strip('"').strip("'")))


# =================================================================================
# ENCRYPT / DECRYPT FILE
# =================================================================================

def encrypt_file(path: str) -> None:
    path = normalize_path(path)
    if not os.path.exists(path):
        print("File not found. Returning to menu.")
        return
    try:
        password = prompt_password_encrypt()
    except (CancelledError, KeyboardInterrupt):
        print("\nCancelled.")
        return
    try:
        with open(path, "rb") as f:
            file_data = f.read()
        filename  = os.path.basename(path)
        packed    = pack_file(filename, file_data)
        encrypted = encrypt_bytes(packed, password)
        base      = os.path.splitext(path)[0]
        out_path  = safe_output_path(
            os.path.dirname(path) or ".",
            os.path.basename(base) + "SecCRYv3",
            ".SCRY",
        )
        with open(out_path, "wb") as f:
            f.write(encrypted)
        print(f"\nFile sealed → {out_path}")
    except OSError as e:
        print(f"File error: {e}")
    except Exception as e:
        print(f"Encryption failed: {e}")
        traceback.print_exc()


def decrypt_file(path: str) -> None:
    path = normalize_path(path)
    if not os.path.exists(path):
        print("File not found. Returning to menu.")
        return
    try:
        password = prompt_password_decrypt()
    except (CancelledError, KeyboardInterrupt):
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
        print(f"\nOriginal file detected: {original_name}")
        print(f"  → Restore as: {stem}{ext}  |  Decline to use: {stem}.restored")
        try:
            confirm = prompt_input(
                "Restore original file extension? (y/n, ESC to cancel): "
            ).strip().lower()
        except CancelledError:
            print("Cancelled.")
            return
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


# =================================================================================
# TEXT MODE
# =================================================================================

def encrypt_text(msg: str, password: str) -> str:
    return base64.b64encode(encrypt_bytes(msg.encode(), password)).decode()


def decrypt_text(token: str, password: str) -> str:
    try:
        raw = base64.b64decode(token.encode(), validate=True)
    except Exception:
        raise ValueError("Invalid base64 input — cipher text is malformed.")
    plaintext_bytes = decrypt_bytes(raw, password)
    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "Decrypted content is not valid UTF-8 text. "
            "This payload may be a file — use option 4 (Decrypt file) instead."
        )


# =================================================================================
# MAIN MENU LOOP
# =================================================================================

if __name__ == "__main__":
    if not _IS_WINDOWS:
        _term.enter()

    try:
        first_print = True

        while True:
            _menu_print(first_print)
            first_print = False

            try:
                raw_choice = _menu_input_loop()
            except CancelledError:
                continue
            except KeyboardInterrupt:
                sys.stdout.write("\nExiting.\n")
                break

            # ---- Drag-and-drop ----
            if raw_choice.startswith("_DND_:"):
                path = raw_choice[len("_DND_:"):]
                handle_dnd_file(path)
                first_print = True
                continue

            choice = raw_choice.strip()

            if choice == "1":
                try:
                    msg = prompt_input("Message (ESC to cancel): ")
                    pw  = prompt_password_encrypt()
                    print("\nEncrypted:\n", encrypt_text(msg, pw))
                except CancelledError:
                    print("\nCancelled.")
                except KeyboardInterrupt:
                    print("\nCancelled.")
                except Exception as e:
                    print(f"Encryption failed: {e}")
                    traceback.print_exc()
                input("\nPress Enter to return to menu...")
                first_print = True

            elif choice == "2":
                try:
                    msg = prompt_input("Cipher (ESC to cancel): ")
                    pw  = prompt_password_decrypt()
                    print("\nDecrypted:\n", decrypt_text(msg, pw))
                except CancelledError:
                    print("\nCancelled.")
                except KeyboardInterrupt:
                    print("\nCancelled.")
                except InvalidTag:
                    print("Wrong password or corrupted data.")
                except ValueError as e:
                    print(f"Decryption failed: {e}")
                except Exception as e:
                    print(f"Decryption failed: {e}")
                    traceback.print_exc()
                input("\nPress Enter to return to menu...")
                first_print = True

            elif choice == "3":
                try:
                    path = prompt_input("File path (ESC to cancel): ")
                    encrypt_file(path)
                except CancelledError:
                    print("\nCancelled.")
                except KeyboardInterrupt:
                    print("\nCancelled.")
                input("\nPress Enter to return to menu...")
                first_print = True

            elif choice == "4":
                try:
                    path = prompt_input("SCRY file path (ESC to cancel): ")
                    decrypt_file(path)
                except CancelledError:
                    print("\nCancelled.")
                except KeyboardInterrupt:
                    print("\nCancelled.")
                input("\nPress Enter to return to menu...")
                first_print = True

            elif choice == "5":
                print(ABOUT_TEXT)
                input("Press Enter to return to menu...")
                first_print = True

            elif choice == "6":
                sys.stdout.write("\n")
                break

            elif choice == "":
                pass   # ESC or empty burst — just redraw

            else:
                # Invalid: reprint menu in-place (first_print stays False)
                # The stray characters are already echoed on the prompt line;
                # the next _menu_print call will overwrite everything cleanly.
                pass

    finally:
        if not _IS_WINDOWS:
            _term.leave()