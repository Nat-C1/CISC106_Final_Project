
from drafter import *
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from bakery import assert_equal

# ==========================================
# RSA CONSTANTS
# ==========================================

RSA_P = 1009
RSA_Q = 1013
RSA_N = RSA_P * RSA_Q
RSA_PHI = (RSA_P - 1) * (RSA_Q - 1)


def calculate_private_key(e: int) -> str:
    d = pow(e, -1, RSA_PHI)
    return str(d)


# ==========================================
# DATA CLASSES
# ==========================================

@dataclass
class Message:
    plaintext: str
    ciphertext: str
    key: str
    public_key: str
    private_key: str


@dataclass
class State:
    messages: list[Message]
    algorithm: str
    encrypt: str
    message_input: str


# ==========================================
# MAIN PAGE
# ==========================================

@route
def index(state: State) -> Page:
    """The main page of the website
Args: state - state of website
Returns: Main pages to take in the input for all of the other pages"""
    
    return Page(state, [
        Header("Cryptography Website"),

        Text("Enter one or more messages, with each message on a new line."),

        Header("Messages", 5),
        TextArea("message_input"),

        Header("Encryption / Decryption Key", 5),
        Text("Key formats:"), '\n',
        Text("Caesar: Whole number (example: 5)"), '\n',
        Text("RSA: Public exponent e (example: 17)"), '\n',
        Text("RSA modulus n is automatically set to " + str(RSA_N)), '\n',
        Text("AES: 16 byte key, 16 normal ASCII characters (example: 1234567890ab3456)"), '\n',
        Text("MD-5: No key required"), '\n',
        Text("SHA-256: No key required"), '\n',

        TextBox("key"),

        Header("Algorithm", 5),
        SelectBox(
            "algorithm",
            ["RSA", "Caesar", "MD-5", "AES", "SHA-256"], state.algorithm),

        Header("Operation", 5),
        SelectBox(
            "encrypt",
            ["Encrypt", "Decrypt"], state.encrypt),

        Button("Execute", update_state)
    ])

@route
def update_state(state:State, message_input:str, key:str, algorithm:str, encrypt:str):
    """takes the arguments from the main page and updates the state, error occur if state updates from main page fields
Args: state - the state of website
message_input, the message input from main page
key - string from the key field on main page
algorithm - from the select field on main page
encrypt - from the second select box

Returns: execute route, and updated state"""


    state.message_input = message_input
    state.algorithm = algorithm
    state.encrypt = encrypt
    return execute(state, key)

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

# CAESAR CIPHER AREA

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

def ceasar_encrypt_text(string: str, rotate: int) -> str:
    """encrypts the string input by rotating it the amount indicated
Args:
    string: message to be rotated
    rotate: amount to rotate
Returns:
    Rotated string"""
    
    rotated = ""

    for char in string:
        original = ord(char)

        if 32 <= original <= 126:
            rotation = ((original - 32 + rotate) % 95) + 32
            rotated += chr(rotation)
        else:
            rotated += char

    return rotated


def ceasar_decrypt_text(cipher: str, rotate: int) -> str:
    """decrypts the string by rotating it the amount indicated
Atgs:
    cipher: encrypted text
    rotate: amount to rotate
Returns:
    unencrypted string"""
    
    normal = ""

    for char in cipher:
        original = ord(char)

        if 32 <= original <= 126:
            rotation = ((original - 32 - rotate) % 95) + 32
            normal += chr(rotation)
        else:
            normal += char

    return normal


@route
def ceasar(state: State) -> Page:
    """takes in the state of the website and produces the output of the options in the state
Args:
    state: website state
Returns:
    a page displaying whether it should encrypt or decrypt, the key, and the rotated string"""
    
    components = [
        Header("Caesar Cipher Results"),
        Text("Operation: " + state.encrypt),
        Header("Results", 5)
    ]

    for message in state.messages:
        if state.encrypt == "Encrypt":
            message.ciphertext = ceasar_encrypt_text(message.plaintext, int(message.key))
        else:
            message.ciphertext = ceasar_decrypt_text(message.plaintext, int(message.key))

        components.append(Text(message.ciphertext))
        components.append('\n')

    components.append(Button("Back to Main Page", index))

    return Page(state, components)

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

# RSA AREA

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

# RSA ENCRYPTION

def rsa_encrypt_text(state:State, message: Message):
    """takes in the state and the message to be encrypted
Args:
    state: website state
    message: message to be encrypted
Returns:
    the encrypted message as a sring of ',' seperated #'s"""
    
    n = RSA_N
    e = int(message.public_key)

    ciphertext = []

    for char in message.plaintext:
        number = ord(char)
        encrypted = pow(number, e, n)
        ciphertext.append(str(encrypted))

    message.ciphertext = ",".join(ciphertext)

# RSA DECRYPTION

def rsa_decrypt_text(state:State, message: Message):
    """takes in the state and the message to be decrypted
Args:
    state: website state
    message: encrypted message as a sring of ',' seperated #'s
Returns:
    the unencrypted message"""
    
    n = RSA_N
    d = int(message.private_key)
    

    plaintext = ""

    for number in message.ciphertext.split(","):
        if number.strip():
            decrypted = pow(int(number), d, n)
            plaintext += chr(decrypted)

    message.plaintext = plaintext

# ==========================================
# RSA RESULTS PAGE
# ==========================================

@route
def rsa_page(state: State) -> Page:
    """takes in the state and produces a page of the results of running the correct above function
Args:
    state: website state
Returns:
    a page of the given message, the other half of the message, the key(s), and which way it was sent"""

    components = [
        Header("RSA Results"),
        Text("Operation: " + state.encrypt),
        Text("RSA Modulus (n): " + str(RSA_N)),
        Header("Results", 5)
    ]

    for message in state.messages:

        if state.encrypt == "Encrypt":
            rsa_encrypt_text(state, message)

        else:
            rsa_decrypt_text(state, message)

        components.append(Text("Plaintext: " + message.plaintext))
        components.append('\n')
        components.append(Text("Ciphertext: " + message.ciphertext))
        components.append('\n')
        components.append(Text("Public Key: " + message.public_key))
        components.append('\n')
        components.append(Text("Private Key: " + message.private_key))
        components.append('\n')
        
    components.append(Button("Back to Main Page", index))

    return Page(state, components)

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

# AES AREA

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

def aes_encrypt_text(message: Message):
    """Takes in the message to be encrypted and returns the cipher text
Args:
    message: Message dataclass with needed information for encryption
Returns:
    the encrypted text added to the message dataclass"""

    key = message.key.encode("utf-8")

    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    padded_text = (
        padder.update(message.plaintext.encode("utf-8"))
        + padder.finalize()
    )

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    encryptor = cipher.encryptor()

    ciphertext = (encryptor.update(padded_text) + encryptor.finalize())

    message.ciphertext = base64.b64encode(ciphertext).decode("utf-8")

def aes_decrypt_text(message: Message):
    """Takes in the message to be decrypted
Args:
    message: Message dataclass with needed information to be decrypted
Returns:
    updated Message dataclass"""
    key = message.key.encode("utf-8")

    ciphertext = base64.b64decode(message.plaintext)

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    decryptor = cipher.decryptor()

    padded_text = (decryptor.update(ciphertext) + decryptor.finalize())

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    plaintext = (unpadder.update(padded_text) + unpadder.finalize())

    message.plaintext = plaintext.decode("utf-8")

@route
def aes_page(state: State) -> Page:
    """A page that shows the results of the earlier 2 functions, and the information in the state dataclass
Args:
    state: total website state
Returns:
    a page with the key shown, both messages, an error page for an incorrect key"""
    
    components = [
        Header("AES Results"),
        Text("Operation: " + state.encrypt), '\n',
        Text("Algorithm: AES-128-ECB"), '\n',
        Header("Results", 5)
    ]

    for message in state.messages:

        if len(message.key.encode("utf-8")) != 16:
            return Page(state, [
                Header("AES Error"),
                Text("Invalid AES key size."),
                Text("AES-128 requires exactly 16 bytes."),
                Text("Your key contains " +
                     str(len(message.key.encode("utf-8"))) + " bytes."),
                Button("Back to Main Page", index)
            ])

        if state.encrypt == "Encrypt":
            aes_encrypt_text(message)

        else:
            aes_decrypt_text(message)

        components.append(Text("Plaintext: " + message.plaintext))
        components.append('\n')
        components.append(Text("Ciphertext: " + message.ciphertext))
        components.append('\n')

    components.append(Button("Back to Main Page", index))

    return Page(state, components)

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

# MD-5 AREA

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

def md5_text(message: Message):
    """takes the message and returns the hash
Args: message dataclass with required fields
Returns: updated dataclass with hash"""
    
    plaintext = message.plaintext.encode("utf-8")

    message.ciphertext = MD5.new(plaintext).hexdigest()

@route
def md5_page(state: State) -> Page:
    """A page displaying the information of the state dataclass and above function
Args:
    state: state of website
Returns:
    a page with the algorithm name, hash, and message"""
    
    components = [
        Header("MD5 Results"),
        Text("Algorithm: MD5"), '\n',
        Text("Operation: Hash"), '\n',
        Header("Results", 5)
    ]

    for message in state.messages:

        md5_text(message)

        components.append(Text("Original Message: " + message.plaintext))
        components.append('\n')
        components.append(Text("MD5 Hash: " + message.ciphertext))
        components.append('\n')

    components.append(
        Button("Back to Main Page", index)
    )

    return Page(state, components)



# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

# SHA-256 AREA

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

def sha256_text(message: Message):
    """produces a SHA-256 hash of the given information
Args:
    message: message dataclass with needed fields
Returns:
    updated dataclass with hash added"""
    
    plaintext = message.plaintext.encode("utf-8")

    message.ciphertext = SHA256.new(plaintext).hexdigest()

@route
def sha256_page(state: State) -> Page:
    """Page displaying the information when SHA-256 is chosen
Args:
    state: state of website
Returns:
    Page with algorithm title, plaintext, and hash"""
    
    components = [
        Header("SHA-256 Results"),
        Text("Algorithm: SHA-256"), '\n',
        Text("Operation: Hash"), '\n',
        Header("Results", 5)
    ]

    for message in state.messages:

        sha256_text(message)

        components.append(Text("Original Message: " + message.plaintext))
        components.append('\n')
        components.append(Text("SHA-256 Hash: " + message.ciphertext))
        components.append('\n')

    components.append(
        Button("Back to Main Page", index)
    )

    return Page(state, components)

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

# AREA

# =====================================================================================================================
# =====================================================================================================================
# =====================================================================================================================

def format_message(state: State, key:str) -> State:
    """formats the message dataclass and adds them to the state.messages field
Args:
    state: state of website
    key: encryption key
Returns:
    state of the website, with state.messages formatted correctly"""
    
    state.messages = []

    for message_text in state.message_input.split("\n"):

        if message_text.strip() != "":

            message = Message(
                plaintext="",
                ciphertext="",
                key=key,
                public_key="",
                private_key=""
            )

            message.plaintext = message_text

            
            state.messages.append(message)

        if state.algorithm == "RSA":
            if state.encrypt == "Encrypt":
                message.public_key = key
                message.private_key = calculate_private_key(int(key))

            elif state.encrypt == "Decrypt":
                message.private_key = key
                message.ciphertext = message_text

    return state

# ==========================================
# EXECUTE SELECTED ALGORITHM
# ==========================================

@route
def execute(state: State, key: str) -> Page:
    """decides which page to run
Args:
    state: website state
    key: encryption key
Returns:
    the correct page for the algorithm chosen"""
    
    state = format_message(state,key)

    if state.algorithm == "RSA":
        return rsa_page(state)

    elif state.algorithm == "Caesar":
        return ceasar(state)

    elif state.algorithm == "MD-5":
        return md5_page(state)

    elif state.algorithm == "AES":
        return aes_page(state)

    elif state.algorithm == "SHA-256":
        return sha256_page(state)

    return index(state)


# ==========================================
# START WEBSITE
# ==========================================

set_site_information('Nate Cheek', 
'''An educational example of different cryptographic algorithms, 
    including RSA, Ceasar Cipher, AES-ECB, MD-5, and SHA-256. 
        Multiple messages are able to be encrypted at once with the same key.''',
                     
'sources were personal knowledge of the algorithms and thefile named "GPT_LOG.pdf" in the repository',
                     
                     'Planning is accessible in repository in "CS106 Final Planning Document ____"',
                     
                     'NEEDED?')


start_server(State([],"","",""))


