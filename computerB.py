from math import sqrt
from secrets import choice
import paho.mqtt.client as mqtt
from time import sleep
import ast
from typing import List, Tuple

class Tools:
    """A collection of utility methods for mathematical operations and cryptography."""
    @staticmethod
    def text_to_numerical(text: str) -> List[int]:
        """
        Convert a string into a list of its ASCII numerical values.

        Args:
            text (str): The input text.

        Returns:
            list[int]: List of ASCII values for each character in the text.
        """
        return [ord(char) for char in text]

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Compute the extended greatest common divisor (GCD) of two numbers.

        Args:
            a (int): First number.
            b (int): Second number.

        Returns:
            tuple[int, int, int]: GCD and coefficients for the linear combination.
        """
        if b == 0:
            # Base case: If b is 0, then GCD is a, and coefficients are 1 and 0
            return a, 1, 0
        # Recursively call extended_gcd on b and a % b
        gcd, x1, y1 = Tools.extended_gcd(b, a % b)
        # Compute new coefficients
        x = y1
        y = x1 - (a // b) * y1
        # Return the GCD and coefficients (x, y)
        return gcd, x, y

    @staticmethod
    def modexp(base: int, exp: int, modulus: int) -> int:
        """
        Perform modular exponentiation.

        Args:
            base (int): The base value.
            exp (int): The exponent value.
            modulus (int): The modulus.

        Returns:
            int: Result of (base^exp) % modulus.
        """
        return pow(base, exp, modulus)

    @staticmethod
    def getG(p: int) -> int:
        """
        Find a primitive root modulo p.

        Args:
            p (int): A prime number.

        Returns:
            int: A primitive root modulo p.

        Raises:
            ValueError: If no primitive root is found.
        """
        # Try all numbers from 1 to p-1 as potential primitive roots
        for x in range(1, p):
            rand = x
            exp = 1
            next = rand % p
            # Check if the number generates all powers modulo p
            while next != 1:
                next = (next * rand) % p
                exp += 1
            # If the exponent reaches p-1, then rand is a primitive root
            if exp == p - 1:
                return rand  # Return the first primitive root found
        raise ValueError("No primitive root found")

class Encryption(Tools):
    """Handles encryption logic using Diffie-Hellman-like key exchange."""
    def __init__(self, p: int, private_secret: int, B: int, text_message: str):
        """
        Initialize the encryption object.

        Args:
            p (int): Prime modulus.
            private_secret (int): The private key of the sender.
            B (int): Public key of the recipient.
            text_message (str): Message to be encrypted.
        """
        self.p = p
        # Calculate the primitive root modulo p
        self.g = self.getG(p)
        self.private_secret = private_secret
        self.B = B
        # Convert the message to its numerical ASCII values
        self.message_list = self.text_to_numerical(text_message)
        # List to hold the encrypted message
        self.encrypted_message_list = []
        self.message = text_message
        # Compute the public key of the sender (g^private_secret mod p)
        self.public_key = pow(self.g, self.private_secret, self.p)

    def calculate_secret(self) -> int:
        """
        Calculate the shared secret key using the recipient's public key.

        Returns:
            int: The shared secret key.
        """
        if self.B is not None:
            return pow(self.B, self.private_secret, self.p)

    def send_encrypted_message(self) -> List[Tuple[int, int]]:
        """
        Encrypt the message using the shared secret.

        Each character's ASCII value is multiplied by the shared secret and reduced modulo p.
        The public key of the sender is paired with each encrypted value

        Returns:
            list[tuple[int, int]]: List of encrypted character tuples (public key, encrypted ASCII).
        """
        # Calculate the shared secret
        secret = self.calculate_secret()
        for num in self.text_to_numerical(self.message):
            # Encrypt each character by multiplying its ASCII value with the shared secret, modulo p
            self.encrypted_message_list.append((self.public_key, (num * secret) % self.p))
        return self.encrypted_message_list

class Decryption(Tools):
    """Handles decryption logic using Diffie-Hellman-like key exchange."""

    def __init__(self, p: int, private_secret: int, message: List[Tuple[int, int]]):
        """
        Initialize the decryption object.

        Args:
            p (int): Prime modulus.
            private_secret (int): The private key of the recipient.
            message (list[tuple[int, int]]): The encrypted message to be decrypted.
        """
        self.p = p
        # Calculate the primitive root modulo p
        self.g = self.getG(p)
        self.private_secret = private_secret
        self.message = message
        # List to hold the decrypted message
        self.decrypted_message = []

    def calculate_secret_key(self, A: int) -> int:
        """
        Calculate the shared secret key using the sender's public key.

        The shared secret is computed as A^private_secret mod p, where A is the sender's public k

        Args:
            A (int): Public key of the sender.

        Returns:
            int: The shared secret key.
        """
        return pow(A, self.private_secret, self.p)

    def find_inverse_key(self, key: int) -> int:
        """
        Find the modular inverse of the shared secret key.

        This inverse is used to decrypt the message. The modular inverse is the value x such that
        (key * x) % p = 1.

        Args:
            key (int): The shared secret key.

        Returns:
            int: The modular inverse of the key.

        Raises:
            ValueError: If no inverse exists.
        """
        # Use the extended Euclidean algorithm to compute the modular inverse
        gcd, inverse_key, _ = self.extended_gcd(key, self.p)
        if gcd != 1:
            # If the gcd is not 1, the modular inverse does not exist
            raise ValueError("Inverse does not exist")
        return inverse_key % self.p

    def decrypt(self) -> str:
        """
        Decrypt the encrypted message.

        For each encrypted character, the modular inverse of the shared secret is used to reverse
        the encryption, and the original ASCII value is recovered.

        Returns:
            str: The decrypted message.
        """
        for message in self.message:
            # For each decoded message tuple (A, x)
            A, x = message
            # Calculate the shared secret key using the sender's public key
            key = self.calculate_secret_key(A)
            # Find the modular inverse of the shared secret key
            inverse_key = self.find_inverse_key(key)
            # Decrypt the message using the modular inverse of the shared secret
            decrypted_message = (x * inverse_key) % self.p
            # Convert the decrypted ASCII value back to a character
            self.decrypted_message.append(chr(decrypted_message))
        return "".join(self.decrypted_message)
    
class ComputerB(Tools):
    """Represents a device capable of sending and receiving messages using MQTT and encryption."""

    def __init__(
        self,
        broker: str,
        port: int,
        topic: str,
        topic_encryption: str,
        p: int,
        private_secret: int,
        sent_message: str,
        send_mode: bool,
        receive_mode: bool,
    ):
        """
        Initialize the ComputerB object.

        Args:
            broker (str): MQTT broker address.
            port (int): MQTT broker port.
            topic (str): Topic for key exchange.
            topic_encryption (str): Topic for message encryption.
            p (int): Prime modulus.
            private_secret (int): Private key of this device.
            sent_message (str): Message to be sent (in send mode).
            send_mode (bool): Whether the device should encrypt and send a message.
            receive_mode (bool): Whether the device should decrypt a received message.
        """
        # Initialization and MQTT setup
        self.broker = broker
        self.port = port
        self.topic = topic
        self.topic_encryption = topic_encryption
        self.client = mqtt.Client()  # Create an MQTT client instance
        self.client.on_connect = self.on_connect  # Set the callback for connection events
        self.client.on_message = self.on_message  # Set the callback for message receipt
        
        # Parameters for encryption and key exchange
        self.p = p
        self.g = self.getG(self.p)  # Calculate the primitive root modulo p
        self.private_secret = private_secret
        self.sent_message = sent_message
        self.A = None  # Public key from Computer A
        self.process_completed = False
        self.send_mode = send_mode
        self.receive_mode = receive_mode

    def on_connect(self, client: mqtt.Client, userdata, flags, rc: int):
        """
        Callback when the MQTT client connects to the broker.

        Args:
            client (mqtt.Client): The client instance.
            userdata: User-defined data.
            flags: Connection flags.
            rc (int): Connection result code.
        """
        print("Connected with result code " + str(rc))  # Print the connection result code
        # Subscribe to the topics for public key exchange and encrypted message reception
        self.client.subscribe(self.topic)
        self.client.subscribe(self.topic_encryption)

    def on_message(self, client: mqtt.Client, userdata, msg: mqtt.MQTTMessage):
        """
        Callback when a message is received on subscribed topics.

        Args:
            client (mqtt.Client): The client instance.
            userdata: User-defined data.
            msg (mqtt.MQTTMessage): The received message.
        """
        # Check if the message is from the expected topic for receiving the public key
        if msg.topic == self.topic:
            try:
                # Parse and store the public key (A) from Computer A
                self.A = int(msg.payload.decode('utf-8'))  # Set A from the received public key
                if self.send_mode:
                    # If in send mode, encrypt the message and send it to the encryption topic
                    encrypted_message = self.encrypt_message(self.sent_message)
                    self.client.publish(self.topic_encryption, str(encrypted_message).encode("utf-8"), qos=2)
                    print(f"The sent message - {self.sent_message}")

                    self.process_completed = True  # Mark the process as completed

            except ValueError:
                print("Failed to parse A value.")  # Handle case where A is not a valid integer
        # Check if the message is from the topic where encrypted messages are received
        elif msg.topic == self.topic_encryption and self.receive_mode:
            encrypted_message = ast.literal_eval(msg.payload.decode('utf-8'))  # Deserialize the encrypted message
            decrypted_message = self.decrypt_message(encrypted_message)
            print(f"Decrypted message from A: {decrypted_message}")

            self.process_completed = True  # Mark the process as completed

    def encrypt_message(self, message: str) -> str:
        """
        Encrypt the given message using the public key (A) received from Computer A.

        Args:
            message (str): The message to be encrypted.

        Returns:
            str: The encrypted message.
        """
        # Encrypt using A received from Computer A
        encryption = Encryption(self.p, self.private_secret, self.A, message)
        return encryption.send_encrypted_message()

    def decrypt_message(self, message: List[Tuple[int, int]]):
        """
        Decrypt the received decoded message and display it.

        Args:
            message (list[tuple[int, int]]): The decoded message.
        """
        decryption = Decryption(self.p, self.private_secret, message)
        return decryption.decrypt()

    def run(self):
        """
        Start the MQTT client and send the public key to Computer A.

        This function connects the client to the MQTT broker, starts the client loop, sends
        the public key to Computer A, and then listens for responses until the process is completed.

        Returns:
            None: This function doesn't return any value.
        """
        # Connect to the MQTT broker and start the client loop
        self.client.connect(self.broker, self.port, 60)
        self.client.loop_start()
        try:
            # Generate and send the public key (B) to Computer A
            public_key = pow(self.g, self.private_secret, self.p)
            self.client.publish(self.topic, str(public_key).encode("utf-8"), qos=2)
            # Keep the loop running until stop condition is met
            while True:
                # Break the loop if process is completed.
                if self.process_completed is True: 
                    break
                sleep(0.1)
        finally:
            print("Communication complete. Stopping Computer B.")
            self.client.loop_stop()  # Stop the MQTT client loop
            self.client.disconnect()  # Disconnect from the MQTT broker


broker = "rasul062-HP-Laptop-15-da1xxx"
port = 1883
topic = "communication/public_key"
topic_encryption = "communication/encryption"

# Instantiate the ComputerB object and run the MQTT client
computer_b = ComputerB(broker, port, topic, topic_encryption, 2137, 5, "deneme", True, False)
computer_b.run()