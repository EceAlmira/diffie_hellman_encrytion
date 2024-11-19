from math import sqrt
from secrets import choice
import paho.mqtt.client as mqtt
from time import sleep
import ast

class Tools:

    @staticmethod
    def text_to_numerical(text):
        # Convert each character in the text to its ASCII value using ord()
        return [ord(char) for char in text]

    @staticmethod
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = Tools.extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    @staticmethod
    def modexp(base, exp, modulus):
        return pow(base, exp, modulus)

    @staticmethod
    def is_prime(number):
        if number == 2 or number == 3:
            return True
        elif number % 2 == 0 or number < 2:
            return False
        for current_number in range(3, int(sqrt(number)) + 1, 2):
            if number % current_number == 0:
                return False
        return True

    @staticmethod
    def generate_prime_number(min_value=0, max_value=300):
        primes = [number for number in range(min_value, max_value) if Tools.is_prime(number)]
        return choice(primes)

    @staticmethod
    def getG(p):
        for x in range(1, p):
            rand = x
            exp = 1
            next = rand % p
            while next != 1:
                next = (next * rand) % p
                exp += 1
            if exp == p - 1:
                return rand  # Return the first primitive root found
        raise ValueError("No primitive root found")

class Encryption(Tools):
    def __init__(self, p, private_secret, B, text_message):
        self.p = p
        self.g = self.getG(p)
        self.private_secret = private_secret
        self.B = B
        self.message_list = self.text_to_numerical(text_message)
        self.encrypted_message_list = []
        self.message = text_message

    def calculate_secret(self):
        # Use the received B to calculate the shared secret
        if self.B is not None:
            return pow(self.B, self.private_secret, self.p)

    def send_encrypted_message(self):
        secret = self.calculate_secret()
        for num in self.text_to_numerical(self.message):
            # Encrypt using the shared secret
            self.encrypted_message_list.append((self.B, (num * secret) % self.p))
        return self.encrypted_message_list

class Decryption(Tools):
    def __init__(self, p, private_secret, message):
        self.p = p
        self.g = self.getG(p)
        self.private_secret = private_secret
        self.message = message
        self.decrypted_message = []

    def calculate_secret_key(self, B):
        # Calculate the shared secret using B and private key
        return pow(B, self.private_secret, self.p)

    def find_inverse_key(self, key):
        gcd, inverse_key, _ = self.extended_gcd(key, self.p)
        if gcd != 1:
            raise ValueError("Inverse does not exist")
        return inverse_key % self.p

    def decrypt(self):
        for message in self.message:
            B, encrypted_num = message
            key = self.calculate_secret_key(B)
            inverse_key = self.find_inverse_key(key)
            decrypted_char = (encrypted_num * inverse_key) % self.p
            self.decrypted_message.append(chr(decrypted_char))
        return "".join(self.decrypted_message)
    
class ComputerB(Tools):
    def __init__(self, broker, port, topic, topic_encryption, p, private_secret):
        # Initialization and MQTT setup
        self.broker = broker
        self.port = port
        self.topic = topic
        self.topic_encryption = topic_encryption
        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        
        # Parameters
        self.p = p
        self.g = self.getG(self.p)
        self.private_secret = private_secret
        self.A = None  # Public key from Computer A

    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code " + str(rc))
        self.client.subscribe(self.topic)
        self.client.subscribe(self.topic_encryption)

    def on_message(self, client, userdata, msg):
        if msg.topic == self.topic:
            # Received a public key from Computer A
            try:
                self.A = int(msg.payload.decode('utf-8'))
                # Send the public key to Computer A
                public_key = pow(self.g, self.private_secret, self.p)
                self.client.publish(self.topic, str(public_key).encode("utf-8"))
            except ValueError:
                print("Failed to parse A value.")
        elif msg.topic == self.topic_encryption:
            # Received an encrypted message; decrypt it
            encrypted_message = ast.literal_eval(msg.payload.decode('utf-8'))
            decrypted_message = self.decrypt_message(encrypted_message)
            print(f"Decrypted message from A: {decrypted_message}")

            # Re-encrypt and send it back to A
            encrypted_message = self.encrypt_message(decrypted_message)
            self.client.publish(self.topic_encryption, str(encrypted_message).encode("utf-8"))

    def encrypt_message(self, message):
        # Encrypt using A received from Computer A
        encryption = Encryption(self.p, self.private_secret, self.A, message)
        return encryption.send_encrypted_message()

    def decrypt_message(self, message):
        # Decrypt the received message
        decryption = Decryption(self.p, self.private_secret, message)
        return decryption.decrypt()

    def run(self):
        self.client.connect(self.broker, self.port, 60)
        self.client.loop_start()
        try:
            # Send the initial public key to Computer A
            public_key = pow(self.g, self.private_secret, self.p)
            self.client.publish(self.topic, str(public_key).encode("utf-8"))
            while True:
                sleep(1)
        except KeyboardInterrupt:
            self.client.loop_stop()


broker = "192.168.198.126"
port = 1883
topic = "communication/public_key"
topic_encryption = "communication/encryption"

# Instantiate the ComputerB object and run the MQTT client
computer_b = ComputerB(broker, port, topic, topic_encryption, 2137, 5)
computer_b.run()           