from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import ast
import base64
import hmac
from hashlib import sha256
import hashlib
import datetime
import time
from timeit import default_timer as timer
import socket 
import struct
import threading
import os
import random
import json
import queue
import pickle
import statistics

def hash_string(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

def generate_keychain(length):
    # Start with a random key.
    keychain = [os.urandom(16).hex()]
    # Generate the rest of the keys.
    for i in range(1, length):
        keychain.insert(0, hash_string(keychain[0]))
    return keychain

# Load private and public keys
with open("private_key_server.pem", "rb") as key_file:
    private_key_server = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

with open("public_key_server.pem", "rb") as key_file:
    public_key_server = serialization.load_pem_public_key(key_file.read())

with open("private_key_client1.pem", "rb") as key_file:
    private_key_client1 = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

with open("public_key_client1.pem", "rb") as key_file:
    public_key_client1 = serialization.load_pem_public_key(key_file.read())

with open("private_key_client2.pem", "rb") as key_file:
    private_key_client2 = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

with open("public_key_client2.pem", "rb") as key_file:
    public_key_client2 = serialization.load_pem_public_key(key_file.read())

with open("private_key_client3.pem", "rb") as key_file:
    private_key_client3 = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

with open("public_key_client3.pem", "rb") as key_file:
    public_key_client3 = serialization.load_pem_public_key(key_file.read())

with open("private_key_client4.pem", "rb") as key_file:
    private_key_client4 = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

with open("public_key_client4.pem", "rb") as key_file:
    public_key_client4 = serialization.load_pem_public_key(key_file.read())

with open("private_key_client5.pem", "rb") as key_file:
    private_key_client5 = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

with open("public_key_client5.pem", "rb") as key_file:
    public_key_client5 = serialization.load_pem_public_key(key_file.read())


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data  
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        hash_data = str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)
        return hashlib.sha256(hash_data.encode('utf-8')).hexdigest()

    def to_dict(self):
        return self.__dict__

class Blockchain:
    def __init__(self):
        self.chain = []
        self.add_genesis_block()

    def add_genesis_block(self):
        index = 0
        #timestamp = 'Genesis Block'
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = 'Genesis Block' # or any default data for genesis block
        # Base64 encode an empty string for the genesis block data
        #data = base64.b64encode(b'Genesis Block').decode()  # Empty base64 string
        previous_hash = '000' # or any default value

        genesis_block = Block(index, timestamp, data, previous_hash)
        self.chain.append(genesis_block)


    def add_block(self, new_block):
        # Check if the new block's index is correct
        if new_block.index != self.get_latest_block().index + 1:
            print("Error: Block index is not correct.")
            return False

        # Check if the new block's previous hash is correct
        if new_block.previous_hash != self.get_latest_block().hash:
            print("Error: Previous hash is not correct.")
            return False

        # If all checks pass, append the new block to the chain
        self.chain.append(new_block)
        return True

    def get_latest_block(self):
        return self.chain[-1]

    @staticmethod
    def is_valid_new_block(new_block, previous_block):
        if previous_block.index + 1 != new_block.index:
            print('Invalid index', new_block.index)
            return False
        elif previous_block.hash != new_block.previous_hash:
            print('Invalid previous_hash')
            return False
        elif new_block.calculate_hash() != new_block.hash:
            print('Invalid hash')
            return False
        return True

    def print_blockchain(self):
        for block in self.chain:
            print(f"Index: {block.index}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Data: {block.data}")
            print(f"Previous Hash: {block.previous_hash}")
            print(f"Hash: {block.hash}")
            print(" ")
            #print("\n")

class Server(threading.Thread):
    def __init__(self, blockchain, lock, port):
        threading.Thread.__init__(self)
        self.blockchain = blockchain
        self.lock = lock
        self.port = port
        self.block_queue = queue.PriorityQueue()  # use a priority queue to ensure blocks are processed in order
        self.public_keys = {
            1: public_key_client1,
            2: public_key_client2,
            3: public_key_client3,
            4: public_key_client4,
        } # store public keys of all clients (vehicles)
        self.public_key_server = public_key_server
        self.private_key_server = private_key_server
        self.commitment_keys = {}
        self.vehicles_packets = {}
        self.request_time = None
        self.last_authenticated_key = None

    def run(self):
        host = 'localhost'
        print(f"Server listening on {self.port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, self.port))
            server_socket.listen(1)
            while True:
                # Accept new connections and add any received blocks to the queue with a priority based on the timestamp
                client_socket, addr = server_socket.accept()
                print(f"Connected to {addr}")
                threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()

    def handle_client(self, client_socket, addr):
        # First, receive the nonce from the client
        self.send_request(client_socket)
        time.sleep(1)

        received_data = client_socket.recv(1024)  # 1024 is the buffer size
        # Decoding the bytes back into a string
        received_string = received_data.decode('utf-8')
        # Converting the string back into an integer
        vehicle_id = int(received_string)

        # handle the new vehicle
        self.handle_new_vehicle(client_socket, vehicle_id)
        # Then receive the challenge
        self.receive_challenge(client_socket, vehicle_id)
        time.sleep(2)
        #calculate time
        self.calculate_and_print_upper_bound()
        time.sleep(1)
        #Receive packets
        self.receive_packets(client_socket, vehicle_id)

        #self.send_blockchain(client_socket)

    def handle_new_vehicle(self, client_socket, vehicle_id):
        # This method should be called when a new vehicle connects to the server.
        # It reads the vehicle ID and public key from the client socket and stores the public key in the dictionary.

        # Retrieve the public key from the dictionary
        public_key = self.public_keys.get(vehicle_id)

        if public_key is not None:
            self.public_keys[vehicle_id] = public_key
        else:
            print(f"No public key found for vehicle ID {vehicle_id}")

    def send_blockchain(self, client_socket):
        blockchain_data = pickle.dumps(self.blockchain)
        len_blockchain_data = len(blockchain_data).to_bytes(4, 'big')
        client_socket.sendall(len_blockchain_data + blockchain_data)

    def process_packets(self):
        # Initialize an empty list of blocks
        blocks = []

        if not self.vehicles_packets or next(iter(self.vehicles_packets), None) is None:
            print("No packets to process")
            return
        # num_packets = len(self.vehicles_packets[next(iter(self.vehicles_packets))])

        # Get the number of packets from the first vehicle (assuming all vehicles send the same number of packets)
        num_packets = len(self.vehicles_packets[next(iter(self.vehicles_packets))])

        # For each packet index...
        for i in range(self.length+self.delay):
            # Initialize an empty list for the block data
            block_data = []

            # For each vehicle...
            for vehicle_id, packets in self.vehicles_packets.items():
                # Add the i-th packet from this vehicle to the block data
                if i < len(packets):
                    block_data.append(packets[i])

            # Create a new block with the collected data
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            block = Block(len(self.blockchain.chain), timestamp, block_data, self.blockchain.get_latest_block().hash)

            # Add the new block to the blockchain
            self.blockchain.add_block(block)

        # Return the blockchain
        return self.blockchain    

    def send_request(self, client_socket):
        nonce = str(random.randint(0, 1e9))  # Generate a random nonce
        self.request_time = time.time()
        # Send the nonce to the client over the socket
        client_socket.sendall(nonce.encode())
        print("Server has sent request with nonce:", nonce)
        return nonce

    def calculate_and_print_upper_bound(self):
        current_time = time.time()
        upper_bound = current_time - self.request_time + self.vehicle_time

        # Convert upper_bound from seconds since epoch to a human-readable format
        upper_bound_time = time.ctime(upper_bound)

        # Print upper_bound_time
        print("The upper bound time is:", upper_bound_time)

    def receive_challenge(self, client_socket, addr):
        with self.lock:
            # Receive the lengths first
            len_encrypted_challenge = int.from_bytes(client_socket.recv(4), 'big')
            len_signature = int.from_bytes(client_socket.recv(4), 'big')

            # Receive data from the server
            encrypted_challenge_b64 = self._recvall(len_encrypted_challenge, client_socket)
            signature_b64 = self._recvall(len_signature, client_socket)

            # Add missing padding to the base64 string
            required_padding = len(signature_b64) % 4
            if required_padding != 0:
                signature_b64 += b'=' * (4 - required_padding)

            # Decode the base64 strings
            signature = base64.b64decode(signature_b64)
            encrypted_challenge = base64.b64decode(encrypted_challenge_b64)

            try:
                # Decrypt the challenge with the server's private key
                challenge_str = self.private_key_server.decrypt(
                    encrypted_challenge,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Verify the signature with the client's public key
                self.public_keys[addr].verify(
                    signature,
                    challenge_str,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f"Signature is valid for Vehicle {addr}")
            except KeyError:
                print(f"No public key found for vehicle ID {addr}")
            except InvalidSignature:
                print(f"Invalid signature for vehicle ID {addr}")

            # Decode the challenge back into the original format
            challenge = eval(challenge_str.decode())  
            print("Received challenge:", challenge)

            # Unpack the challenge into its components
            nonce, self.commitment_key, self.delay, self.length, self.vehicle_time = challenge
            print("Received commiment:", self.commitment_key)

            # Store the commitment key for this vehicle
            self.commitment_keys[addr] = self.commitment_key

    def _recvall(self, n, client_socket):
        """Helper function to receive n bytes or return None if EOF is hit"""
        data = bytearray()
        while len(data) < n:
            packet = client_socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)

    def recvall(self, n, client_socket):
        data = b''
        while len(data) < n:
            packet = client_socket.recv(n - len(data))
            #print(f"Received {len(packet)} bytes")  # Debugging output
            if not packet:
                return None
            data += packet
        return data

    def compute_hash(self, key, i):
        """
        Compute hash of the given key i times.

        Parameters:
        key (str): The key to be hashed.
        i (int): The number of times to hash the key.

        Returns:
        str: The resulting hash after hashing the key i times.
        """

        # Check if key is None
        if key is None:
            print("Key is None")
            return None

        key_hash = key
        #print(f"Computing hash for key: {key} {i} times")
        for _ in range(i):  # Changed here
            key_hash = hashlib.sha256(key_hash.encode()).hexdigest()

        return key_hash

    def compute_mac(self, message, key):
        # If the key is None, return a default value (e.g., 'None')
        if key is None:
            return 'None'
        # The key must be bytes or bytearray, if it's a string, it needs to be encoded
        if isinstance(key, str):
            key = key.encode()
        # Create a new HMAC object with the given key and SHA-256 as the hash function
        h = hmac.new(key, digestmod=hashlib.sha256)

        # Check if message is not None and serialize it before updating the HMAC object
        if message is not None:
            # Convert the message dictionary to a JSON string and then encode it to bytes
            message_bytes = json.dumps(message).encode()
            h.update(message_bytes)
        else:
            return 'None'

        # Return the MAC as a hexadecimal string
        return h.hexdigest()
        
    def receive_packets(self, client_socket, addr):
        print("Server Receiving packets")
        with self.lock:
            # Look up the commitment key for this vehicle
            self.commitment_key = self.commitment_keys[addr]
            messages = []
            keys = []
            MACs = []
            packets = []

            for i in range(self.length+self.delay):
                packet_length_bytes = self.recvall(4, client_socket)
                if not packet_length_bytes:
                    break
                packet_length = int.from_bytes(packet_length_bytes, 'big')

                encrypted_packet = self.recvall(packet_length, client_socket)

                try:
                    packet_str = self.private_key_server.decrypt(
                        encrypted_packet,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    packet = ast.literal_eval(packet_str.decode())
                    print(f"Decoded packet {len(messages)+1}: {packet}")

                    message, current_hash, previous_hash = packet

                    messages.append(message)
                    keys.append(previous_hash)
                    MACs.append(current_hash)

                    # Add packet to the packets list of the corresponding vehicle
                    if addr not in self.vehicles_packets:
                        self.vehicles_packets[addr] = []
                    self.vehicles_packets[addr].append(packet)

                    if i >= 2:
                        if self.last_authenticated_key is None and keys[i] is not None:
                            # Handle the first key
                            key_hash_once = hashlib.sha256(keys[i].encode()).hexdigest()
                            self.last_authenticated_key = key_hash_once
                            print(f"Hash first key once: {key_hash_once}")
                            #print(f"Last authenticated key: {self.last_authenticated_key}")
                            print(f"Authenticated key 1")
                        else:
                            if keys[i] is not None:
                                # Compute the hash chain for the key
                                key_hash_once = hashlib.sha256(keys[i].encode()).hexdigest()
                                key_hash_i_times = self.compute_hash(keys[i], i - 1)
                                print(f"Computed key hash (once): {key_hash_once}")
                                print(f"Computed key hash ({i-1} times): {key_hash_i_times}")
                                print(f"Last authenticated key: {self.last_authenticated_key}")
                                # If key_hash_once equals the previous key or key_hash_i_times equals the commitment key
                                if key_hash_once == self.last_authenticated_key or key_hash_i_times == self.commitment_key:
                                    print(f"Authenticated key {i-1}")
                                    self.last_authenticated_key = keys[i]  # Update the last authenticated key
                                else:
                                    print(f"Authentication failed for key in packet {i-1}: Key doesn't match.")
                                    print(f"Computed key hash (once): {key_hash_once}")
                                    if 'key_hash_i_times' in locals():  # Check if key_hash_i_times has been computed
                                        print(f"Computed key hash (i times): {key_hash_i_times}")
                                    continue  # Skip to the next iteration if key authentication fails
                            else:
                                print(f"Authentication failed for key in packet {i+1}: Previous key was not authenticated.")
                                if keys[i] is not None:  # Check if key_hash_once and key_hash_i_times have been computed
                                    print(f"Computed key hash (once): {key_hash_once}")
                                    if 'key_hash_i_times' in locals():  # Check if key_hash_i_times has been computed
                                        print(f"Computed key hash (i times): {key_hash_i_times}")
                                continue  # Skip to the next iteration if the previous key was not authenticated

                        # Authenticate the MAC 
                        delayed_message = messages[i - 2]
                        delayed_mac = MACs[i - 2]
                        current_key = keys[i]
                        
                        computed_mac = self.compute_mac(delayed_message, current_key)

                        # Print the message, key, and computed MAC
                        # print(f"Message: {delayed_message}")
                        # print(f"Key: {current_key}")
                        print(f"Received MAC: {delayed_mac}")
                        print(f"Computed MAC: {computed_mac}")

                        if computed_mac == delayed_mac:
                            print(f"Authenticated MAC {i-1}")
                        else:
                            print(f"Authentication failed for packet {i-1}: MAC doesn't match.")
                            continue

                except Exception as e:
                    print(f"Error while processing packet {len(messages)}: {e}")
                    continue

        print(f"Server received packet from vehicle {addr}.")        

        return packets, list(zip(messages, keys, MACs))

    def collect_data(self):
        vehicle_data = {
            'vehicle_speeds': {},
            'vehicle_neighbors': {},
            'report_accidents': {}
        }

        # Loop over the packets collected for each vehicle
        for vehicle_id, packets in self.vehicles_packets.items():
            for packet in packets:
                message, timestamp, _ = packet
                if message:
                    # Append speed data
                    vehicle_data['vehicle_speeds'].setdefault(vehicle_id, []).append(message['data']['speed'])
                    
                    # Process neighbors data
                    neighbors = message['data'].get('neighbors', [])

                    # Check if neighbors is not a list or tuple, then make it a list with a single element
                    if not isinstance(neighbors, (list, tuple)):
                        neighbors = [neighbors]

                    if not neighbors:
                        # If neighbors list is empty, append 'None' to indicate no neighbors at this time
                        vehicle_data['vehicle_neighbors'].setdefault(vehicle_id, []).append(None)
                    else:
                        # If there is one or more neighbors, append the data correctly
                        # If there's only one neighbor, it will be a single-element list
                        vehicle_data['vehicle_neighbors'].setdefault(vehicle_id, []).append(tuple(neighbors))

                    # Append accident report data
                    if 'report_accident' in message['data']:
                        vehicle_data['report_accidents'].setdefault(vehicle_id, []).append(message['data']['report_accident'])
                    else:
                        # If no accident data, append None or a suitable default value
                        vehicle_data['report_accidents'].setdefault(vehicle_id, []).append(None)
        
        print(vehicle_data)

        return vehicle_data

    def analyze_speed_data(self, vehicle_speeds):
        # Calculate the average speed for each timestamp and compare individual speeds
        num_vehicles = len(vehicle_speeds)
        num_timestamps = len(next(iter(vehicle_speeds.values())))  # Assuming all vehicles have the same number of timestamps
        
        for i in range(num_timestamps):
            # Get the speed of all vehicles at timestamp i
            speeds_at_timestamp = [speeds[i] for speeds in vehicle_speeds.values()]
            average_speed_at_timestamp = statistics.mean(speeds_at_timestamp)
            
            for vehicle_id, speeds in vehicle_speeds.items():
                if speeds[i] < average_speed_at_timestamp:
                    print(f"Vehicle {vehicle_id} drive faster: {speeds[i]} < {average_speed_at_timestamp}")
                elif speeds[i] > average_speed_at_timestamp:
                    print(f"Vehicle {vehicle_id} slow down: {speeds[i]} > {average_speed_at_timestamp}")
        else:
            print("No speed data to analyze.")

    def analyze_neighbor_data(self, vehicle_neighbors):
        malicious_vehicles_per_packet = {}
        malicious_vehicle_counts = {}

        # Iterate over each packet index
        packet_indexes = range(len(next(iter(vehicle_neighbors.values()))))
        for packet_index in packet_indexes:
            # Dictionary to keep track of which vehicles have been reported as a neighbor
            reported_as_neighbor_by = {vehicle_id: set() for vehicle_id in vehicle_neighbors.keys()}

            # Collect reports for the current packet

            for vehicle_id, packets in vehicle_neighbors.items():
                if packet_index < len(packets) and packets[packet_index] is not None:
                    neighbor_info = packets[packet_index]
                    # We need to make sure we're always working with an iterable of neighbors
                    # Check the type of neighbor_info and handle it accordingly
                    if isinstance(neighbor_info, int):  # Single integer
                        neighbor_info = (neighbor_info,)
                    elif not isinstance(neighbor_info, (tuple, set)):  # It's not an int, tuple, or set
                        # Print the unexpected neighbor_info type and value
                        print(f"Unexpected neighbor_info type: {type(neighbor_info)}, value: {neighbor_info}")
                        raise ValueError("Neighbor info must be an integer, a tuple, or a set")
                    # If it's a tuple or set, we can iterate over it without any changes
                    for neighbor_id in neighbor_info:
                        if neighbor_id is not None:
                            reported_as_neighbor_by[neighbor_id].add(vehicle_id)

            # Check for discrepancies in the current packet
            for vehicle_id, reporters in reported_as_neighbor_by.items():
                actual_neighbors = vehicle_neighbors[vehicle_id][packet_index]
                if actual_neighbors is not None:
                    # Ensure actual_neighbors is a tuple for comparison
                    if not isinstance(actual_neighbors, tuple):
                        actual_neighbors = (actual_neighbors,)
                    for reporter in reporters:
                        if reporter not in actual_neighbors:
                            malicious_vehicles_per_packet.setdefault(packet_index + 1, set()).add(vehicle_id)
                            # Increment the count for the malicious vehicle
                            malicious_vehicle_counts[vehicle_id] = malicious_vehicle_counts.get(vehicle_id, 0) + 1
                            break

            # Output the results for the current packet
            print(f"Packet {packet_index + 1} reports: {reported_as_neighbor_by}")
            if packet_index + 1 in malicious_vehicles_per_packet:
                for vehicle in malicious_vehicles_per_packet[packet_index + 1]:
                    print(f"Malicious vehicle detected: Vehicle {vehicle} in packet {packet_index + 1}")

        print("")
        # After analyzing all packets, print out the count of malicious detections
        # Find the vehicle with the most malicious detections
        max_malicious_detections = 0
        most_malicious_vehicles = []

        for vehicle_id, count in malicious_vehicle_counts.items():
            if count > max_malicious_detections:
                most_malicious_vehicles = [vehicle_id]
                max_malicious_detections = count
            elif count == max_malicious_detections:
                most_malicious_vehicles.append(vehicle_id)

        # Print out the vehicle(s) with the most malicious detections
        if most_malicious_vehicles:
            for vehicle_id in most_malicious_vehicles:
                print(f"Vehicle {vehicle_id} has the highest number of malicious detections: {max_malicious_detections}")
        else:
            print("No malicious vehicle detections found.")
        return malicious_vehicles_per_packet

    def analyze_accident_reports(self, vehicle_accidents):
        time.sleep(1)

        # Determine the number of packets based on the first vehicle's reports
        num_packets = len(next(iter(vehicle_accidents.values())))

        for packet_index in range(num_packets):
            # Count the number of True reports for the current packet
            true_count = sum(reports[packet_index] for reports in vehicle_accidents.values() if reports[packet_index] is not None)
            # Count the number of False reports for the current packet
            false_count = sum(not reports[packet_index] for reports in vehicle_accidents.values() if reports[packet_index] is not None)

            # Determine majority for the current packet
            if true_count > false_count:
                majority_report = True
            elif false_count > true_count:
                majority_report = False
            else:
                # In case of a tie, it is undecided
                print(f"Packet {packet_index+1}: The vote was tied, so the accident report is undecided.")
                continue

            # Compare each vehicle's report with the majority
            for vehicle_id, reports in vehicle_accidents.items():
                if reports[packet_index] is not None and reports[packet_index] != majority_report:
                    if majority_report:
                        print(f"Packet {packet_index+1}: Vehicle {vehicle_id} did not report the majority-confirmed accident.")
                    else:
                        print(f"Packet {packet_index+1}: Vehicle {vehicle_id} reported an accident, but it was not confirmed by the majority.")
            if majority_report:
                print(f"Packet {packet_index+1}: Majority reports there is an accident.")
            else:
                print(f"Packet {packet_index+1}: Majority reports there is no accident.")

    def close_connection(self):
        print("close connection")
        self.client_socket.close()

class Vehicle(threading.Thread):
    def __init__(self, vehicle_id, blockchain, lock, port, server_port, private_key_client, public_key_client):
        threading.Thread.__init__(self)
        self.vehicle_id = vehicle_id
        # self.blockchain = blockchain
        self.blockchain = Blockchain()  # Each vehicle has its own blockchain
        self.port = port
        self.server_port = server_port
        self.lock = lock
        self.public_key_client = public_key_client
        self.private_key_client = private_key_client
        self.public_key_server = public_key_server
        self.delay = 2
        self.length = 10
        self.nonce = None
        self.keychain = generate_keychain(self.length+1)
        self.commitment_key = self.keychain[0]
        self.report_index = 0  # Initialize the report index
        
        # Define the vehicle_neighbors data structure with reports
        self.vehicle_neighbors = {
            1: [(2, 3, 5), (2, 4, 5), (3, 5), (2, 3, 4), (None), (2, 3, 4), (2, 3), (4), (3), (2)],
            2: [(1), (1, 3), (None), (1, 3, 5), (None), (1, 3), (1, 5), (3), (None), (1)],
            3: [(1), (2), (1, 4, 5), (1, 2, 4), (None), (1, 2, 4), (1), (2, 4, 5), (1, 4), (4)],
            4: [(2, 3), (None), (1, 2), (3), (1, 3), (None), (3), (None), (None), (1)],  # False data for malicious vehicle
            5: [(1), None, (1, 3), (1, 2), None, None, (2), (3), None, (4)]
        }
    def create_new_block(self, new_block_data):
        last_block = self.blockchain.chain[-1]
        #index = last_block.index + 1
        timestamp = time.time()
        previous_hash = last_block.hash  
        # Decode the base64 string back into bytes before creating the block
        decoded_data = base64.b64decode(new_block_data)
        # Server will assign index, so set to None for now
        return Block(None, timestamp, new_block_data, previous_hash)

    def run(self):
        # Delay to ensure servers have started
        time.sleep(2)
        print(f"Vehicle {self.vehicle_id} is connecting...")
        host = 'localhost'
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, self.server_port))
        # First, receive the nonce from the server
        self.receive_nonce()
        self.client_socket.sendall(bytes(str(self.vehicle_id), 'utf-8'))
        time.sleep(1)
        # Then send the challenge
        #print(f"Vehicle {self.vehicle_id} Commitment key: {commitment_key}")
        encrypted_challenge, signature = self.send_challenge(self.client_socket)
        time.sleep(3)
        self.send_packets(self.client_socket)
        # If you need to use encrypted_challenge and signature outside, you can return them
        return encrypted_challenge, signature

    def receive_blockchain(self):
        len_blockchain_data = int.from_bytes(self.client_socket.recv(4), 'big')
        blockchain_data = self._recvall(len_blockchain_data, self.client_socket)
        self.blockchain = pickle.loads(blockchain_data)

        # Now print the blockchain
        print(f"Vehicle {self.vehicle_id} received blockchain")
        # for block in self.blockchain.chain:
        #     print(f"Block #{block.index}:")
        #     print(f"Timestamp: {block.timestamp}")
        #     print(f"Data: {block.data}")
        #     print(f"Previous Hash: {block.previous_hash}")
        #     print(f"Hash: {block.hash}")

    def _recvall(self, n, client_socket):
        """Helper function to receive n bytes or return None if EOF is hit"""
        data = bytearray()
        while len(data) < n:
            packet = client_socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)

    def receive_nonce(self):
        # Receive data from the server
        data = self.client_socket.recv(1024)
        # Decode the data to get the nonce
        self.nonce = data.decode()
        print(f"Vehicle {self.vehicle_id} has received nonce.")

    def generate_challenge(self, nonce):
        vehicle_time = time.time()
        return (nonce, self.commitment_key, self.delay, self.length, vehicle_time)

    def send_challenge(self, client_socket):
        self.vehicle_time = time.time()
        if self.nonce is None:
            raise ValueError("Nonce has not been set.")

        challenge = (self.nonce, self.commitment_key, self.delay, self.length, self.vehicle_time)
        print(f"Vehicle {self.vehicle_id}  has generated the challenge.")
        challenge_str = str(challenge).encode()

        # Sign the challenge with the client's private key
        signature = self.private_key_client.sign(
            challenge_str,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Encrypt the challenge with the server's public key
        encrypted_challenge = self.public_key_server.encrypt(
            challenge_str,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_challenge_b64 = base64.b64encode(encrypted_challenge)
        signature_b64 = base64.b64encode(signature)

        # Convert lengths to bytes and pad them to a fixed size
        len_encrypted_challenge = len(encrypted_challenge_b64).to_bytes(4, 'big')
        len_signature = len(signature_b64).to_bytes(4, 'big')

        # print(f"Vehicle {vehicle_id} Sending Challenge..")

        client_socket.sendall(len_encrypted_challenge + len_signature + encrypted_challenge_b64 + signature_b64)

        return encrypted_challenge_b64, signature_b64  # Return the encrypted_challenge and signature

    def compute_mac(self, message, key):
        # If the key is None, return a default value (e.g., 'None')
        if key is None:
            return 'None'
        # The key must be bytes or bytearray, if it's a string, it needs to be encoded
        if isinstance(key, str):
            key = key.encode()
        # Create a new HMAC object with the given key and SHA-256 as the hash function
        h = hmac.new(key, digestmod=hashlib.sha256)

        # Check if message is not None and serialize it before updating the HMAC object
        if message is not None:
            # Convert the message dictionary to a JSON string and then encode it to bytes
            message_bytes = json.dumps(message).encode()
            h.update(message_bytes)
        else:
            return 'None'

        # Return the MAC as a hexadecimal string
        return h.hexdigest()

    def send_packets(self, client_socket):
        print(f"Vehicle {self.vehicle_id} Sending packets")
        packets = []
        hash_chain = []
        malicious_vehicle_id = 4  # Designate vehicle 4 as malicious
        all_vehicle_ids = {1, 2, 3, 4}  # Set of all possible vehicle IDs
        for i in range(self.length+self.delay):
            # print(f"Vehicle {vehicle_id}: sending packet {i+1}.")
            # Generate block data
            if i < self.length:

                # Use the predefined neighbor data from the vehicle_neighbors structure
                neighbor_data = self.vehicle_neighbors[self.vehicle_id][i] if i < len(self.vehicle_neighbors[self.vehicle_id]) else None

                message = {
                    "index": i+1,
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "data": {
                        "Vehicle ID": self.vehicle_id,  # Add the vehicle_id to the message data
                        "speed": random.randint(60, 100),
                        "neighbors": neighbor_data,
                        # "neighbors": random.randint(0, 2),
                        "report_accident": bool(random.getrandbits(1))
                    },
                    "previous_hash": hash_chain[i-1] if i > 0 else "",
                    "hash": "" # The hash will be assigned after the data is complete
                }
                # Serialize the message and compute its hash
                message["hash"] = hashlib.sha256(json.dumps(message).encode()).hexdigest()
                hash_chain.append(message["hash"])
            else:
                message = None

            # print(f"vehicle_id {self.vehicle_id} neighbors: {neighbor_vehicle_ids}")

            # Use keys from the start of the list.
            key_to_use_for_mac = self.keychain[i+1] if i < self.length else None
            # print(f"message:{message},")
            # print(f"key used for MAC {key_to_use_for_mac}.")
            mac = self.compute_mac(message, key_to_use_for_mac) if message is not None else 'None'

            # Fetch key in the same order for the packet.
            # The key is included starting from the 3rd packet.
            key = self.keychain[i-1] if i-2 >= 0 and i < self.length+self.delay else None
            #Construct the packet
            packet = (message, mac, key)
            packet_str = str(packet).encode()
            print(f"Packet {i+1}:", packet)

            try:
                # Encrypt the packet with the server's public key
                encrypted_packet = self.public_key_server.encrypt(
                    packet_str,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )


                # Convert encrypted_packet (bytes) to a base64 encoded string
                encoded_packet = base64.b64encode(encrypted_packet).decode('utf-8')
                packets.append(encoded_packet)

                # Send the length of the encrypted packet followed by the packet itself
                packet_length = len(encrypted_packet).to_bytes(4, 'big')
                client_socket.sendall(packet_length + encrypted_packet)

            except Exception as e:
                print(f"Error while encrypting packet {i}: {e}")
                continue

        print(f"Vehicle {self.vehicle_id} sent all packets.")

    
start=timer()

blockchain = Blockchain()
blockchain1 = Blockchain()
blockchain2 = Blockchain()
blockchain3 = Blockchain()
blockchain4 = Blockchain()
blockchain5 = Blockchain()

server_port = 2002

lock = threading.Lock()

# Creating separate locks for each vehicle
lock1 = threading.Lock()
lock2 = threading.Lock()
lock3 = threading.Lock()
lock4 = threading.Lock()
lock5 = threading.Lock()

vehicle1 = Vehicle(1, blockchain1, lock1, 12346, server_port, private_key_client1, public_key_client1)
vehicle2 = Vehicle(2, blockchain2, lock2, 12347, server_port, private_key_client2, public_key_client2)
vehicle3 = Vehicle(3, blockchain3, lock3, 12348, server_port, private_key_client3, public_key_client3)
vehicle4 = Vehicle(4, blockchain4, lock4, 12349, server_port, private_key_client4, public_key_client4)
vehicle5 = Vehicle(5, blockchain4, lock5, 12350, server_port, private_key_client5, public_key_client5)


server = Server(blockchain, lock, server_port)
server.start()
vehicle1.start()
vehicle2.start()
# time.sleep(1)
vehicle3.start()
# time.sleep(1)
vehicle4.start()
vehicle5.start()

vehicle1.join()
vehicle2.join()
vehicle3.join()
vehicle4.join()
vehicle5.join()

time.sleep(3)
# Process packets and add blocks to the blockchain
blocks = server.process_packets()

print("")
print("---------- Evaluation/Analysis ------------")
vehicle_data = server.collect_data()

# Analyze the collected data
print("---------- Analyze Speed Data ------------")
server.analyze_speed_data(vehicle_data['vehicle_speeds'])

print("---------- Analyze Neighbors Data ------------")
# malicious_vehicles = server.analyze_neighbor_data(vehicle_data['vehicle_neighbors'])
malicious_vehicles = server.analyze_neighbor_data(vehicle_data['vehicle_neighbors'])
print(malicious_vehicles)

print("---------- Analyze Report Accident Data ------------")
# server.analyze_accident_reports(vehicle_data['report_accidents'], len(vehicle_data['vehicle_speeds']))
server.analyze_accident_reports(vehicle_data['report_accidents'])

# vehicle1.receive_blockchain()
# vehicle2.receive_blockchain()
# vehicle3.receive_blockchain()
# vehicle4.receive_blockchain()

print("")
print("Final blockchain: ")
blockchain.print_blockchain()

end = timer()

# print(f"time in seconds to run the code: {end-start} ")
