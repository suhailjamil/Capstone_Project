import json
import time
import random
import socket
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import threading
import os
import sys

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from kafka import KafkaProducer
except ImportError:
    print("WARNING: kafka-python not installed. Using mock KafkaProducer.")
    # Mock KafkaProducer for testing without Kafka

    class KafkaProducer:
        def __init__(self, **kwargs):
            print(f"Mock KafkaProducer initialized with {kwargs}")

        def send(self, topic, value=None, key=None):
            print(f"Mock send to {topic}: {value}")
            if key:
                print(f"With key: {key}")
            return MockFuture()

        def flush(self):
            print("Mock flush")

        def close(self):
            print("Mock close")

    class MockFuture:
        def add_callback(self, fn):
            fn(None)


class NetworkTrafficSimulator:
    """
    Simulates network traffic patterns for testing
    """

    def __init__(self, normal_rate=10, attack_rate=100, protocols=['TCP', 'UDP', 'ICMP']):
        """
        Initialize the traffic simulator

        Parameters:
        -----------
        normal_rate : int
            Normal packets per second
        attack_rate : int
            Attack packets per second
        protocols : list
            List of protocols to simulate
        """
        self.normal_rate = normal_rate
        self.attack_rate = attack_rate
        self.protocols = protocols
        self.is_attacking = False
        self.attack_probability = 0.5  # chance of attack per second

        # Generate some random IPs for simulation
        self.source_ips = [f'192.168.1.{i}' for i in range(1, 11)]
        self.destination_ips = [f'10.0.0.{i}' for i in range(1, 6)]
        self.ports = list(range(1024, 10000, 1000))

    def generate_packet(self):
        """Generate a single network packet"""
        timestamp = datetime.now()
        src_ip = random.choice(self.source_ips)
        dst_ip = random.choice(self.destination_ips)
        protocol = random.choice(self.protocols)
        src_port = random.choice(self.ports)
        dst_port = 80 if protocol == 'TCP' else 53 if protocol == 'UDP' else 0

        # Base packet size
        packet_size = random.randint(64, 1500)

        # If we're simulating an attack, make some anomalous traffic
        if self.is_attacking:
            if random.random() < 0.8:  # 80% of packets during attack are anomalous
                # DDoS-like traffic has some characteristics
                src_ip = random.choice(self.source_ips)  # More random sources
                packet_size = random.randint(1000, 1500)  # Larger packets
                dst_port = 80  # Target web server

        packet = {
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_size': packet_size,
            'is_attack': self.is_attacking
        }

        return packet

    def toggle_attack(self):
        """Toggle attack mode on or off"""
        self.is_attacking = not self.is_attacking
        status = "ON" if self.is_attacking else "OFF"
        print(f"Attack simulation turned {status}")

    def simulate_random_attacks(self):
        """Randomly start and stop attacks"""
        while True:
            time.sleep(10)  # Check every 10 seconds
            if not self.is_attacking and random.random() < self.attack_probability:
                self.toggle_attack()
                # Attack duration between 5-20 seconds
                attack_duration = random.randint(5, 20)
                threading.Timer(attack_duration, self.toggle_attack).start()


class KafkaNetworkProducer:
    """
    Produces network traffic data to Kafka
    """

    def __init__(self, bootstrap_servers='localhost:9092', topic='network_traffic',
                 use_real_data=False, data_path=None):
        """
        Initialize the Kafka producer

        Parameters:
        -----------
        bootstrap_servers : str
            Kafka bootstrap servers
        topic : str
            Kafka topic to produce to
        use_real_data : bool
            Whether to use real data from CSV
        data_path : str
            Path to real data CSV
        """
        self.topic = topic
        self.running = False
        self.use_real_data = use_real_data
        self.data_path = data_path
        self.real_data = None
        self.data_index = 0

        try:
            self.producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            print(f"Connected to Kafka at {bootstrap_servers}")
        except Exception as e:
            print(f"Error connecting to Kafka: {e}")
            print("Using mock KafkaProducer instead")
            self.producer = KafkaProducer(bootstrap_servers=bootstrap_servers)

        # Initialize traffic simulator
        self.simulator = NetworkTrafficSimulator()

        # If using real data, load it
        if self.use_real_data and self.data_path:
            try:
                self.load_real_data(self.data_path)
            except Exception as e:
                print(f"Error loading real data: {e}")
                self.use_real_data = False

    def load_real_data(self, data_path):
        """Load real network traffic data from CSV"""
        print(f"Loading real data from {data_path}")
        self.real_data = pd.read_csv(data_path)
        print(f"Loaded {len(self.real_data)} packets")

    def get_next_real_packet(self):
        """Get next packet from real data"""
        if self.real_data is None or len(self.real_data) == 0:
            return None

        # Get next row and convert to dict
        if self.data_index >= len(self.real_data):
            self.data_index = 0

        packet = self.real_data.iloc[self.data_index].to_dict()
        self.data_index += 1

        # Add current timestamp
        packet['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

        return packet

    def produce_traffic(self, packets_per_second=10):
        """
        Produce network traffic data to Kafka

        Parameters:
        -----------
        packets_per_second : int
            Number of packets to produce per second
        """
        self.running = True

        # Start attack simulator in background thread
        attack_thread = threading.Thread(
            target=self.simulator.simulate_random_attacks)
        attack_thread.daemon = True
        attack_thread.start()

        print(
            f"Producing {packets_per_second} packets per second to topic '{self.topic}'")

        try:
            while self.running:
                # Adjust rate based on attack status
                current_rate = self.simulator.attack_rate if self.simulator.is_attacking else packets_per_second

                # Calculate sleep time to achieve the target rate
                sleep_time = 1.0 / current_rate

                start_time = time.time()

                # Generate and send packet
                if self.use_real_data:
                    packet = self.get_next_real_packet()
                    if packet is None:
                        packet = self.simulator.generate_packet()
                else:
                    packet = self.simulator.generate_packet()

                self.producer.send(self.topic, value=packet)

                # Print status occasionally
                if random.random() < 0.01:  # ~1% of packets
                    protocol = packet['protocol']
                    src = packet['src_ip']
                    dst = packet['dst_ip']
                    size = packet['packet_size']
                    print(f"{protocol} {src} -> {dst} ({size} bytes)")

                # Sleep to maintain rate
                elapsed = time.time() - start_time
                remaining = sleep_time - elapsed
                if remaining > 0:
                    time.sleep(remaining)

        except KeyboardInterrupt:
            print("Stopping traffic producer")
        finally:
            self.producer.flush()
            self.producer.close()
            self.running = False

    def stop(self):
        """Stop the producer"""
        self.running = False


# Example usage
if __name__ == "__main__":
    # Look for real data
    data_path = '../../data/raw/cidds_traffic.csv'
    use_real_data = os.path.exists(data_path)

    producer = KafkaNetworkProducer(
        bootstrap_servers='localhost:9092',
        topic='network_traffic',
        use_real_data=use_real_data,
        data_path=data_path if use_real_data else None
    )

    try:
        producer.produce_traffic(packets_per_second=50)
    except KeyboardInterrupt:
        print("Stopping producer")
        producer.stop()
