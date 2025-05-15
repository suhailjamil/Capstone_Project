from network.firewall_api import FirewallAPI
from network.kafka_producer import KafkaNetworkProducer
from models.anomaly_detector import AnomalyDetector
from data_processing.etl import NetworkDataProcessor
import os
import sys
import time
import argparse
import threading
import pandas as pd
import numpy as np
import json
import sqlite3
from datetime import datetime, timedelta
from queue import Queue

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import project modules

try:
    from kafka import KafkaConsumer
except ImportError:
    print("WARNING: kafka-python not installed. Using mock KafkaConsumer.")
    # Mock KafkaConsumer for testing without Kafka

    class KafkaConsumer:
        def __init__(self, *topics, **kwargs):
            print(
                f"Mock KafkaConsumer initialized with topics {topics} and {kwargs}")
            self.topics = topics
            self.running = True
            self.messages = Queue()

            # Start thread to generate mock messages
            self._thread = threading.Thread(target=self._generate_messages)
            self._thread.daemon = True
            self._thread.start()

        def _generate_messages(self):
            """Generate mock messages"""
            while self.running:
                timestamp = datetime.now()
                protocols = ['TCP', 'UDP', 'ICMP']
                topic = self.topics[0]

                for i in range(5):  # Generate 5 messages
                    message = {
                        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
                        'src_ip': f'192.168.1.{i}',
                        'dst_ip': f'10.0.0.{i}',
                        'src_port': 1000 + i,
                        'dst_port': 80,
                        'protocol': protocols[i % len(protocols)],
                        'packet_size': 100 + i * 10,
                        'is_attack': False
                    }

                    self.messages.put(MockMessage(
                        topic, json.dumps(message).encode('utf-8')))

                time.sleep(1)  # Sleep for 1 second

        def __iter__(self):
            return self

        def __next__(self):
            if not self.running:
                raise StopIteration

            try:
                return self.messages.get(timeout=1)
            except:
                return self.__next__()

        def close(self):
            self.running = False

    class MockMessage:
        def __init__(self, topic, value):
            self.topic = topic.encode('utf-8')
            self.value = value


class NetworkAnomalyDetectionSystem:
    """
    Real-time network anomaly detection system
    """

    def __init__(self, config=None):
        """
        Initialize the system

        Parameters:
        -----------
        config : dict
            Configuration parameters
        """
        self.config = config or {}
        self.data_dir = self.config.get('data_dir', '../data')
        self.raw_dir = os.path.join(self.data_dir, 'raw')
        self.processed_dir = os.path.join(self.data_dir, 'processed')

        # Create directories if they don't exist
        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)

        # Initialize SQLite database
        self.db_path = os.path.join(self.processed_dir, 'network_data.sqlite')

        # Initialize components
        self.data_processor = NetworkDataProcessor(
            input_path=self.raw_dir,
            output_path=self.processed_dir,
            db_path=self.db_path
        )

        # Initialize anomaly detector
        model_path = os.path.join(
            self.processed_dir, 'anomaly_detector_model.json')
        if os.path.exists(model_path):
            self.anomaly_detector = AnomalyDetector.load_model(model_path)
        else:
            self.anomaly_detector = AnomalyDetector()

        # Initialize firewall API
        self.firewall = FirewallAPI(log_file=os.path.join(
            self.processed_dir, 'firewall.log'))

        # Initialize Kafka settings
        self.kafka_bootstrap = self.config.get(
            'kafka_bootstrap', 'localhost:9092')
        self.kafka_topic = self.config.get('kafka_topic', 'network_traffic')

        # State
        self.running = False
        self.feature_buffer = []
        self.buffer_size = self.config.get(
            'buffer_size', 60)  # 60 seconds of data
        self.window_size = self.config.get(
            'window_size', 60)  # 1 minute window
        self.last_analysis_time = None

    def preprocess_message(self, message):
        """
        Preprocess a Kafka message into features

        Parameters:
        -----------
        message : dict
            Raw network packet data

        Returns:
        --------
        features : dict
            Extracted features
        """
        try:
            # Parse message
            if isinstance(message, bytes) or isinstance(message, str):
                packet = json.loads(message)
            else:
                packet = message

            # Add to feature calculations
            protocol = packet.get('protocol', 'UNKNOWN')
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            packet_size = packet.get('packet_size', 0)
            timestamp = datetime.strptime(
                packet.get('timestamp', datetime.now().strftime(
                    '%Y-%m-%d %H:%M:%S.%f')),
                '%Y-%m-%d %H:%M:%S.%f'
            )

            # Create feature dict
            features = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'packet_size': packet_size,
                'is_attack': packet.get('is_attack', False)
            }

            return features
        except Exception as e:
            print(f"Error preprocessing message: {e}")
            return None

    def aggregate_features(self, feature_buffer, window_minutes=1):
        """
        Aggregate features over a time window

        Parameters:
        -----------
        feature_buffer : list
            List of feature dicts
        window_minutes : int
            Window size in minutes

        Returns:
        --------
        aggregated : dict
            Aggregated features
        """
        if not feature_buffer:
            return None

        # Convert to DataFrame
        df = pd.DataFrame(feature_buffer)

        # Add minute column for grouping
        df['minute'] = df['timestamp'].dt.floor('min')

        # Group by minute
        grouped = df.groupby('minute').agg({
            'packet_size': ['count', 'mean', 'std'],
            'protocol': lambda x: x.value_counts().to_dict(),
            'src_ip': 'nunique',
            'dst_ip': 'nunique',
            'is_attack': 'max'  # If any packet is an attack, the window is an attack
        }).reset_index()

        # Flatten columns
        grouped.columns = ['_'.join(col).strip('_') if isinstance(
            col, tuple) else col for col in grouped.columns]

        # Extract protocol counts
        for protocol in ['TCP', 'UDP', 'ICMP']:
            grouped[f'{protocol}_count'] = grouped['protocol'].apply(
                lambda x: x.get(protocol, 0) if isinstance(x, dict) else 0
            )

        # Drop the dictionary column
        grouped.drop('protocol', axis=1, inplace=True)

        return grouped.to_dict('records')

    def process_features(self, features):
        """
        Process features through anomaly detection

        Parameters:
        -----------
        features : list
            List of feature dicts

        Returns:
        --------
        anomalies : list
            List of anomaly dicts
        """
        if not features:
            return []

        # Convert to DataFrame
        df = pd.DataFrame(features)

        # Drop non-numeric columns for clustering
        drop_cols = ['minute', 'is_attack']
        numeric_df = df.drop(columns=drop_cols, errors='ignore')

        # Fit/predict if we have enough data
        if len(numeric_df) >= 5:  # Minimum points needed
            # If model not trained yet, tune and train
            if not hasattr(self.anomaly_detector, 'model') or self.anomaly_detector.model is None:
                self.anomaly_detector.tune_parameters(numeric_df)
                self.anomaly_detector.fit(numeric_df)

            # Predict anomalies
            labels = self.anomaly_detector.predict(numeric_df)

            # Add labels back to original data
            df['anomaly'] = labels == -1

            # Get anomalies
            anomalies = df[df['anomaly'] == True].to_dict('records')

            return anomalies
        else:
            print(f"Not enough data for clustering: {len(numeric_df)} points")
            return []

    def respond_to_anomalies(self, anomalies):
        """
        Respond to detected anomalies

        Parameters:
        -----------
        anomalies : list
            List of anomaly dicts
        """
        if not anomalies:
            return

        print(f"Detected {len(anomalies)} anomalies")

        # Extract unique source IPs from anomalies
        anomaly_ips = set()
        for anomaly in anomalies:
            # If we have raw data with src_ip
            if 'src_ip' in anomaly and isinstance(anomaly['src_ip'], str):
                anomaly_ips.add(anomaly['src_ip'])

        # Block IPs
        for ip in anomaly_ips:
            self.firewall.block_ip(ip, "Anomaly detected")

        # Log anomalies to database
        conn = sqlite3.connect(self.db_path)
        anomaly_df = pd.DataFrame(anomalies)
        if 'anomaly' in anomaly_df.columns:
            anomaly_df.drop('anomaly', axis=1, inplace=True)
        anomaly_df.to_sql('anomalies', conn, if_exists='append', index=False)
        conn.close()

    def consume_traffic(self):
        """
        Consume network traffic from Kafka
        """
        print(f"Starting Kafka consumer for topic '{self.kafka_topic}'")

        try:
            # Create Kafka consumer
            consumer = KafkaConsumer(
                self.kafka_topic,
                bootstrap_servers=self.kafka_bootstrap,
                auto_offset_reset='latest',
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                group_id='network_anomaly_detector'
            )

            # Process messages
            for message in consumer:
                if not self.running:
                    break

                # Preprocess message
                features = self.preprocess_message(message.value)
                if features:
                    self.feature_buffer.append(features)

                # Check if it's time to analyze
                now = datetime.now()
                if (self.last_analysis_time is None or
                        (now - self.last_analysis_time).total_seconds() >= self.window_size):
                    # Aggregate features
                    aggregated = self.aggregate_features(self.feature_buffer)

                    # Process features
                    if aggregated:
                        # Separate features and labels
                        df = pd.DataFrame(aggregated)
                        feature_cols = self.anomaly_detector.feature_columns
                        true_labels = df['is_attack_max'].values

                        # Process features
                        anomalies = self.process_features(df[feature_cols])

                        # Get metrics
                        report = self.anomaly_detector.evaluate_model(
                            df, true_labels)
                        f1_score = report['anomaly']['f1-score']

                        # Get firewall stats
                        firewall_stats = self.firewall.get_performance_stats()

                        # Print metrics
                        print(f"\n[Window Metrics] F1: {f1_score:.2f} | "
                              f"Blocks: {firewall_stats['total_blocks']} | "
                              f"Avg Response: {firewall_stats['avg_response']:.6f}s",
                              flush=True)
                    # Update analysis time
                    self.last_analysis_time = now

                    # Keep only recent data in buffer
                    cutoff = now - timedelta(seconds=self.buffer_size)
                    self.feature_buffer = [
                        f for f in self.feature_buffer if f['timestamp'] > cutoff]

            consumer.close()

        except Exception as e:
            print(f"Error consuming traffic: {e}")

    def simulate_traffic(self):
        """Simulate network traffic"""
        print("Starting traffic simulator")

        # Create Kafka producer
        producer = KafkaNetworkProducer(
            bootstrap_servers=self.kafka_bootstrap,
            topic=self.kafka_topic
        )

        # Start producer thread
        producer_thread = threading.Thread(target=producer.produce_traffic)
        producer_thread.daemon = True
        producer_thread.start()

        return producer

    def start(self, simulate=True):
        """
        Start the anomaly detection system

        Parameters:
        -----------
        simulate : bool
            Whether to simulate traffic
        """
        print("Starting Network Anomaly Detection System")

        # Set running flag
        self.running = True

        # Start traffic simulation if requested
        if simulate:
            self.producer = self.simulate_traffic()

        # Start consumer thread
        consumer_thread = threading.Thread(target=self.consume_traffic)
        consumer_thread.daemon = True
        consumer_thread.start()

        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n=== Final Metrics ===")
            firewall_stats = self.firewall.get_performance_stats()

            # Safe metric printing
            print(f"Total Blocks: {firewall_stats['total_blocks']}")
            print(f"Avg Response: {firewall_stats['avg_response']:.6f}s")
            print(f"Fastest Response: {firewall_stats['min_response']:.6f}s")
            print(f"Slowest Response: {firewall_stats['max_response']:.6f}s")

            # Handle protocol key error
            if self.feature_buffer:
                first_packet = self.feature_buffer[0]
                protocol = first_packet.get('protocol', 'UNKNOWN')
                print(f"First Packet Protocol: {protocol}")

            self.stop()

    def stop(self):
        """Stop the anomaly detection system"""
        self.running = False

        # Save model
        model_path = os.path.join(
            self.processed_dir, 'anomaly_detector_model.json')
        if hasattr(self.anomaly_detector, 'model') and self.anomaly_detector.model is not None:
            self.anomaly_detector.save_model(model_path)

# Command line interface


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Network Anomaly Detection System'
    )

    parser.add_argument(
        '--simulate',
        action='store_true',
        help='Simulate network traffic'
    )

    parser.add_argument(
        '--kafka',
        type=str,
        default='localhost:9092',
        help='Kafka bootstrap servers'
    )

    parser.add_argument(
        '--topic',
        type=str,
        default='network_traffic',
        help='Kafka topic'
    )

    parser.add_argument(
        '--data-dir',
        type=str,
        default='../data',
        help='Data directory'
    )

    return parser.parse_args()


# Main entry point
if __name__ == "__main__":
    args = parse_args()

    # Build config
    config = {
        'kafka_bootstrap': args.kafka,
        'kafka_topic': args.topic,
        'data_dir': args.data_dir
    }

    # Create and start system
    system = NetworkAnomalyDetectionSystem(config)
    system.start(simulate=args.simulate)
