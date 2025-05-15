import pandas as pd
import os
import sqlite3
from datetime import datetime


class NetworkDataProcessor:
    def __init__(self, input_path, output_path, db_path=None):
        """
        Initialize the ETL pipeline for network data

        Parameters:
        -----------
        input_path : str
            Path to raw CIDDS-001 data
        output_path : str
            Path to save processed data
        db_path : str, optional
            Path to SQLite database for storing results
        """
        self.input_path = input_path
        self.output_path = output_path
        self.db_path = db_path

    def load_data(self, filename):
        """Load raw network data from CSV"""
        print(f"Loading data from {os.path.join(self.input_path, filename)}")

        if filename.endswith('.parquet'):
            return pd.read_parquet(os.path.join(self.input_path, filename))

        # For CIDDS-001 dataset:
        # Assuming format: Date, Time, Duration, Source IP, Source Port, Destination IP,
        # Destination Port, Protocol, Packets, Bytes, Flows, Flags, Attack
        try:
            df = pd.read_csv(os.path.join(self.input_path, filename),
                             parse_dates=[['Date', 'Time']])
            print(f"Loaded {len(df)} rows")
            return df
        except Exception as e:
            print(f"Error loading data: {e}")
            # Create sample data if actual data is not available
            return self._create_sample_data()

    def _create_sample_data(self):
        """Create sample data for testing if real data is unavailable"""
        print("Creating sample data for testing")

        # Create a timestamp range for the past 24 hours
        end_time = pd.Timestamp.now()
        start_time = end_time - pd.Timedelta(days=1)
        timestamps = pd.date_range(start=start_time, end=end_time, freq='1min')

        # Create sample data
        data = {
            'Date_Time': timestamps,
            'Duration': [0.1] * len(timestamps),
            'Source IP': ['192.168.1.' + str(i % 255) for i in range(len(timestamps))],
            'Source Port': [1000 + (i % 1000) for i in range(len(timestamps))],
            'Destination IP': ['10.0.0.' + str(i % 255) for i in range(len(timestamps))],
            'Destination Port': [80 if i % 3 == 0 else (443 if i % 3 == 1 else 22) for i in range(len(timestamps))],
            # 0=TCP, 1=UDP, 2=ICMP
            'Protocol': [(i % 3) for i in range(len(timestamps))],
            'Packets': [10 + (i % 100) for i in range(len(timestamps))],
            'Bytes': [100 + (i % 1000) for i in range(len(timestamps))],
            'Flags': ['....S.'] * len(timestamps),
            'Attack': [0] * len(timestamps)  # 0 = normal, 1 = attack
        }

        # Inject some anomalies (attacks)
        attack_indices = [i for i in range(len(timestamps)) if i % 50 == 0]
        for idx in attack_indices:
            data['Attack'][idx] = 1
            data['Packets'][idx] = data['Packets'][idx] * \
                10  # Unusual packet count
            data['Bytes'][idx] = data['Bytes'][idx] * 20  # Unusual byte count

        return pd.DataFrame(data)

    def extract_features(self, df):
        """Extract time-series features from network data"""
        print("Extracting features...")

        # Make sure we have a datetime column
        if 'Date_Time' not in df.columns:
            if 'Date' in df.columns and 'Time' in df.columns:
                df['Date_Time'] = pd.to_datetime(df['Date'] + ' ' + df['Time'])
            else:
                raise ValueError("No timestamp column found")

        # Convert protocol numbers to names if needed
        protocol_map = {0: 'TCP', 1: 'UDP', 2: 'ICMP'}
        if df['Protocol'].dtype == 'int64' or df['Protocol'].dtype == 'float64':
            df['Protocol'] = df['Protocol'].map(
                lambda x: protocol_map.get(x, 'OTHER'))

        # Aggregate by minute for time-series analysis
        df['Minute'] = df['Date_Time'].dt.floor('min')

        features = df.groupby('Minute').agg({
            'Packets': ['sum', 'mean', 'std'],
            'Bytes': ['sum', 'mean', 'std'],
            'Protocol': lambda x: x.value_counts().to_dict(),
            'Source IP': 'nunique',
            'Destination IP': 'nunique',
            'Source Port': 'nunique',
            'Destination Port': 'nunique',
            'Duration': 'mean',
            'Attack': 'max'  # If any flow in this minute was an attack, mark the minute as attack
        }).reset_index()

        # Flatten multi-level columns
        features.columns = ['_'.join(col).strip('_') if isinstance(
            col, tuple) else col for col in features.columns.values]

        # Extract protocol counts
        for protocol in protocol_map.values():
            features[f'{protocol}_count'] = features['Protocol'].apply(
                lambda x: x.get(protocol, 0) if isinstance(x, dict) else 0
            )

        # Drop the original protocol column with dict values
        features.drop('Protocol', axis=1, inplace=True)

        print(f"Extracted features with shape {features.shape}")
        return features

    def save_to_database(self, df, table_name='network_features'):
        """Save processed data to SQLite database"""
        if self.db_path:
            print(f"Saving to database {self.db_path}")
            conn = sqlite3.connect(self.db_path)
            df.to_sql(table_name, conn, if_exists='replace', index=False)
            conn.close()
            print(f"Saved {len(df)} rows to table {table_name}")

    def save_to_csv(self, df, filename):
        """Save processed data to CSV file"""
        output_file = os.path.join(self.output_path, filename)
        print(f"Saving to {output_file}")
        df.to_csv(output_file, index=False)
        print(f"Saved {len(df)} rows to {output_file}")

    def process_data(self, input_file, output_file='processed_features.csv', table_name='network_features'):
        """Full ETL pipeline"""
        # Extract
        df = self.load_data(input_file)

        # Transform
        features_df = self.extract_features(df)

        # Load
        self.save_to_csv(features_df, output_file)
        if self.db_path:
            self.save_to_database(features_df, table_name)

        return features_df


# Example usage
if __name__ == "__main__":
    processor = NetworkDataProcessor(
        input_path='../../data/raw',
        output_path='../../data/processed',
        db_path='../../data/processed/network_data.sqlite'
    )

    # Process default file or use sample data if not found
    try:
        features = processor.process_data('cidds_traffic.csv')
    except:
        features = processor.process_data('sample_data.csv')

    print("Feature columns:", features.columns.tolist())
    print("Data preview:")
    print(features.head())
