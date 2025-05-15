import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import sqlite3
import os
import json
import matplotlib.pyplot as plt
from sklearn import metrics


class AnomalyDetector:
    def __init__(self, eps=0.5, min_samples=5, metrics=None):
        """
        DBSCAN-based network anomaly detector

        Parameters:
        -----------
        eps : float
            Maximum distance between samples for one to be in neighborhood of another
        min_samples : int
            Number of samples in a neighborhood for a point to be a core point
        metrics : list of str, optional
            List of metrics to use for clustering. If None, uses all numeric features.
        """
        self.eps = eps
        self.min_samples = min_samples
        self.metrics = metrics
        self.model = None
        self.scaler = None
        self.true_labels = []
        self.pred_labels = []

    def evaluate_model(self, X, true_labels):
        """Calculate metrics using only feature columns"""
        try:
            X_features = X[self.feature_columns]
            labels = self.predict(X_features)

            y_pred = (labels == -1).astype(int)
            y_true = np.array(true_labels).astype(int)

            # Handle case with no predicted anomalies
            if len(np.unique(y_pred)) == 1:
                return {'anomaly': {'f1-score': 0.0}}

            return metrics.classification_report(
                y_true, y_pred,
                target_names=['normal', 'anomaly'],
                output_dict=True,
                zero_division=0
            )
        except Exception as e:
            print(f"Evaluation error: {str(e)}")
            return {'anomaly': {'f1-score': 0.0}}

    def tune_parameters(self, X, eps_range=(0.1, 1.0), eps_step=0.1, plot=True):
        """
        Tune DBSCAN parameters by testing different eps values

        Parameters:
        -----------
        X : pandas DataFrame
            Input features for clustering
        eps_range : tuple
            Range of eps values to test (min, max)
        eps_step : float
            Step size for eps values
        plot : bool
            Whether to plot the results

        Returns:
        --------
        best_eps : float
            Epsilon value that gave the most stable number of clusters
        """
        print("Tuning DBSCAN parameters...")

        # Standardize the features
        if self.scaler is None:
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)

        # Test different eps values
        eps_values = np.arange(eps_range[0], eps_range[1] + eps_step, eps_step)
        n_clusters = []

        for eps in eps_values:
            dbscan = DBSCAN(eps=eps, min_samples=self.min_samples)
            labels = dbscan.fit_predict(X_scaled)
            unique_labels = set(labels)

            # Count clusters (excluding noise which is labeled as -1)
            n_clusters.append(len([l for l in unique_labels if l != -1]))

        # Plot number of clusters vs. eps
        if plot:
            plt.figure(figsize=(10, 6))
            plt.plot(eps_values, n_clusters, marker='o',
                     linestyle='-', color='#00b3b3')
            plt.xlabel('Epsilon', fontsize=14)
            plt.ylabel('Number of Clusters', fontsize=14)
            plt.title(
                'DBSCAN Parameter Tuning: Number of Clusters vs Epsilon', fontsize=16)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()

            # Save the plot to a file
            plot_dir = '../../data/processed'
            os.makedirs(plot_dir, exist_ok=True)
            plt.savefig(os.path.join(plot_dir, 'dbscan_tuning.png'))
            plt.close()

        # Find best eps value - choose the one that gives a stable number of clusters
        derivatives = np.diff(n_clusters)
        stable_indices = np.where(derivatives == 0)[0]

        if len(stable_indices) > 0:
            # Get the first stable region
            best_idx = stable_indices[0]
            best_eps = eps_values[best_idx]
        else:
            # If no stable region, choose the eps with the most clusters
            best_idx = np.argmax(n_clusters)
            best_eps = eps_values[best_idx]

        print(
            f"Best eps value: {best_eps} (gives {n_clusters[best_idx]} clusters)")
        self.eps = best_eps

        return best_eps

    def fit(self, X):
        """
        Fit the DBSCAN model to the data

        Parameters:
        -----------
        X : pandas DataFrame
            Input features for clustering

        Returns:
        --------
        self : object
            Returns self
        """
        print("Fitting DBSCAN model...")

        # Select features if metrics is specified
        if self.metrics:
            X = X[self.metrics]
        else:
            # Use only numeric columns
            X = X.select_dtypes(include=['number'])

        # Standardize the features
        if self.scaler is None:
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)

        # Fit DBSCAN
        self.model = DBSCAN(eps=self.eps, min_samples=self.min_samples)
        self.model.fit(X_scaled)

        return self

    def predict(self, X):
        """
        Predict clusters and identify anomalies

        Parameters:
        -----------
        X : pandas DataFrame
            Input features for prediction

        Returns:
        --------
        labels : numpy array
            Cluster labels (with -1 indicating anomalies)
        """
        if self.model is None:
            raise ValueError("Model not fitted yet. Call fit() first.")

        # Select features if metrics is specified
        if self.metrics:
            X = X[self.metrics]
        else:
            # Use only numeric columns
            X = X.select_dtypes(include=['number'])

        # Standardize the features
        X_scaled = self.scaler.transform(X)

        # Predict using DBSCAN
        labels = self.model.fit_predict(X_scaled)

        return labels

    def detect_anomalies(self, X):
        """
        Detect anomalies in the data

        Parameters:
        -----------
        X : pandas DataFrame
            Input features for anomaly detection

        Returns:
        --------
        anomalies : pandas DataFrame
            Subset of X that contains anomalies
        """
        # Get cluster labels
        labels = self.predict(X)

        # Add labels to the data
        X_copy = X.copy()
        X_copy['cluster'] = labels

        # Anomalies are points that don't belong to any cluster (labeled as -1)
        anomalies = X_copy[X_copy['cluster'] == -1]

        print(
            f"Detected {len(anomalies)} anomalies out of {len(X)} samples ({len(anomalies)/len(X):.2%})")

        return anomalies

    def save_model(self, filepath):
        """Save model parameters to JSON file"""
        if self.model is None:
            raise ValueError("No model to save. Call fit() first.")

        model_params = {
            'eps': self.eps,
            'min_samples': self.min_samples,
            'metrics': self.metrics
        }

        with open(filepath, 'w') as f:
            json.dump(model_params, f)

        print(f"Model saved to {filepath}")

    @classmethod
    def load_model(cls, filepath):
        """Load model parameters from JSON file"""
        with open(filepath, 'r') as f:
            model_params = json.load(f)

        detector = cls(
            eps=model_params['eps'],
            min_samples=model_params['min_samples'],
            metrics=model_params['metrics']
        )

        print(f"Model loaded from {filepath}")
        return detector


# Example usage
if __name__ == "__main__":
    # Load data from SQLite if available
    db_path = '../../data/processed/network_data.sqlite'

    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        data = pd.read_sql("SELECT * FROM network_features", conn)
        conn.close()
    else:
        # Create sample data if database doesn't exist
        from datetime import datetime, timedelta

        now = datetime.now()
        timestamps = [now - timedelta(minutes=i) for i in range(100)]

        data = pd.DataFrame({
            'Minute': timestamps,
            'Packets_sum': np.random.randint(100, 1000, 100),
            'Packets_mean': np.random.uniform(5, 20, 100),
            'Packets_std': np.random.uniform(1, 5, 100),
            'Bytes_sum': np.random.randint(1000, 10000, 100),
            'Bytes_mean': np.random.uniform(50, 200, 100),
            'Bytes_std': np.random.uniform(10, 50, 100),
            'TCP_count': np.random.randint(0, 100, 100),
            'UDP_count': np.random.randint(0, 50, 100),
            'ICMP_count': np.random.randint(0, 10, 100),
            'Source IP_nunique': np.random.randint(1, 20, 100),
            'Destination IP_nunique': np.random.randint(1, 10, 100),
            'Attack_max': np.zeros(100),
        })

        # Add some anomalies
        anomaly_indices = [10, 25, 40, 75]
        for idx in anomaly_indices:
            data.loc[idx, 'Packets_sum'] *= 10
            data.loc[idx, 'Bytes_sum'] *= 10
            data.loc[idx, 'Attack_max'] = 1

    # Pick numeric columns for analysis (excluding timestamp and target)
    feature_cols = [col for col in data.columns if col not in [
        'Minute', 'Attack_max']]

    # Create and tune anomaly detector
    detector = AnomalyDetector()
    detector.tune_parameters(data[feature_cols])

    # Fit model and detect anomalies
    detector.fit(data[feature_cols])
    anomalies = detector.detect_anomalies(data[feature_cols])

    # Save model
    os.makedirs('../../data/processed', exist_ok=True)
    detector.save_model('../../data/processed/anomaly_detector_model.json')

    print("Detected anomalies:")
    if len(anomalies) > 0:
        print(anomalies.head())
    else:
        print("No anomalies detected")
