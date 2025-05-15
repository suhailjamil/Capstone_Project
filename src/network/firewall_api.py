import json
import time
import requests
import socket
import os


class FirewallAPI:
    """
    Mock API for firewall rule management
    """

    def __init__(self, log_file=None, real_firewall=False, api_url=None):
        """
        Initialize the firewall API

        Parameters:
        -----------
        log_file : str
            Path to log file
        real_firewall : bool
            Whether to use real firewall via API
        api_url : str
            URL of real firewall API
        """
        self.log_file = log_file
        self.real_firewall = real_firewall
        self.api_url = api_url
        self.blocked_ips = set()
        self.response_times = []

        # Create log directory if needed
        if self.log_file:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

            # Write header to log file if it doesn't exist
            if not os.path.exists(self.log_file):
                with open(self.log_file, 'w') as f:
                    f.write("timestamp,action,ip,reason\n")

    def block_ip(self, ip, reason="Anomaly detected"):
        start = time.perf_counter()
        # Simulated blocking logic
        self.blocked_ips.add(ip)
        elapsed = time.perf_counter() - start
        self.response_times.append(elapsed)
        print(f"Blocking {ip} ({reason})", flush=True)
        return True

    def get_performance_stats(self):
        """Get formatted performance metrics with safe defaults"""
        stats = {
            'total_blocks': len(self.response_times),
            'avg_response': 0.0,
            'min_response': 0.0,
            'max_response': 0.0
        }

        if self.response_times:
            stats['avg_response'] = np.mean(self.response_times)
            stats['min_response'] = np.min(self.response_times)
            stats['max_response'] = np.max(self.response_times)

        return stats

    def log_action(self, action, ip, reason):
        """Log firewall action to file"""
        if not self.log_file:
            return

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        with open(self.log_file, 'a') as f:
            f.write(f"{timestamp},{action},{ip},{reason}\n")

    def block_ip(self, ip, reason="Anomaly detected"):
        """
        Block an IP address

        Parameters:
        -----------
        ip : str
            IP address to block
        reason : str
            Reason for blocking

        Returns:
        --------
        success : bool
            Whether the operation was successful
        """
        # Validate IP address
        try:
            socket.inet_aton(ip)
        except socket.error:
            print(f"Invalid IP address: {ip}")
            return False

        print(f"Blocking IP {ip} ({reason})")

        # Add to blocked IPs
        self.blocked_ips.add(ip)

        # Log action
        self.log_action("BLOCK", ip, reason)

        # If using real firewall, make API call
        if self.real_firewall and self.api_url:
            try:
                payload = {
                    "action": "block",
                    "ip": ip,
                    "reason": reason
                }
                response = requests.post(
                    f"{self.api_url}/block",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    print(f"Successfully blocked {ip} on real firewall")
                    return True
                else:
                    print(
                        f"Error blocking {ip} on real firewall: {response.status_code}")
                    return False
            except Exception as e:
                print(f"Error calling firewall API: {e}")
                return False

        return True

    def unblock_ip(self, ip, reason="Manual unblock"):
        """
        Unblock an IP address

        Parameters:
        -----------
        ip : str
            IP address to unblock
        reason : str
            Reason for unblocking

        Returns:
        --------
        success : bool
            Whether the operation was successful
        """
        # Validate IP address
        try:
            socket.inet_aton(ip)
        except socket.error:
            print(f"Invalid IP address: {ip}")
            return False

        print(f"Unblocking IP {ip} ({reason})")

        # Remove from blocked IPs
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)

        # Log action
        self.log_action("UNBLOCK", ip, reason)

        # If using real firewall, make API call
        if self.real_firewall and self.api_url:
            try:
                payload = {
                    "action": "unblock",
                    "ip": ip,
                    "reason": reason
                }
                response = requests.post(
                    f"{self.api_url}/unblock",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    print(f"Successfully unblocked {ip} on real firewall")
                    return True
                else:
                    print(
                        f"Error unblocking {ip} on real firewall: {response.status_code}")
                    return False
            except Exception as e:
                print(f"Error calling firewall API: {e}")
                return False

        return True

    def is_blocked(self, ip):
        """Check if an IP is blocked"""
        return ip in self.blocked_ips

    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        return list(self.blocked_ips)

    def generate_rules(self, blocked_ips=None):
        """
        Generate iptables rules for blocked IPs

        Parameters:
        -----------
        blocked_ips : list
            List of IPs to block. If None, use self.blocked_ips

        Returns:
        --------
        rules : list
            List of iptables rules
        """
        if blocked_ips is None:
            blocked_ips = self.get_blocked_ips()

        rules = []

        for ip in blocked_ips:
            rules.append(f"iptables -A INPUT -s {ip} -j DROP")
            rules.append(f"iptables -A OUTPUT -d {ip} -j DROP")

        return rules


# Example usage
if __name__ == "__main__":
    firewall = FirewallAPI(log_file="../../data/processed/firewall.log")

    # Block some IPs
    firewall.block_ip("192.168.1.1", "Test block")
    firewall.block_ip("10.0.0.1", "Suspicious activity")

    # Get and print blocked IPs
    print("Blocked IPs:", firewall.get_blocked_ips())

    # Generate iptables rules
    rules = firewall.generate_rules()
    print("Generated iptables rules:")
    for rule in rules:
        print(rule)

    # Unblock an IP
    firewall.unblock_ip("192.168.1.1", "Test complete")

    # Check updated list
    print("Updated blocked IPs:", firewall.get_blocked_ips())
