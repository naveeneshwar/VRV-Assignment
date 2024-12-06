import csv
from collections import Counter
import re

# Count the number of requests made by each IP address.
def count_requests_per_ip(log_file_path):
    ip_counter = Counter()
    with open(log_file_path, 'r') as file:
        for line in file:
            ip = line.split()[0]
            ip_counter[ip] += 1
    return ip_counter

#Identify the most frequently accessed endpoint.
def most_accessed_endpoint(log_file_path):
    endpoint_counter = Counter()
    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.search(r'"(GET|POST)\s([^\s]+)', line)
            if match:
                endpoint = match.group(2)
                endpoint_counter[endpoint] += 1
    # Get the most accessed endpoint and its count
    most_accessed = endpoint_counter.most_common(1)
    return most_accessed[0] if most_accessed else None

#Detect suspicious activity based on failed login attempts (401 or "Invalid credentials")
def detect_suspicious_activity(log_file_path, threshold=10):
    failed_attempts = []
    with open(log_file_path, 'r') as file:
        for line in file:
            if " 401 " in line or "Invalid credentials" in line:
                ip = line.split()[0]
                failed_attempts.append(ip)

    failed_count = Counter(failed_attempts)
    suspicious_ips = {ip: count for ip, count in failed_count.items() if count >= threshold}
    return suspicious_ips

#Save the results to a CSV file.
def save_to_csv(results, filename="log_analysis_results.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Request Count"])  # For Requests per IP
        for ip, count in results["requests_per_ip"].items():
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line separator

        writer.writerow(["Endpoint", "Access Count"])  # For Most Accessed Endpoint
        if results["most_accessed_endpoint"]:
            endpoint, count = results["most_accessed_endpoint"]
            writer.writerow([endpoint, count])

        writer.writerow([])  # Blank line separator

        writer.writerow(["IP Address", "Failed Login Count"])  # For Suspicious Activity
        for ip, count in results["suspicious_activity"].items():
            writer.writerow([ip, count])

#Displaying results
def display_results(results):
    print("Requests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    print("-" * 40)
    for ip, count in results["requests_per_ip"].items():
        print(f"{ip:<20} {count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    if results["most_accessed_endpoint"]:
        endpoint, count = results["most_accessed_endpoint"]
        print(f"Endpoint: {endpoint}, Accessed {count} times")
    else:
        print("No endpoints accessed.")
    
    # Suspicious Activity
    print("\nSuspicious Activity Detected:")
    if results["suspicious_activity"]:
        print(f"{'IP Address':<20} {'Failed Login Attempts':<10}")
        print("-" * 40)
        for ip, count in results["suspicious_activity"].items():
            print(f"{ip:<20} {count:<10}")
    else:
        print("No suspicious activity detected.")

def main(log_file_path, threshold=10):
    results = {}

    # Step 1: Count Requests per IP
    results["requests_per_ip"] = count_requests_per_ip(log_file_path)

    # Step 2: Identify the Most Accessed Endpoint
    results["most_accessed_endpoint"] = most_accessed_endpoint(log_file_path)

    # Step 3: Detect Suspicious Activity
    results["suspicious_activity"] = detect_suspicious_activity(log_file_path, threshold)

    # Display the results in the terminal
    display_results(results)

    # Save results to CSV file
    save_to_csv(results)

if __name__ == "__main__":
    log_file = "sample.log" 
    main(log_file, threshold=5)  #The log provided has IPs with 7 or fewer failed attempts, so threshold has been set to 5.
