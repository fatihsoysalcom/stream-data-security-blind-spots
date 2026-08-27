import time
import random
from collections import deque

# --- Data Simulation ---
# Generates a single transaction with a timestamp, user_id, amount, and transaction_id.
# Can optionally generate a 'suspiciously' small amount.
def generate_transaction(user_id, is_suspicious_sequence=False):
    amount = round(random.uniform(1, 1000), 2)
    if is_suspicious_sequence:
        amount = round(random.uniform(1, 9.99), 2) # Small amount for suspicious pattern
    return {
        "timestamp": time.time(),
        "user_id": user_id,
        "amount": amount,
        "transaction_id": random.randint(10000, 99999)
    }

# Simulates a continuous stream of transactions.
# It injects a sequence of rapid, small transactions from a specific user
# to represent a potential threat that relies on temporal context.
def simulate_data_stream(num_transactions=20):
    stream_data = []
    suspicious_user = "user_fraud_123"
    print("Simulating data stream...")
    for i in range(num_transactions):
        if 5 <= i < 10: # Inject a suspicious sequence of 5 transactions
            transaction = generate_transaction(suspicious_user, is_suspicious_sequence=True)
            time.sleep(0.5) # Rapid succession to trigger real-time detection
        else:
            transaction = generate_transaction(random.choice([f"user_{chr(65+j)}" for j in range(4)]), is_suspicious_sequence=False)
            time.sleep(random.uniform(0.1, 1.5)) # Normal pace for other transactions
        stream_data.append(transaction)
        print(f"  Generated: {transaction['user_id']} - ${transaction['amount']:.2f} (ID: {transaction['transaction_id']})")
    print("Stream simulation finished.")
    return stream_data

# --- Traditional Security Scanner (Batch Processing) ---
# This function represents a traditional scanner that processes data in batches,
# typically after it has been collected and stored. It struggles with dynamic,
# temporal patterns.
def traditional_scanner_batch_analysis(all_transactions):
    print("\n--- Traditional Security Scanner (Batch Analysis) ---")
    print("Analyzing all transactions after they have been collected (static view)...")

    suspicious_threshold_amount = 10.0 # A simple threshold for 'small' transactions
    potential_small_transactions = []

    # A traditional batch scanner often looks for individual anomalies or aggregates
    # data without strong temporal context or state across events.
    # It's hard for it to detect patterns like 'N small transactions in X seconds'.
    for tx in all_transactions:
        # This scanner only looks at individual transaction amounts.
        # It will flag any transaction below the threshold, leading to many false positives
        # for legitimate small purchases, and it *misses the specific fraudulent sequence*.
        if tx['amount'] < suspicious_threshold_amount:
            potential_small_transactions.append(tx)

    if potential_small_transactions:
        print(f"  Found {len(potential_small_transactions)} transactions below ${suspicious_threshold_amount:.2f}.")
        print("  However, this approach generates many false positives (legitimate small transactions).")
        print("  The specific *rapid sequence* threat (multiple small transactions from one user in a short time) was likely missed because this scanner lacks real-time temporal context and state management.")
    else:
        print("  No individual transactions found below the threshold.")


# --- Stream-Based Security Scanner (Real-time Processing) ---
# This function demonstrates a security scanner designed for stream data.
# It processes events as they arrive, maintains state (e.g., a time window),
# and can detect dynamic, temporal patterns that traditional scanners miss.
def stream_based_scanner_realtime_analysis(stream_data_iterable):
    print("\n--- Stream-Based Security Scanner (Real-time Analysis) ---")
    print("Processing transactions as they arrive in real-time (using recorded timestamps)...")

    # Configuration for detecting suspicious patterns in the stream
    time_window_seconds = 5 # Look for patterns within this many seconds
    min_small_transactions_in_window = 3 # Minimum number of small transactions
    small_transaction_max_amount = 10.0 # Max amount for a "small" transaction

    # Store recent transactions per user in a deque (double-ended queue).
    # This allows efficient adding/removing from both ends and maintains order,
    # crucial for windowed processing.
    user_transaction_windows = {} # {user_id: deque([(timestamp, amount), ...])}

    threat_detected = False

    for tx in stream_data_iterable:
        user_id = tx['user_id']
        current_time = tx['timestamp']
        amount = tx['amount']

        if user_id not in user_transaction_windows:
            user_transaction_windows[user_id] = deque()

        # Add current transaction to the user's window
        user_transaction_windows[user_id].append((current_time, amount))

        # Remove old transactions from the window to maintain the defined time_window_seconds.
        # This is the core of real-time windowed processing.
        while user_transaction_windows[user_id] and \
              user_transaction_windows[user_id][0][0] < current_time - time_window_seconds:
            user_transaction_windows[user_id].popleft()

        # Check for the suspicious pattern in the current user's window.
        # This logic directly addresses the 'rapid sequence' threat.
        small_transactions_count = 0
        for _, tx_amount in user_transaction_windows[user_id]:
            if tx_amount < small_transaction_max_amount:
                small_transactions_count += 1

        # If the criteria are met, a threat is detected.
        # This demonstrates how a stream processor can identify threats based on
        # temporal patterns that are invisible to static batch analysis.
        if small_transactions_count >= min_small_transactions_in_window and \
           len(user_transaction_windows[user_id]) >= min_small_transactions_in_window:
            print(f"\n  !!! THREAT DETECTED for user {user_id} !!!")
            print(f"  {small_transactions_count} small transactions (<${small_transaction_max_amount:.2f}) detected within {time_window_seconds} seconds.")
            print("  This pattern indicates potential fraudulent activity, which a traditional batch scanner would likely miss due to lack of real-time context.")
            threat_detected = True
            # In a real system, an immediate alert or action would be triggered here.
            break # Stop processing if threat is found for demonstration purposes

    if not threat_detected:
        print("  No specific rapid sequence threats detected by the real-time scanner in this run.")

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Simulate the data stream once. The timestamps are recorded during this simulation.
    # This collected list will be used by both scanners to ensure they operate on the same data.
    all_transactions_for_analysis = simulate_data_stream(num_transactions=20)

    # 2. Run the traditional batch scanner on the *entire collected dataset*.
    # It processes data after all events have occurred.
    traditional_scanner_batch_analysis(all_transactions_for_analysis)

    # 3. Run the stream-based scanner. It processes the *same collected data*,
    # but it does so sequentially, event-by-event, using the recorded timestamps
    # to simulate real-time windowed analysis.
    stream_based_scanner_realtime_analysis(all_transactions_for_analysis)
