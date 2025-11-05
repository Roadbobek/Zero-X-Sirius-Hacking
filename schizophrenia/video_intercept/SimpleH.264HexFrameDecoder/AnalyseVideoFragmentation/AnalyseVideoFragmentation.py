import csv

def analyze_fragments(csv_filepath, target_frame_id_hex="b885"):
    """
    Reads a CSV file containing packet data (Delta/Hex), extracts the 16-byte header
    and the first 4 bytes of the payload (bytes 16-19), and looks for a Fragment Index
    within the same Frame ID.

    We hypothesize the Fragment Index is in bytes 16-19 since the 16-byte header is static.
    """
    results = []
    # Convert the target Frame ID from hex string to integer for easy comparison
    target_frame_id = int(target_frame_id_hex, 16)
    
    # We will assume your CSV format has a column named 'Delta' or similar 
    # that contains the full packet data as a single hex string.
    try:
        # NOTE: You will need to replace 'Delta' with the actual column name 
        # that contains the continuous hex string data in your CSV.
        DATA_COLUMN_NAME = 'Delta' 
        PACKET_ID_COLUMN_NAME = 'Packet No'

        with open(csv_filepath, mode='r', newline='') as file:
            reader = csv.DictReader(file)
            
            for row in reader:
                try:
                    packet_id = row.get(PACKET_ID_COLUMN_NAME, 'N/A')
                    full_hex_data = row.get(DATA_COLUMN_NAME, '').strip()

                    if not full_hex_data:
                        continue # Skip empty rows

                    # Ensure the hex string has an even number of characters
                    if len(full_hex_data) % 2 != 0:
                         # Pad with 0 for incomplete last byte if necessary, though ideally hex strings are complete
                         full_hex_data += '0'
                    
                    # 1. Extract the Frame ID (Bytes 8-9)
                    frame_id_hex = full_hex_data[16:20] # 8 * 2 = 16, 10 * 2 = 20
                    
                    if len(frame_id_hex) < 4:
                        continue # Packet is too short to contain the Frame ID

                    current_frame_id = int(frame_id_hex, 16)

                    # Filter for packets belonging to the target frame for analysis
                    if current_frame_id != target_frame_id:
                        continue

                    # 2. Extract the potential Fragment Index area (Bytes 16-19, or Payload Bytes 0-3)
                    payload_start = 16 * 2 # Offset 16 * 2 chars = 32
                    
                    # We look at the first 4 bytes of the payload
                    fragment_area_hex = full_hex_data[payload_start:payload_start + 8] 

                    results.append({
                        'Packet No': packet_id,
                        'Frame ID (8-9)': frame_id_hex,
                        'Payload Bytes 0-3 (16-19)': fragment_area_hex
                    })

                except Exception as e:
                    print(f"Error processing packet {row.get(PACKET_ID_COLUMN_NAME)}: {e}")
            
    except FileNotFoundError:
        print(f"Error: The file '{csv_filepath}' was not found.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

    return results

# --- Main Execution ---

# 1. Update this path to your actual CSV file.
CSV_FILE_PATH = 'video_capture_5.10_Delta_CSV.csv' 

# 2. Choose a Frame ID to analyze (e.g., 'b885' which spans packets 41-114 in your data).
TARGET_FRAME = 'b885' 

analysis = analyze_fragments(CSV_FILE_PATH, TARGET_FRAME)

print("\n--- Fragment Analysis (Assuming Index in Payload) ---")
print(f"Filtering for Frame ID: {TARGET_FRAME}")
print("-----------------------------------------------------")

if analysis:
    print("Pkt No. | Frame ID | Payload Bytes 0-3 (Bytes 16-19)")
    print("-----------------------------------------------------")
    for item in analysis:
        # Note: The output is formatted here for clarity, but you should look for the 
        # sequential counter inside the 'Payload Bytes' field in the actual output.
        print(f"{item['Packet No'].ljust(7)} | {item['Frame ID (8-9)'].ljust(8)} | {item['Payload Bytes 0-3 (16-19)']}")

print("\nInstruction: Look for a 1 or 2-byte value inside the 'Payload Bytes 0-3' column that increments sequentially (e.g., 0001, 0002, 0003, or 01, 02, 03).")
