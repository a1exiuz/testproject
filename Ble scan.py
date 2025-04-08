import asyncio
from bleak import BleakScanner
from datetime import datetime

# Set to track previously detected devices
detected_devices = set()

# Function to save scan result to a text file
def save_to_file(scan_data):
    with open("ble_scan_results.txt", "a") as file:
        file.write(scan_data + "\n")

async def continuous_scan():
    while True:
        # Start scanning for BLE devices
        devices = await BleakScanner.discover()

        # Get the number of new devices detected
        new_devices = [device for device in devices if device.address not in detected_devices]

        # Update the detected_devices set with the new devices' addresses
        detected_devices.update(device.address for device in new_devices)

        # Get the number of new devices detected
        num_new_devices = len(new_devices)

        # Create a formatted string with timestamp and number of new devices
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        scan_data = f"Timestamp: {timestamp}, New devices detected: {num_new_devices}"

        # Save the scan data to a text file
        save_to_file(scan_data)

        print(f"Scanned {num_new_devices} new devices.")
        print(f"Data saved to text file: {scan_data}")

        # Wait for 10 seconds before scanning again
        await asyncio.sleep(10)

# Run the continuous scanning function
asyncio.run(continuous_scan())
