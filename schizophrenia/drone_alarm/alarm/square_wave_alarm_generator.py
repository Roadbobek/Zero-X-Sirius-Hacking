import math
import wave
import struct
import os
import sys
import time
import subprocess

# --- Core Alarm Generation Function ---

def generate_square_wave_alarm(filename, frequency, duration, cycles, gap, rate=44100, volume=32767):
    """
    Generates a pulsing square wave audio signal based on inputs and saves it 
    as a 16-bit mono WAV file.
    Uses only standard library modules (math, wave, struct).
    """
    
    # 1. Generate a single pulse (square wave)
    pulse_samples = int(rate * duration)
    pulse_data = []
    
    # Calculate the period in samples for the square wave
    period = rate / frequency
    
    for i in range(pulse_samples):
        # A simple square wave switches between max and min amplitude
        if (i % period) < (period / 2):
            sample = volume
        else:
            sample = -volume
            
        # Convert to 16-bit signed short bytes (Little-endian '<h')
        pulse_data.append(struct.pack('<h', int(sample)))

    # 2. Generate the silence gap
    gap_samples = int(rate * gap)
    # A single zero-value 16-bit sample, repeated for the length of the gap
    silence_sample = struct.pack('<h', 0)
    silence_data = [silence_sample] * gap_samples

    # 3. Combine pulses and gaps for the alarm sound
    full_data = []
    for _ in range(cycles):
        full_data.extend(pulse_data)
        full_data.extend(silence_data)

    # 4. Write the final data to the WAV file
    with wave.open(filename, 'w') as wav_file:
        wav_file.setparams((
            1,                       # nchannels (mono)
            2,                       # sampwidth (2 bytes for 16-bit)
            rate,                    # framerate
            len(full_data),          # nframes
            'NONE',                  # comptype
            'not compressed'         # compname
        ))
        wav_file.writeframes(b''.join(full_data))


# --- File Naming Utility ---

def get_unique_filename(base_name):
    """Checks if a file exists and appends a counter if necessary."""
    if not os.path.exists(base_name):
        return base_name

    name, ext = os.path.splitext(base_name)
    counter = 1
    while True:
        counter += 1
        new_filename = f"{name}_{counter}{ext}"
        if not os.path.exists(new_filename):
            return new_filename


# --- Playback Utility (OS-Specific) ---

def play_system_sound(filename):
    """Plays the generated WAV file using the simplest OS-specific method."""
    print("--- Playing Alarm ---")
    
    try:
        if sys.platform == "win32": # Windows: use winsound (built-in)
            import winsound
            winsound.PlaySound(filename, winsound.SND_FILENAME)
        elif sys.platform == "darwin": # macOS: use afplay (built-in)
            subprocess.run(['afplay', filename], check=True)
        elif sys.platform.startswith("linux"): # Linux: use aplay (common utility)
            # aplay is part of the ALSA utilities, often pre-installed
            subprocess.run(['aplay', filename], check=True)
        else:
            print(f"ERROR: Playback is not supported directly on {sys.platform}. Please play the file manually.")
    except Exception as e:
        # Handles cases where the utility (like 'aplay') is not found or fails
        print(f"Playback failed. Ensure your system's audio utility is available. Error: {e}")


# --- Main Application Logic ---

def get_user_input(prompt, default_value, input_type=float):
    """Prompts the user for input with a default value and handles conversion/validation."""
    while True:
        try:
            # Use specific input type for display format
            prompt_str = f"{prompt} (Default: {default_value}) > "
            user_input = input(prompt_str).strip()
            
            if not user_input:
                return default_value
            
            value = input_type(user_input)
            if value < 0:
                print("Value must be positive.")
                continue
            return value
        except ValueError:
            print("Invalid input. Please enter a number.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


def main():
    # --- 1. Get User Configurations ---
    print("--- Alarm Configuration ---")
    
    # Defaults: (frequency=880, duration=0.5, cycles=3, gap=0.1)
    frequency = get_user_input("Enter frequency (Hz)", 880)
    duration = get_user_input("Enter beep duration (seconds)", 0.5)
    cycles = get_user_input("Enter number of beeps/cycles", 3, int)
    gap = get_user_input("Enter gap between beeps (seconds)", 0.1)

    # --- 2. Generate Unique Filename ---
    
    # Create a base name from the configuration for easy identification
    base_name_template = f"f{int(frequency)}_d{duration}_c{cycles}_g{gap}.wav"
    alarm_file = get_unique_filename(base_name_template)

    print(f"\nConfiguration saved. Generating file: {alarm_file}")
    
    # --- 3. Generate and Play Alarm ---
    
    # Call the generation function with user inputs
    generate_square_wave_alarm(alarm_file, frequency, duration, cycles, gap)

    # Play the newly created file
    play_system_sound(alarm_file)
    
    print("\n--- Program Finished ---")
    input("Press ENTER to exit and keep the generated file...")


if __name__ == "__main__":
    main()
