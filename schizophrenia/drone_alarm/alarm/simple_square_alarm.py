import math
import wave
import struct

def generate_square_wave_alarm(filename, frequency=880, duration=0.5, cycles=3, gap=0.1, rate=44100, volume=32767):
    """Generates a pulsing square wave and saves it as a WAV file."""
    
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
            
        # Convert to 16-bit signed short bytes
        pulse_data.append(struct.pack('<h', int(sample)))

    # 2. Generate the silence gap
    gap_samples = int(rate * gap)
    silence_data = [struct.pack('<h', 0)] * gap_samples

    # 3. Combine pulses and gaps for the alarm sound
    full_data = []
    for _ in range(cycles):
        full_data.extend(pulse_data)
        full_data.extend(silence_data)

    # 4. Write the final data to the WAV file
    with wave.open(filename, 'w') as wav_file:
        wav_file.setparams((1, 2, rate, len(full_data), 'NONE', 'not compressed'))
        wav_file.writeframes(b''.join(full_data))

# Generate the alarm sound file
ALARM_FILE = 'simple_alarm.wav'
generate_square_wave_alarm(ALARM_FILE)
print(f"Generated alarm sound: {ALARM_FILE}")
input("Press ENTER to exit...")