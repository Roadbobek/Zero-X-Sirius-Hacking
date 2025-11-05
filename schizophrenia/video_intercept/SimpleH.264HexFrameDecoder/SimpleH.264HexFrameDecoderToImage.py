import av
import binascii
from PIL import Image
import io
import sys

# NOTE ON DEPENDENCIES:
# This script requires the 'av' (PyAV) and 'Pillow' libraries.
# Install them using: pip install av Pillow

# --- Configuration ---/
# Your drone video is almost certainly H.264 (libx264) or H.265 (libx265).
# H.264 is the most common. If this fails, try 'h265'.
CODEC_NAME = 'h264'
OUTPUT_IMAGE_NAME = 'decoded_frame.png'

# --- RAW PAYLOAD INPUT (MANDATORY: REPLACE THIS STRING) ---
# Paste the full, raw hex payload string captured from your drone's TShark log
# inside the triple quotes below.
#
# IMPORTANT: The hex string must be continuous (no spaces, newlines, or '0x' prefixes)
# and must represent a complete NAL unit sequence (SPS/PPS/IDR frame) for the decoder to work.
# You may need to manually trim off custom drone headers if they exist before the H.264 start codes (00000001).
RAW_HEX_PAYLOAD = "9301380402020001b785000000000000b785000000000000b6850000000000002200000041000000900201000005d0023200040001018bab76fad0003f9520024fa5003b2698077cf7a005e6800cf6e71400a2800ebf5a005c11d79a002800c7cb8fc680141f61c0ed400a38eb40071da8014601e7a50019ce3b5002ff003a0033efed4000a005e493e940013924f5a005e9d3ad002139e40e6980e52c09298dc4103eb401cbcf94d7ec8afcade729fc73480ea676db7127ae79a0068e4641ff001a005eb40067d6801070303393400bd78cfdda0033cf1cd002f51da8003d3903d88a002800ef93800d001ec2800e94000a0039ef400668017a5300e0e45200e68003c83ed400641a003ebc8a0033c7a814009d3a93d680178dded40013823228013bfa5002e79a003d47bd001dfde800fe21919f4a003073da80038dbc12466800a000f140076a003b9a00338ed40076e280000127b63be28001c608383d7eb4001ebf5a000f718e28017391ef4006477a00518c827a500275ef4c05fa50019cd200a003391d2801a564f309133329fe1da001fe3400eef40037080776efe9400671d0d001da8013a9cd002e7d06680100f97de980bbb03073480339a004ce091b871da800ce4e714c03a5200c6071f953003c7b7140099e3ebd8d200e9d7a5001ea38c5006178b10edd3e43e8e99fa50060e298098a4014c05a004a4014c0314001f6a004a0069e28012900b400e14017b446dba848a3f8e123f5152c0d8f734805efed4c02980b4000e9cd00267da8010d001efda90087a7140053038aa002800a00298050014802800a0028016800a002800a002800a002800a601400500148005002d300a002800a002800a007ad003c5002d0028a0051400ea00d9d07acfecb480d4cf3400bc64904d002f734000efdf3400a0f34c051d6800ef40052014645002fe74c0334000c67de801d9e28001d79a0053ef4005002fe82800a005ef8ec680023183c9cf1400bde8001400a78eb40074a002801723028010f4e33c5003ba9c50002800a603973e9919e4520395d47e5d5eddb38db30fe7401d64edfbf6c1c6793400d031c9e09a003be7ad0021e0f4a0039c0c64d002e3da800a003140003f85002e4fd6801319eb4c0504f39a005e9d450026738c607d280141e79249a0043920e6900bd001cd00267268017b5001819c9e9d7eb40016247418fa50003a645002752722800e0e41a005e837753d00a004190304e68017b734009400bda8003c7340099ebed4007a5001400b9eb8a003eb8a00075ce3a5001d074c902800fa500181de8013a2e07ae68017f9d0019f426800c9c500033ebd69800c0f507d0f7a005e7b714803b63f1a003a0cd002e49e0d0022f4c804e38a005f706800e4f7a0033ebc1a6018395381934804c8dc7de800ea0739a0008e"

def decode_payload(raw_hex_payload: str):
    """
    Converts the raw hex payload into binary bytes and attempts to decode
    the first frame using the specified video codec (PyAV/FFmpeg).
    """
    if not raw_hex_payload:
        print("ERROR: RAW_HEX_PAYLOAD is empty. Please paste your drone's captured hex data.", file=sys.stderr)
        return

    print(f"Payload length: {len(raw_hex_payload)} characters (approx. {len(raw_hex_payload) // 2} bytes)")

    try:
        # 1. Convert the hexadecimal string into raw binary bytes
        binary_payload = binascii.unhexlify(raw_hex_payload)
    except binascii.Error as e:
        print(f"ERROR: Failed to convert hex to binary. Check for invalid characters in your payload.", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        return

    # 2. Initialize the Codec Context
    try:
        # Create a CodecContext configured for decoding the specific CODEC_NAME
        codec_context = av.CodecContext.create(CODEC_NAME, 'r')
    except av.InvalidCodecsError as e:
        print(f"ERROR: The codec '{CODEC_NAME}' is not available in PyAV/FFmpeg.", file=sys.stderr)
        return

    # 3. Decode the frame
    # We use iter_decode because the input bytes might contain multiple NAL units
    # (like SPS, PPS, and the video frame data itself)
    print(f"Attempting to decode using codec: {CODEC_NAME}...")
    decoded_frames = []
    try:
        # The decode method is highly sensitive to correct H.264 data format.
        decoded_frames = list(codec_context.decode(binary_payload))
    except av.FFmpegError as e:
        print("\n--- DECODING FAILED ---", file=sys.stderr)
        print("This usually means the payload is incomplete, corrupted, or has non-H.264 data at the start.", file=sys.stderr)
        print(f"FFmpeg Error Details: {e}", file=sys.stderr)
        print("Suggestion: Manually check the start of your hex string for the H.264 start code: 00000001.", file=sys.stderr)
        return

    if not decoded_frames:
        print(f"SUCCESS: Decoded {len(decoded_frames)} frames.", file=sys.stderr)
        print("WARNING: No complete frames were decoded. The payload might only contain header data (SPS/PPS).", file=sys.stderr)
        return

    # 4. Process the first successful frame
    frame = decoded_frames[0]
    print(f"\nSUCCESS: Decoded 1 frame! Resolution: {frame.width}x{frame.height}")

    # Convert the PyAV Frame object to a PIL Image
    image = frame.to_image()

    # Save the image
    image.save(OUTPUT_IMAGE_NAME)
    print(f"Image successfully saved as '{OUTPUT_IMAGE_NAME}'")


if __name__ == "__main__":
    decode_payload(RAW_HEX_PAYLOAD)
