import streamlit as st
import io
from PIL import Image
import numpy as np
import PyPDF2
import cv2
import pydub
import tempfile
import os
import qrcode
import base64
from datetime import datetime
from utils.encryption import encrypt_message, decrypt_message
from utils.steganography import (
    encode_image, decode_image,
    encode_audio, decode_audio,
    encode_video, decode_video,
    encode_pdf, decode_pdf
)
from utils.database import add_encoding_operation, get_recent_operations, get_operation_stats

# Set page config
st.set_page_config(
    page_title="Secure Steganography",
    page_icon="🔐",
    layout="wide"
)

# Initialize session state variables if they don't exist
if 'encoded_file' not in st.session_state:
    st.session_state.encoded_file = None
if 'encoded_file_name' not in st.session_state:
    st.session_state.encoded_file_name = None
if 'encoded_file_type' not in st.session_state:
    st.session_state.encoded_file_type = None
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'username' not in st.session_state:
    st.session_state.username = None
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

# App title and description
st.title("Multi-Format Steganography with AES Encryption")
st.markdown("""
This application allows you to hide messages securely in different file formats using:
1. **AES Encryption** - Protects your message with a password
2. **Steganography** - Hides the encrypted message in various media files
3. **QR Code Generation** - Creates QR codes containing your encrypted data
""")

# Show user login status
if st.session_state.logged_in:
    st.sidebar.success(f"Logged in as: {st.session_state.username}")
    if st.sidebar.button("Log Out"):
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.logged_in = False
        st.rerun()
else:
    st.sidebar.info("You are not logged in. Go to the Login page to create an account or sign in.")

# Sidebar navigation
st.sidebar.title("Navigation")
st.sidebar.markdown("""
- [Home](/) - Encode/Decode Messages
- [Login](/login) - User Authentication
- [Saved Messages](/saved_messages) - Manage Your Messages
- [Statistics](/statistics) - Usage Statistics
""")

# Main tabs
tab1, tab2 = st.tabs(["Encode Message", "Decode Message"])

# Encode tab
with tab1:
    st.header("Hide Your Secret Message")
    
    # Get message input
    message = st.text_area("Enter the secret message to hide:", height=150)
    
    # Get encryption key
    encryption_key = st.text_input("Enter encryption password:", type="password")
    
    # Option to save the message
    if st.session_state.logged_in:
        save_message = st.checkbox("Save this message in your account")
        
        if save_message:
            message_title = st.text_input("Message title:")
    
    # File upload
    st.subheader("Select carrier file:")
    file_format = st.radio(
        "Choose file format:",
        ["Image (PNG/JPEG)", "Audio (WAV)", "Video (MP4)", "PDF"]
    )
    
    uploaded_file = st.file_uploader(
        "Upload a file", 
        type=["png", "jpg", "jpeg", "wav", "mp4", "pdf"],
        help="Select the file in which you want to hide your message"
    )
    
    # Process encoding
    if st.button("Encode Message", disabled=(not uploaded_file or not message or not encryption_key)):
        try:
            with st.spinner("Processing..."):
                # Step 1: Encrypt the message
                encrypted_data = encrypt_message(message, encryption_key)
                
                # Save message if requested
                if st.session_state.logged_in and save_message and message_title:
                    from utils.database import Session, SavedMessage
                    
                    session = Session()
                    try:
                        new_message = SavedMessage(
                            user_id=st.session_state.user_id,
                            title=message_title,
                            encrypted_content=encrypted_data,
                            created_at=datetime.utcnow(),
                            modified_at=datetime.utcnow()
                        )
                        
                        session.add(new_message)
                        session.commit()
                        st.success(f"Message '{message_title}' saved to your account.")
                    except Exception as e:
                        session.rollback()
                        st.error(f"Error saving message: {str(e)}")
                    finally:
                        session.close()
                
                # Step 2: Apply steganography based on file type
                file_bytes = uploaded_file.getvalue()
                file_name = uploaded_file.name
                file_type_for_db = ""
                
                if "Image" in file_format:
                    file_type_for_db = "Image"
                    img = Image.open(io.BytesIO(file_bytes))
                    result_img = encode_image(img, encrypted_data)
                    
                    # Convert result to bytes for download
                    output = io.BytesIO()
                    result_img.save(output, format='PNG')
                    output_bytes = output.getvalue()
                    
                    st.session_state.encoded_file = output_bytes
                    st.session_state.encoded_file_name = f"encoded_{file_name.split('.')[0]}.png"
                    st.session_state.encoded_file_type = "image/png"
                    
                    # Display preview
                    st.success("Message encoded successfully!")
                    st.image(result_img, caption="Encoded Image (with hidden message)")
                
                elif "Audio" in file_format:
                    file_type_for_db = "Audio"
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as temp_file:
                        temp_file.write(file_bytes)
                        temp_file_path = temp_file.name
                    
                    # Process audio file
                    output_path = encode_audio(temp_file_path, encrypted_data)
                    
                    # Read the result file
                    with open(output_path, "rb") as f:
                        output_bytes = f.read()
                    
                    # Clean up temporary files
                    os.unlink(temp_file_path)
                    os.unlink(output_path)
                    
                    st.session_state.encoded_file = output_bytes
                    st.session_state.encoded_file_name = f"encoded_{file_name}"
                    st.session_state.encoded_file_type = "audio/wav"
                    
                    st.success("Message encoded successfully!")
                    st.audio(output_bytes, format='audio/wav')
                
                elif "Video" in file_format:
                    file_type_for_db = "Video"
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.mp4') as temp_file:
                        temp_file.write(file_bytes)
                        temp_file_path = temp_file.name
                    
                    # Process video file
                    output_path = encode_video(temp_file_path, encrypted_data)
                    
                    # Read the result file
                    with open(output_path, "rb") as f:
                        output_bytes = f.read()
                    
                    # Clean up temporary files
                    os.unlink(temp_file_path)
                    os.unlink(output_path)
                    
                    st.session_state.encoded_file = output_bytes
                    st.session_state.encoded_file_name = f"encoded_{file_name}"
                    st.session_state.encoded_file_type = "video/mp4"
                    
                    st.success("Message encoded successfully!")
                    st.video(output_bytes)
                
                elif "PDF" in file_format:
                    file_type_for_db = "PDF"
                    pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
                    output_bytes = encode_pdf(pdf_reader, encrypted_data)
                    
                    st.session_state.encoded_file = output_bytes
                    st.session_state.encoded_file_name = f"encoded_{file_name}"
                    st.session_state.encoded_file_type = "application/pdf"
                    
                    st.success("Message encoded successfully!")
                    st.download_button(
                        "Preview is not available for PDF files. Click here to download.",
                        data=output_bytes,
                        file_name=st.session_state.encoded_file_name,
                        mime="application/pdf"
                    )
                
                # Record the operation in the database
                try:
                    add_encoding_operation(
                        file_type=file_type_for_db,
                        original_filename=file_name,
                        encoded_filename=st.session_state.encoded_file_name,
                        message_length=len(message)
                    )
                except Exception as e:
                    st.warning(f"Could not record operation in database: {str(e)}")
            
            # Generate QR code for encrypted data
            if 'encrypted_data' in locals():
                # Create QR code with encrypted data
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(encrypted_data)
                qr.make(fit=True)
                
                # Create an image from the QR code
                qr_img = qr.make_image(fill_color="black", back_color="white")
                
                # Convert QR code to bytes for display and download
                qr_bytes = io.BytesIO()
                qr_img.save(qr_bytes, format='PNG')
                qr_bytes = qr_bytes.getvalue()
                
                # Store QR code in session state for download
                st.session_state.qr_code = qr_bytes
                
                # Display QR code
                st.subheader("QR Code of Encrypted Data")
                st.image(qr_bytes, caption="QR Code (contains encrypted data)")
                
                # Download buttons for QR code
                st.download_button(
                    label="Download QR Code",
                    data=qr_bytes,
                    file_name=f"qrcode_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png",
                    mime="image/png"
                )
            
            # Download button for encoded file
            if st.session_state.encoded_file:
                st.download_button(
                    label="Download Encoded File",
                    data=st.session_state.encoded_file,
                    file_name=st.session_state.encoded_file_name,
                    mime=st.session_state.encoded_file_type
                )
                
        except Exception as e:
            st.error(f"Error during encoding: {str(e)}")

# Decode tab
with tab2:
    st.header("Extract Hidden Message")
    
    # File upload for decoding
    st.subheader("Upload file with hidden message:")
    decode_method = st.radio(
        "Choose decode method:",
        ["Steganography File", "QR Code"],
        key="decode_method"
    )
    
    # Initialize decode_file_format for both paths
    decode_file_format = None
    
    if decode_method == "Steganography File":
        decode_file_format = st.radio(
            "Choose file format:",
            ["Image (PNG/JPEG)", "Audio (WAV)", "Video (MP4)", "PDF"],
            key="decode_format"
        )
        
        decode_file = st.file_uploader(
            "Upload a file", 
            type=["png", "jpg", "jpeg", "wav", "mp4", "pdf"],
            key="decode_file",
            help="Select the file from which you want to extract the hidden message"
        )
    else:  # QR Code option
        st.info("Upload a QR code that contains encrypted data")
        decode_file = st.file_uploader(
            "Upload QR Code", 
            type=["png", "jpg", "jpeg"],
            key="decode_qr",
            help="Select the QR code image that contains the encrypted data"
        )
    
    # Get decryption key
    decryption_key = st.text_input("Enter decryption password:", type="password", key="decode_key")
    
    # Process decoding
    if st.button("Decode Message", disabled=(not decode_file or not decryption_key)):
        try:
            with st.spinner("Processing..."):
                file_bytes = decode_file.getvalue()
                
                # Extract encrypted data based on decode method
                if decode_method == "Steganography File":
                    if decode_file_format and "Image" in decode_file_format:
                        img = Image.open(io.BytesIO(file_bytes))
                        encrypted_data = decode_image(img)
                    
                    elif decode_file_format and "Audio" in decode_file_format:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as temp_file:
                            temp_file.write(file_bytes)
                            temp_file_path = temp_file.name
                        
                        encrypted_data = decode_audio(temp_file_path)
                        os.unlink(temp_file_path)  # Clean up
                    
                    elif decode_file_format and "Video" in decode_file_format:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.mp4') as temp_file:
                            temp_file.write(file_bytes)
                            temp_file_path = temp_file.name
                        
                        encrypted_data = decode_video(temp_file_path)
                        os.unlink(temp_file_path)  # Clean up
                    
                    elif decode_file_format and "PDF" in decode_file_format:
                        pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
                        encrypted_data = decode_pdf(pdf_reader)
                
                else:  # QR Code decoding
                    try:
                        # Open the QR code image
                        qr_img = Image.open(io.BytesIO(file_bytes))
                        
                        # Resize to a reasonable size if the image is too large
                        if qr_img.width > 1000 or qr_img.height > 1000:
                            qr_img = qr_img.resize((800, 800), Image.LANCZOS)
                            
                        # Make sure we're working with RGB mode
                        if qr_img.mode != 'RGB':
                            qr_img = qr_img.convert('RGB')
                            
                        # Convert PIL image to OpenCV format safely
                        cv_img = np.array(qr_img)
                        
                        try:
                            # Create a QR Code detector
                            detector = cv2.QRCodeDetector()
                            
                            # Convert to grayscale for better detection
                            gray = cv2.cvtColor(cv_img, cv2.COLOR_RGB2GRAY)
                            
                            # Try to detect and decode
                            data, _, _ = detector.detectAndDecode(gray)
                            
                            # If detection fails, try with the original RGB image
                            if not data:
                                data, _, _ = detector.detectAndDecode(cv_img)
                        except Exception as e:
                            st.error(f"QR detection error: {str(e)}")
                            data = None
                        
                        if data:
                            encrypted_data = data
                            st.success("QR code decoded successfully!")
                        else:
                            st.error("Could not decode QR code. Please ensure it's a valid QR code.")
                            # Skip the rest of the processing
                            encrypted_data = None
                            
                    except Exception as e:
                        st.error(f"Error decoding QR code: {str(e)}")
                        encrypted_data = None
                
                # Check if we have encrypted data to decrypt
                if encrypted_data is not None:
                    try:
                        # Decrypt the extracted data
                        decrypted_message = decrypt_message(encrypted_data, decryption_key)
                        
                        # Display the result
                        st.success("Message extracted successfully!")
                        
                        st.subheader("Decoded Message:")
                        st.text_area("", decrypted_message, height=150, key="decoded_msg")
                    except Exception as e:
                        st.error(f"Error decrypting message: {str(e)}. Make sure you are using the correct decryption password.")
                        decrypted_message = None
                    
                    # Option to save the decoded message if logged in and we have a valid message
                    if st.session_state.logged_in and decrypted_message is not None:
                        save_decoded = st.checkbox("Save this decoded message to your account")
                        
                        if save_decoded:
                            save_title = st.text_input("Title for saved message:", key="save_decoded_title")
                            
                            if st.button("Save to Account"):
                                if save_title:
                                    # Re-encrypt with the same password for storage
                                    try:
                                        from utils.database import Session, SavedMessage
                                        
                                        re_encrypted = encrypt_message(decrypted_message, decryption_key)
                                        
                                        session = Session()
                                        try:
                                            new_message = SavedMessage(
                                                user_id=st.session_state.user_id,
                                                title=save_title,
                                                encrypted_content=re_encrypted,
                                                created_at=datetime.utcnow(),
                                                modified_at=datetime.utcnow()
                                            )
                                            
                                            session.add(new_message)
                                            session.commit()
                                            st.success(f"Decoded message saved as '{save_title}'")
                                        except Exception as e:
                                            session.rollback()
                                            st.error(f"Error saving message: {str(e)}")
                                        finally:
                                            session.close()
                                    except Exception as e:
                                        st.error(f"Error saving message: {str(e)}")
                                else:
                                    st.warning("Please enter a title for the saved message")
                else:
                    st.warning("No valid encrypted data found to decrypt. Please try again with a different file.")
                
        except Exception as e:
            st.error(f"Error during decoding: {str(e)}")

# Recent Activity
st.header("Recent Activity")
try:
    recent_operations = get_recent_operations(limit=5)

    if recent_operations:
        activity_data = []
        for op in recent_operations:
            # Format timestamp
            timestamp = op.timestamp.strftime("%Y-%m-%d %H:%M")
            
            activity_data.append(f"**{timestamp}**: Encoded a {op.file_type} file ({op.original_filename} → {op.encoded_filename})")
        
        for activity in activity_data:
            st.markdown(activity)
    else:
        st.info("No recent encoding activity.")
except Exception as e:
    st.warning("Could not retrieve recent activity. Database connection may be unavailable.")

# Add footer with information
st.markdown("---")
st.markdown("""
### About this application
This application uses AES-256 encryption with a password-derived key to first encrypt your message, 
then hides the encrypted data in your chosen file using Least Significant Bit (LSB) steganography 
for images, audio, and video, or metadata-based encoding for PDFs.

**Security Note**: The strength of the encryption depends on your password complexity. 
Use a strong, unique password for best security.

**QR Code Feature**: After encryption, the app generates a QR code containing your encrypted data,
which can be downloaded and shared. The QR code can be scanned and decoded in the app.

**Database Features**: Create an account to save encrypted messages and track your activity.
""")
