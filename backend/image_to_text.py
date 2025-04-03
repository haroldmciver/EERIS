import pytesseract
from PIL import Image
from pdf2image import convert_from_path
from typing import Union, List
import os

def extract_text_from_image(image_path: str) -> str:
    """
    Extract text from an image file using OCR.
    
    Args:
        image_path: Path to the image file
        
    Returns:
        Extracted text as string
    """
    try:
        # Open the image
        image = Image.open(image_path)
        
        # Extract text using pytesseract
        text = pytesseract.image_to_string(image)
        
        return text.strip()
    except Exception as e:
        raise Exception(f"Error extracting text from image: {str(e)}")

def extract_text_from_pdf(pdf_path: str) -> str:
    """
    Convert PDF to images and extract text using OCR.
    
    Args:
        pdf_path: Path to the PDF file
        
    Returns:
        Combined extracted text from all pages
    """
    try:
        # Convert PDF to images with minimal settings
        images = convert_from_path(
            pdf_path,
            use_pdftocairo=True,
            strict=False
        )
        
        # Extract text from each page
        extracted_text = []
        for image in images:
            text = pytesseract.image_to_string(image)
            extracted_text.append(text.strip())
        
        # Combine text from all pages
        return "\n\n".join(extracted_text)
    except Exception as e:
        raise Exception(f"Error extracting text from PDF: {str(e)}")

def extract_text_from_file(file_path: str) -> str:
    """
    Extract text from either an image or PDF file.
    
    Args:
        file_path: Path to the file (image or PDF)
        
    Returns:
        Extracted text as string
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Get file extension
    _, ext = os.path.splitext(file_path.lower())
    
    # Handle based on file type
    if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']:
        return extract_text_from_image(file_path)
    elif ext == '.pdf':
        return extract_text_from_pdf(file_path)
    else:
        raise ValueError(f"Unsupported file type: {ext}") 