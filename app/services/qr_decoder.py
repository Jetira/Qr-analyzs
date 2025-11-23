"""
QR Code Decoder Service.

Decodes QR images and extracts embedded text/URLs.
"""
from typing import Tuple, Optional, Dict
from PIL import Image
import io
import logging
from pyzbar.pyzbar import decode as pyzbar_decode
from app.core.config import settings

logger = logging.getLogger(__name__)


class QrDecoderService:
    """Service for decoding QR codes from images."""
    
    def __init__(self):
        self.max_file_size = settings.QR_MAX_FILE_SIZE
        self.allowed_formats = settings.QR_ALLOWED_FORMATS
    
    async def decode_qr_image(
        self, 
        file_content: bytes, 
        filename: str
    ) -> Tuple[Optional[str], Dict]:
        """
        Decode QR code from image bytes.
        
        Args:
            file_content: Image file bytes
            filename: Original filename
        
        Returns:
            Tuple of (decoded_text, metadata_dict)
            If decoding fails, decoded_text will be None
        """
        metadata = {
            "size_bytes": len(file_content),
            "format": None,
            "dimensions": None,
            "error": None
        }
        
        try:
            # Check file size
            if len(file_content) > self.max_file_size:
                metadata["error"] = f"File too large (max {self.max_file_size} bytes)"
                return None, metadata
            
            # Check file extension
            file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if file_ext not in self.allowed_formats:
                metadata["error"] = f"Invalid format. Allowed: {', '.join(self.allowed_formats)}"
                return None, metadata
            
            # Open image
            image = Image.open(io.BytesIO(file_content))
            
            # Store metadata
            metadata["format"] = image.format or file_ext.upper()
            metadata["dimensions"] = f"{image.width}x{image.height}"
            
            # Decode QR code
            decoded_objects = pyzbar_decode(image)
            
            if not decoded_objects:
                metadata["error"] = "No QR code found in image"
                return None, metadata
            
            # Get first QR code data
            qr_data = decoded_objects[0].data.decode("utf-8", errors="ignore")
            
            return qr_data, metadata
        
        except Exception as e:
            metadata["error"] = f"Decoding error: {str(e)}"
            logger.error(f"Error decoding QR image: {e}", exc_info=True)
            return None, metadata
    
    def looks_like_url(self, text: str) -> bool:
        """Check if decoded text looks like a URL."""
        if not text:
            return False
        
        text_lower = text.lower().strip()
        
        # Check for URL schemes
        url_schemes = ["http://", "https://", "ftp://", "ftps://"]
        for scheme in url_schemes:
            if text_lower.startswith(scheme):
                return True
        
        # Check for domain-like patterns (without scheme)
        # e.g., "www.example.com" or "example.com/path"
        if text_lower.startswith("www."):
            return True
        
        # Simple heuristic: contains domain pattern
        if "." in text and ("/" in text or len(text.split(".")) >= 2):
            # Might be a URL without scheme
            return True
        
        return False


# Global instance
qr_decoder = QrDecoderService()
