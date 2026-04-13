class SJWTError(Exception):
    """Clase base para todas las excepciones de SJWT."""
    pass

class SJWTInvalidTokenError(SJWTError):
    """Se lanza cuando el formato del token es totalmente inválido."""
    pass

class SJWTSignatureError(SJWTError):
    """Se lanza cuando la firma HMAC no coincide (posible manipulación)."""
    pass

class SJWTExpiredTokenError(SJWTError):
    """Se lanza cuando el token ha superado su tiempo de vida (exp)."""
    pass

class SJWTDecodeError(SJWTError):
    """Se lanza cuando ocurre un error durante el descifrado AES-GCM."""
    pass