import hmac
import hashlib

from core import config


class CryptoManager:
    """Genera y verifica MACs HMAC-SHA256.

    La longitud del MAC es configurable (ver config.MAC_LENGTH). Por defecto son
    32 bytes (256 bits, completo). Se puede truncar a 16 u 8 bytes para medir el
    trade-off seguridad/ancho de banda como KPI de overhead.
    """

    def __init__(self, secret_key: bytes, mac_length: int = config.MAC_LENGTH):
        if not 1 <= mac_length <= 32:
            raise ValueError("mac_length debe estar entre 1 y 32 bytes.")
        self.secret_key = secret_key
        self.mac_length = mac_length

    def generate_mac(self, data: bytes) -> bytes:
        """Genera una firma HMAC-SHA256 truncada a `mac_length` bytes."""
        full = hmac.new(self.secret_key, data, hashlib.sha256).digest()
        return full[: self.mac_length]

    def verify_mac(self, data: bytes, mac: bytes) -> bool:
        """Compara de forma segura (tiempo constante) la firma esperada contra
        la recibida."""
        expected_mac = self.generate_mac(data)
        return hmac.compare_digest(expected_mac, mac)
