class ReplayGuard:
    def __init__(self):
        # Mantiene el ultimo contador valido por ID de mensaje
        self.last_counters = {}

    def is_valid_sequence(self, msg_id: int, seq_counter: int) -> bool:
        """Verifica que el contador recibido sea estrictamente mayor al anterior."""
        last_seq = self.last_counters.get(msg_id, -1)
        if seq_counter > last_seq:
            self.last_counters[msg_id] = seq_counter
            return True
        return False