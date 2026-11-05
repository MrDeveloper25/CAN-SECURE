class ReplayGuard:
    def __init__(self):
        # Mantiene el ultimo contador valido por ID de mensaje
        self.last_counters = {}

    def is_valid_sequence(self, msg_id: int, seq_counter: int) -> bool:
        """Comprueba que el contador sea mayor sin modificar el estado."""
        last_seq = self.last_counters.get(msg_id, -1)
        return seq_counter > last_seq

    def accept_sequence(self, msg_id: int, seq_counter: int):
        """Registra el contador despues de autenticar correctamente el mensaje."""
        self.last_counters[msg_id] = seq_counter