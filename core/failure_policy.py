class FailurePolicy:
    def __init__(self, max_failures: int = 3):
        self.failure_counts = {}
        self.max_failures = max_failures

    def register_failure(self, msg_id: int) -> bool:
        """Registra un fallo. Devuelve True si se debe activar el modo de alerta/degradacion."""
        self.failure_counts[msg_id] = self.failure_counts.get(msg_id, 0) + 1
        if self.failure_counts[msg_id] >= self.max_failures:
            print(f"[POLITICA DE FALLOS] ¡Alerta! {self.max_failures} fallos consecutivos en ID: {hex(msg_id)}")
            return True
        return False

    def reset_failures(self, msg_id: int):
        self.failure_counts[msg_id] = 0