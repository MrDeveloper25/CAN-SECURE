def calculate_kpis(ids_results: dict):
    total = ids_results.get("total_frames", 1)
    detected = ids_results.get("spoofing_detected", 0) + ids_results.get("replay_detected", 0) + ids_results.get("dos_alerts", 0)
    
    detection_rate = (detected / total) * 100 if total > 0 else 0
    
    print("\n================ RESUMEN DE KPIs ================")
    print(f"Total de Tramas Monitoreadas: {total}")
    print(f"Ataques de Spoofing Detectados: {ids_results.get('spoofing_detected', 0)}")
    print(f"Ataques de Replay Detectados: {ids_results.get('replay_detected', 0)}")
    print(f"Alertas de DoS: {ids_results.get('dos_alerts', 0)}")
    print(f"Tasa de Detección Final: {detection_rate:.2f}%")
    print("=================================================")

if __name__ == "__main__":
    # Datos de prueba
    dummy_results = {"total_frames": 10, "spoofing_detected": 1, "replay_detected": 1, "dos_alerts": 0}
    calculate_kpis(dummy_results)