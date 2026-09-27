#!/bin/bash
# ==============================================================================
# Script para crear y levantar la interfaz CAN virtual (vcan0) en sistemas Linux.
# ==============================================================================

# Detener el script si ocurre algun error
set -e

INTERFACE="vcan0"

echo "[CAN-Secure] Configurando interfaz virtual $INTERFACE..."

# Cargar el módulo del kernel para CAN virtual
sudo modprobe vcan

# Verificar si la interfaz ya existe; si existe, removerla primero
if ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "[CAN-Secure] La interfaz $INTERFACE ya existe. Reiniciando..."
    sudo ip link delete dev "$INTERFACE"
fi

# Crear la interfaz vcan0
sudo ip link add dev "$INTERFACE" type vcan

# Levantar la interfaz
sudo ip link set up "$INTERFACE"

echo "[CAN-Secure] Interfaz $INTERFACE creada y activa exitosamente."
echo "[CAN-Secure] Puedes verificarla ejecutando: ip link show $INTERFACE"