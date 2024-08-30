from scapy.all import *
from cesar import cifrado_cesar
import sys
from datetime import datetime

def enviar_icmp_request(destino, mensaje, desplazamiento):
    ip_id = 1  # Inicializa el contador de identificación para IP
    icmp_id = 1234  # Identificador único para ICMP, puede ser cualquier número fijo para coherencia
    seq_number = 1  # Inicializa el contador de secuencia para ICMP

    for caracter in mensaje:
        letra_cifrada = cifrado_cesar(caracter, desplazamiento)
        
        # Solo enviar la letra cifrada como payload, eliminando el bloque fijo
        payload = letra_cifrada.encode('utf-8')
        
        paquete = IP(dst=destino, id=ip_id) / ICMP(id=icmp_id, seq=seq_number) / Raw(load=payload)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Captura el timestamp actual
        send(paquete)
        print(f"[{timestamp}] IP ID: {ip_id} - ICMP ID: {icmp_id} - Seq: {seq_number} - Letra original: {caracter} -> Letra cifrada: {letra_cifrada} (enviado en paquete ICMP)")
        
        ip_id += 1  # Incrementa el identificador para el siguiente paquete IP
        seq_number += 1  # Incrementa el número de secuencia para el siguiente paquete ICMP

def main():
    destino = "8.8.8.8"
    mensaje = sys.argv[1]
    desplazamiento = int(sys.argv[2])

    enviar_icmp_request(destino, mensaje, desplazamiento)

if __name__ == "__main__":
    main()
