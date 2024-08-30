from scapy.all import *
from cesar import cifrado_cesar
import sys
from datetime import datetime

def enviar_icmp_request(destino, mensaje, desplazamiento):
    ip_id = 1  # Inicializa el contador de identificación para IP
    icmp_id = 1234  # Identificador único para ICMP, puede ser cualquier número fijo para coherencia
    seq_number = 1  # Inicializa el contador de secuencia para ICMP

    # Define el payload ICMP, manteniendo los bytes desde 0x10 a 0x37 coherentes
    # Aquí, los bytes de 0x10 a 0x37 son definidos y se mantienen consistentes
    payload_fijo = b'\x00' * 16 + b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F' \
                   + b'\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F' + b'\x30\x31\x32\x33\x34\x35\x36\x37'
    
    for caracter in mensaje:
        letra_cifrada = cifrado_cesar(caracter, desplazamiento)
        
        # Combina el payload fijo con la letra cifrada
        # El payload inicial mantiene los bytes de 0x10 a 0x37
        payload = payload_fijo + letra_cifrada.encode('utf-8')
        
        paquete = IP(dst=destino, id=ip_id) / ICMP(id=icmp_id, seq=seq_number) / Raw(load=payload)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')  # Captura el timestamp actual
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
