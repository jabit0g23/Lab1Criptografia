from scapy.all import *
from cesar import cifrado_cesar
import sys

def enviar_icmp_request(destino, mensaje, desplazamiento):
    for caracter in mensaje:
        letra_cifrada = cifrado_cesar(caracter, desplazamiento)
        paquete = IP(dst=destino)/ICMP()/Raw(load=letra_cifrada)
        send(paquete)
        print(f"Letra original: {caracter} -> Letra cifrada: {letra_cifrada} (enviado en paquete ICMP)")

def main():
    destino = "8.8.8.8"
    mensaje =  sys.argv[1] 
    desplazamiento = int(sys.argv[2])

    enviar_icmp_request(destino, mensaje, desplazamiento)

if __name__ == "__main__":
    main()
