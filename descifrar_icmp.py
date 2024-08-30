from scapy.all import rdpcap, ICMP, Raw
from cesar import cifrado_cesar
from colorama import Fore, Style
import re

def cargar_paquetes(filepath):
    """Carga los paquetes ICMP desde un archivo .pcapng."""
    paquetes = rdpcap(filepath)
    mensaje_cifrado = ""

    for paquete in paquetes:
        if ICMP in paquete and Raw in paquete:
            mensaje_cifrado += paquete[Raw].load.decode(errors="ignore")

    return mensaje_cifrado

def descifrar_todos_los_desplazamientos(mensaje_cifrado):
    """Descifra el mensaje cifrado probando todos los desplazamientos posibles."""
    posibles_mensajes = []
    
    for desplazamiento in range(1, 26):
        mensaje_descifrado = cifrado_cesar(mensaje_cifrado, -desplazamiento)
        posibles_mensajes.append((desplazamiento, mensaje_descifrado))

    return posibles_mensajes

def identificar_mensaje_probable(mensajes):
    """Identifica el mensaje más probable basado en la presencia de palabras comunes."""
    palabras_comunes = re.compile(r'\b(de|la|que|el|en|y|a|los|del|se|por|con|un|para|es)\b', re.IGNORECASE)
    mejor_puntaje = 0
    mensaje_probable = None

    for desplazamiento, mensaje in mensajes:
        coincidencias = len(palabras_comunes.findall(mensaje))
        if coincidencias > mejor_puntaje:
            mejor_puntaje = coincidencias
            mensaje_probable = (desplazamiento, mensaje)

    return mensaje_probable

def main():
    # Cambia la ruta del archivo a la ubicación de tu archivo .pcapng
    archivo_pcap = "./captura.pcapng"
    
    # Carga el mensaje cifrado desde el archivo de captura
    mensaje_cifrado = cargar_paquetes(archivo_pcap)

    # Descifra probando todos los desplazamientos posibles
    mensajes_descifrados = descifrar_todos_los_desplazamientos(mensaje_cifrado)

    # Identifica el mensaje más probable
    desplazamiento_probable, mensaje_probable = identificar_mensaje_probable(mensajes_descifrados)

    # Imprime todos los mensajes descifrados y resalta el más probable
    for desplazamiento, mensaje in mensajes_descifrados:
        if desplazamiento == desplazamiento_probable:
            print(Fore.GREEN + f"Desplazamiento {desplazamiento}: {mensaje}" + Style.RESET_ALL)
        else:
            print(f"Desplazamiento {desplazamiento}: {mensaje}")

if __name__ == "__main__":
    main()
