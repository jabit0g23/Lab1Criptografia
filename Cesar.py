import sys

def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            ascii_offset = 65 if caracter.isupper() else 97
            nueva_letra = chr((ord(caracter) - ascii_offset + desplazamiento) % 26 + ascii_offset)
            resultado += nueva_letra
        elif caracter.isdigit():
            nueva_cifra = chr((ord(caracter) - ord('0') + desplazamiento) % 10 + ord('0'))
            resultado += nueva_cifra
        else:
            resultado += caracter
    return resultado

# Ejemplo de uso

"""
texto_original = sys.argv[1] 
desplazamiento = int(sys.argv[2])

texto_cifrado = cifrado_cesar(texto_original, desplazamiento)
print("Texto cifrado:", texto_cifrado)

# Para descifrar
texto_descifrado = cifrado_cesar(texto_cifrado, -desplazamiento)
print("Texto descifrado:", texto_descifrado)
"""