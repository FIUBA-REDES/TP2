from collections import deque

# Numeros de protocolo IP (campo "protocol" del encabezado IPv4)
ICMP = 1
TCP = 6
UDP = 17


class NATTable:
    """
    Tabla de traduccion PAT.

    Guarda que conexion privada usa que puerto publico, reparte puertos libres
    sin repetir y los recicla cuando la conexion termina. No sabe nada de
    OpenFlow ni de paquetes: solo guarda y busca datos.
    """

    def __init__(self, start_port: int = 10000, end_port: int = 65535):
        if not 0 < start_port <= end_port <= 65535:
            raise ValueError("rango de puertos invalido")

        # Puertos publicos libres. Se asigna por la izquierda y se devuelve
        # por la derecha, asi un puerto recien liberado tarda en volver a
        # usarse (evita que paquetes viejos caigan en una conexion nueva).
        self.free_ports = deque(range(start_port, end_port + 1))

        # Saliente: (proto, priv_ip, priv_port, dst_ip, dst_port) -> pub_port
        self.outbound = {}

        # Entrante: (proto, pub_port) -> (priv_ip, priv_port, in_port, dst_ip, dst_port)
        # Se guarda tambien el destino para poder reconstruir la clave
        # saliente al liberar.
        self.inbound = {}
