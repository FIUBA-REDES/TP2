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

    def get_or_allocate_outbound(self, proto: int, priv_ip, priv_port: int,
                                 dst_ip, dst_port: int, in_port: int = None):
        """
        Retorna el puerto publico de la conexion. Si es nueva, le asigna uno
        libre. Retorna None si no quedan puertos libres.

        in_port es el puerto del switch donde esta el host privado; se guarda
        para que get_inbound pueda devolverlo.
        """
        key = (proto, priv_ip, priv_port, dst_ip, dst_port)

        # Conexion ya conocida: siempre el mismo puerto
        if key in self.outbound:
            return self.outbound[key]

        if not self.free_ports:
            return None

        pub_port = self.free_ports.popleft()
        self.outbound[key] = pub_port
        self.inbound[(proto, pub_port)] = (priv_ip, priv_port, in_port, dst_ip, dst_port)
        return pub_port

    def get_inbound(self, proto: int, pub_port: int):
        """
        Retorna (priv_ip, priv_port, in_port) o None si el puerto publico no
        tiene una conexion activa.
        """
        entry = self.inbound.get((proto, pub_port))
        if entry is None:
            return None
        priv_ip, priv_port, in_port, _, _ = entry
        return priv_ip, priv_port, in_port

    def active_connections(self) -> int:
        """Cantidad de conexiones con puerto asignado (util para logs)."""
        return len(self.inbound)
