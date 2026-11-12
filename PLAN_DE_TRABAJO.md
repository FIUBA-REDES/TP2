# Plan de Trabajo y División de Tareas: TP2 SDN - NAT
**Materia:** Redes (TA048) / Introducción a los Sistemas Distribuidos (75.43) - FIUBA  
**Objetivo:** Implementación de NAT saliente con traducción por puertos (PAT) sobre POX y Mininet.

---

## 1. Arquitectura Modular y Desacoplamiento

Para que **5 integrantes trabajen en simultáneo sin pisarse ni bloquearse**, el código se divide en módulos independientes con contratos de interfaz bien definidos:

```
tp_sdn_nat/
│
├── topo.py               # [Atu] Topología Mininet y scripts de prueba
├── arp_manager.py        # [Fran] Motor de ARP dinámico y cola de paquetes
├── nat_table.py          # [Elias] Estructura de estado PAT y asignación de puertos
├── protorouter.py        # [Valen] Orquestador de OpenFlow y controlador POX
│
├── tests/                # [Atu y Ramiro] Scripts de prueba automáticos y capturas
└── informe/              # [Ramiro] Informe técnico en PDF y checklist de demo
```

---

## 2. Contratos de Interfaz (Firmas Acordadas)

Antes de programar, todos respetan estas firmas para poder trabajar con mocks/stubs sin esperar a que el compañero termine.

### A. Módulo ARP (`arp_manager.py`)
```python
class ARPManager:
    def __init__(self, connection, router_config):
        """
        router_config = {
            'public_ip': IPAddr, 'public_mac': EthAddr, 'public_port': int,
            'private_ip': IPAddr, 'private_mac': EthAddr
        }
        """
        pass

    def handle_arp(self, event) -> None:
        """Procesa un paquete ARP entrante (Request o Reply)."""
        pass

    def get_mac(self, ip: IPAddr) -> EthAddr | None:
        """Devuelve la MAC si ya fue aprendida, o None si no se conoce."""
        pass

    def resolve_or_queue(self, target_ip: IPAddr, out_port: int, packet_out_callback) -> bool:
        """
        Si la MAC de target_ip se conoce, ejecuta packet_out_callback inmediatamente y retorna True.
        Si no se conoce, envía un ARP Request por out_port, encola el callback y retorna False.
        """
        pass
```

### B. Módulo NAT (`nat_table.py`)
```python
class NATTable:
    def __init__(self, start_port: int = 10000, end_port: int = 65535):
        pass

    def get_or_allocate_outbound(self, proto: int, priv_ip: IPAddr, priv_port: int, dst_ip: IPAddr, dst_port: int) -> int:
        """Retorna el puerto público ya asignado o asigna uno libre nuevo."""
        pass

    def get_inbound(self, proto: int, pub_port: int) -> tuple[IPAddr, int, int] | None:
        """Retorna (priv_ip, priv_port, in_port) o None si el puerto público no tiene mapeo activo."""
        pass

    def release_port(self, proto: int, pub_port: int) -> None:
        """Libera el puerto público cuando el flujo expira en el switch."""
        pass
```

---

## 3. División de Tareas por Integrante

### 🧑‍💻 Atu (Integrante 1): Topología y Automatización de Pruebas
**Archivos principales:** `topo.py`, `tests/run_tests.sh`

- [x] **Extender topología**: Agregar hosts `h3` (`192.168.1.3/24`) y `h4` (`192.168.1.4/24`) conectados a `s1`.
- [ ] **Eliminar ARP estático**: Remover las llamadas a `setARP` de `topo.py`.
- [ ] **Parametrización**: Permitir configurar IPs, MACs y subredes por parámetros o variables para evitar hardcodeos (exigencia de la demo).
- [ ] **Scripts de prueba en Mininet**:
  - [ ] Test 1: Conectividad ICMP (`ping` individual y concurrente).
  - [ ] Test 2: Concurrencia TCP (servidor HTTP en `h1`, descargas simultáneas desde `h2`, `h3` y `h4`).
  - [ ] Test 3: Tráfico UDP bidireccional con `iperf`.
- [ ] **Validación con Wireshark / Tcpdump**: Exportar archivos `.pcap` en interfaces `s1-eth1` y `s1-eth2` verificando la traducción de IPs y puertos.

---

### 🧑‍💻 Fran (Integrante 2): Motor ARP Dinámico
**Archivos principales:** `arp_manager.py`, `tests/test_arp.py`

- [x] **Tabla ARP en memoria**: Estructura `arp_table = {IPAddr: (EthAddr, in_port)}`.
- [x] **Responder a consultas dirigidas al router (ARP Request)**:
  - Si preguntan por la IP privada del router (`192.168.1.254`), responder con `PRIVATE_MAC`.
  - Si preguntan por la IP pública del router (`200.0.0.254`), responder con `PUBLIC_MAC`.
- [x] **Generar consultas del router (ARP Request)**:
  - Enviar broadcast `ff:ff:ff:ff:ff:ff` cuando el router necesita resolver una IP destino desconocida (ej. el servidor `h1`).
- [x] **Cola de paquetes pendientes (`pending_packets`)**:
  - Guardar paquetes que esperan resolución de MAC.
  - Al recibir el `ARP Reply`, registrar la MAC y despachar los paquetes encolados.
- [x] **Tests unitarios aislados**: Probar el aprendizaje y generación de paquetes ARP sin requerir Mininet activo.

---

### 🧑‍💻 Elias (Integrante 3): Motor de Estado y Asignación de Puertos (PAT)
**Archivos principales:** `nat_table.py`, `tests/test_nat.py`

- [x] **Pool de puertos públicos**: Rango configurable (por defecto `10000` a `65535`) gestionado con conjuntos/colas para O(1).
- [x] **Mapeos bidireccionales**:
  - Saliente: `(proto, ip_priv, port_priv, ip_dst, port_dst) -> port_pub`
  - Entrante: `(proto, port_pub) -> (ip_priv, port_priv, in_port)`
- [x] **Soporte de protocolos de transporte**: TCP (`0x06`) y UDP (`0x11`).
- [x] **Soporte ICMP**: Mapear identificador ICMP (`icmp.id`) como pseudo-puerto para permitir que múltiples hosts hagan `ping`.
- [x] **Reutilización y liberación**: Método `release_port()` que recicla el puerto al expirar el flujo.
- [x] **Tests unitarios**: Validar no colisión de puertos entre distintos hosts privados con el mismo puerto de origen hacia el mismo servidor.

---

### 🧑‍💻 Valen (Integrante 4): Orquestador OpenFlow y Controlador Principal
**Archivos principales:** `protorouter.py`

- [x] **Despacho en `_handle_PacketIn`**: Diferenciar `ARP_TYPE` (derivar a `ARPManager`) de `IP_TYPE`.
- [x] **Instalación de Flujos OpenFlow (`ofp_flow_mod`)**:
  - **Flujo Saliente**:
    - Match: `dl_type=0x800`, `nw_proto`, `in_port`, `nw_src`, `tp_src`, `nw_dst`, `tp_dst`.
    - Acciones: Set `nw_src=PUBLIC_IP`, Set `tp_src=port_pub`, Set `dl_src=PUBLIC_MAC`, Set `dl_dst=mac_destino`, `output(PUBLIC_PORT)`.
  - **Flujo Entrante**:
    - Match: `dl_type=0x800`, `nw_proto`, `in_port=PUBLIC_PORT`, `nw_src=dst_ip`, `tp_src=dst_port`, `nw_dst=PUBLIC_IP`, `tp_dst=port_pub`.
    - Acciones: Set `nw_dst=priv_ip`, Set `tp_dst=priv_port`, Set `dl_src=PRIVATE_MAC`, Set `dl_dst=mac_privada`, `output(in_port)`.
- [x] **Timeouts**: Configurar `idle_timeout` (ej. 15-30s) y flag `OFPFF_SEND_FLOW_REM`.
- [x] **Evento `_handle_FlowRemoved`**: Recibir la notificación del switch y avisar a `NATTable` para liberar el puerto público.
- [x] **Despacho del primer paquete (`ofp_packet_out`)**: Traducir y reenviar el paquete que generó el `PacketIn` para no perder el primer SYN.

---

### 🧑‍💻 Ramiro (Integrante 5): Informe Técnico, Diagramas y Preparación de Demo
**Archivos principales:** `informe/informe.md` (o `.tex` / `.pdf`), `informe/diagramas/`

- [ ] **Redacción del Informe (Secciones obligatorias 7.1)**:
  - [ ] 1. Descripción general de la solución y arquitectura de software.
  - [ ] 2. Diseño de la tabla NAT y estrategia de asignación de puertos.
  - [ ] 3. Manejo de ARP (solicitudes, respuestas y cola de espera).
  - [ ] 4. Estrategia de instalación de flujos OpenFlow y políticas de timeouts.
  - [ ] 5. Decisiones de diseño, trade-offs y problemas encontrados con sus soluciones.
  - [ ] 6. Pruebas realizadas: conectividad básica, múltiples clientes concurrentes y diferentes tráficos (TCP/UDP/ICMP).
  - [ ] 7. Conclusión.
- [ ] **Diagramas de secuencia**: Intercambio de mensajes ARP y handshake TCP a través del switch y controlador.
- [ ] **Checklist para la Demostración (Sección 7.3)**:
  - [ ] Guion de prueba para cambiar IPs/MACs al vuelo frente a los docentes.
  - [ ] Demostración de múltiples conexiones salientes compartiendo la misma IP pública.
  - [ ] Explicación del funcionamiento interno del controlador y las tablas OpenFlow en el switch (`dpctl dump-flows`).

---

## 4. Cronograma de Integración y Entregas

| Fase | Plazo sugerido | Hitos |
| :--- | :--- | :--- |
| **Fase 1: Módulos Base** | Día 1 | Topología lista sin ARP estático. `arp_manager.py` y `nat_table.py` testeados con unit tests. |
| **Fase 2: Integración POX** | Día 2 | `protorouter.py` integra ARP y NAT. Se logra `ping` exitoso entre `h2` y `h1`. |
| **Fase 3: Tráfico Concurrente** | Día 3 | Pruebas de `iperf` y `curl` simultáneas desde múltiples clientes. Flujos instalados en el switch sin re-entrar al controlador. |
| **Fase 4: Robustez y Demo** | Día 4 | Validación de timeouts, liberación de puertos y prueba de cambio de IPs/MACs arbitrarias. |
| **Fase 5: Cierre Informe** | Día 5 | Consolidación de gráficos, capturas de Wireshark y entrega del PDF. |
