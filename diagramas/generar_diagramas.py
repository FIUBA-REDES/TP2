#!/usr/bin/env python3
import subprocess

dot_antes = """digraph FlujoAntes {
    rankdir=TB;
    node [shape=box, style="filled,rounded", fontname="Arial", fontsize=11, margin=0.2];
    edge [fontname="Arial", fontsize=10];

    Start [label="Switch recibe paquete\\n(PacketIn en POX)", fillcolor="#e3f2fd", color="#1565c0", shape=ellipse];
    Parsed [label="¿POX pudo decodificar\\nla trama?", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
    DropParsed [label="DROP\\n(Trama no reconocida)", fillcolor="#ffcdd2", color="#c62828"];

    CheckL2 [label="¿Tipo de trama es IPv4?\\n(dl_type == 0x0800)", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
    DropL2 [label="LOG: Ignorar paquete\\n(Descarta ARP, IPv6, etc.)", fillcolor="#ffcdd2", color="#c62828"];

    CheckPrivate [label="¿IP origen pertenece a\\n192.168.1.0/24?", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
    DropPrivate [label="LOG: NO MATCH\\n(Descarta tráfico entrante\\no de otras redes)", fillcolor="#ffcdd2", color="#c62828"];

    InstallOut [label="Instalar Flujo Saliente en Switch:\\n• Match: nw_src, in_port\\n• Acción: Reescribe solo MACs\\n(src=PUBLIC_MAC, dst=H1_MAC hardcodeada)\\n• Output(PUBLIC_PORT)", fillcolor="#c8e6c9", color="#2e7d32"];
    InstallIn [label="Instalar Flujo Entrante en Switch:\\n• Match: nw_src=dstip, nw_dst=srcip\\n• Acción: Reescribe solo MACs\\n(src=PRIVATE_MAC, dst=packet.src)\\n• Output(in_port)", fillcolor="#c8e6c9", color="#2e7d32"];
    PacketOut [label="PacketOut al Switch:\\n• Reescribe MACs del paquete actual\\n• Envía paquete por PUBLIC_PORT", fillcolor="#e1bee7", color="#6a1b9a"];
    End [label="Fin de atención en Controlador", fillcolor="#cfd8dc", color="#455a64", shape=ellipse];

    Start -> Parsed;
    Parsed -> DropParsed [label="No"];
    Parsed -> CheckL2 [label="Sí"];
    CheckL2 -> DropL2 [label="No (e.g. ARP)"];
    CheckL2 -> CheckPrivate [label="Sí"];
    CheckPrivate -> DropPrivate [label="No"];
    CheckPrivate -> InstallOut [label="Sí"];
    InstallOut -> InstallIn;
    InstallIn -> PacketOut;
    PacketOut -> End;
}
"""

dot_despues = """digraph FlujoDespues {
    rankdir=TB;
    node [shape=box, style="filled,rounded", fontname="Arial", fontsize=11, margin=0.15];
    edge [fontname="Arial", fontsize=10];

    Start [label="Switch recibe paquete\\n(PacketIn en POX)", fillcolor="#e3f2fd", color="#1565c0", shape=ellipse];
    Parsed [label="¿Trama decodificada?", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
    DropParsed [label="DROP", fillcolor="#ffcdd2", color="#c62828"];

    CheckType [label="¿Tipo de protocolo L2?", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];

    # Rama ARP
    subgraph cluster_arp {
        label = "Módulo ARP Dinámico (Fran)";
        style = "dashed";
        color = "#1565c0";
        fontname = "Arial Bold";
        fontsize = 12;

        LearnARP [label="Aprender en tabla dinámica:\\narp_table[IP_src] = (MAC_src, in_port)", fillcolor="#bbdefb", color="#1976d2"];
        CheckPending [label="¿Había paquetes esperando\\nesta dirección IP?", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
        FlushPending [label="Desencolar paquetes y\\ndesapachar al Switch", fillcolor="#e1bee7", color="#6a1b9a"];
        CheckRouterIP [label="¿ARP Request pregunta por\\nIP pública o privada del Router?", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
        SendReply [label="Enviar ARP Reply con\\nMAC correspondiente (PUBLIC o PRIVATE)", fillcolor="#c8e6c9", color="#2e7d32"];
        DropARP [label="Ignorar ARP", fillcolor="#cfd8dc", color="#455a64"];
    }

    # Rama IPv4
    subgraph cluster_ip {
        label = "Módulo IPv4 + PAT + OpenFlow (Elias & Valen)";
        style = "dashed";
        color = "#2e7d32";
        fontname = "Arial Bold";
        fontsize = 12;

        CheckL4 [label="¿Protocolo L4?\\n(TCP, UDP o ICMP)", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
        CheckDir [label="¿Dirección del flujo?", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];

        # Saliente
        LookupNATOut [label="Buscar conexión en Tabla NAT\\n(proto, ip_priv, port_priv, ip_dst, port_dst)", fillcolor="#ffe0b2", color="#f57c00"];
        CheckAlloc [label="¿Existe mapeo\\nprevio?", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
        AllocPort [label="Asignar nuevo puerto público libre\\ndel pool (10000 - 65535)\\nRegistrar en Tabla NAT", fillcolor="#ffe0b2", color="#f57c00"];
        CheckMACDst [label="¿Se conoce la MAC del destino?\\n(Consultar arp_table)", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
        QueuePkt [label="Encolar paquete en buffer +\\nEmitir ARP Request por puerto público", fillcolor="#ffecb3", color="#ffa000"];

        InstallFlows [label="Instalar Reglas Bidireccionales en Switch:\\n1. Saliente: rewrite nw_src=PUB_IP, tp_src=port_pub, MACs + timeout\\n2. Entrante: rewrite nw_dst=priv_ip, tp_dst=port_priv, MACs + timeout", fillcolor="#c8e6c9", color="#2e7d32"];
        SendPacketOut [label="Modificar paquete actual (IP, Port, MACs)\\ny enviar PacketOut al Switch", fillcolor="#e1bee7", color="#6a1b9a"];

        # Entrante
        LookupNATIn [label="Buscar en Tabla NAT por puerto dst\\n(proto, port_dst_pub)", fillcolor="#ffe0b2", color="#f57c00"];
        CheckInMatch [label="¿Existe mapeo\\nen Tabla NAT?", shape=diamond, fillcolor="#fff9c4", color="#fbc02d"];
        DropIn [label="DROP (Conexión externa no solicitada)", fillcolor="#ffcdd2", color="#c62828"];
        ForwardIn [label="Instalar flujo inverso / Forward", fillcolor="#c8e6c9", color="#2e7d32"];
    }

    EndNode [label="Fin de procesamiento en Controlador\\n(El resto de los paquetes viaja solo por hardware/switch)", fillcolor="#d1c4e9", color="#512da8", shape=ellipse];

    # Conexiones
    Start -> Parsed;
    Parsed -> DropParsed [label="No"];
    Parsed -> CheckType [label="Sí"];

    CheckType -> LearnARP [label="ARP (0x0806)"];
    LearnARP -> CheckPending;
    CheckPending -> FlushPending [label="Sí"];
    CheckPending -> CheckRouterIP [label="No"];
    FlushPending -> CheckRouterIP;
    CheckRouterIP -> SendReply [label="Sí"];
    CheckRouterIP -> DropARP [label="No"];

    CheckType -> CheckL4 [label="IPv4 (0x0800)"];
    CheckL4 -> CheckDir [label="TCP / UDP / ICMP"];
    CheckL4 -> DropParsed [label="Otro L4"];

    CheckDir -> LookupNATOut [label="Saliente (desde Privada)"];
    LookupNATOut -> CheckAlloc;
    CheckAlloc -> AllocPort [label="No"];
    CheckAlloc -> CheckMACDst [label="Sí"];
    AllocPort -> CheckMACDst;
    CheckMACDst -> QueuePkt [label="No conocida"];
    CheckMACDst -> InstallFlows [label="Conocida"];
    InstallFlows -> SendPacketOut;
    SendPacketOut -> EndNode;

    CheckDir -> LookupNATIn [label="Entrante (desde Pública)"];
    LookupNATIn -> CheckInMatch;
    CheckInMatch -> DropIn [label="No"];
    CheckInMatch -> ForwardIn [label="Sí"];
    ForwardIn -> EndNode;
}
"""

with open("diagramas/flujo_antes.dot", "w") as f:
    f.write(dot_antes)

with open("diagramas/flujo_despues.dot", "w") as f:
    f.write(dot_despues)

# Compilar a SVG y PNG
subprocess.run(["dot", "-Tsvg", "diagramas/flujo_antes.dot", "-o", "diagramas/flujo_antes.svg"], check=True)
subprocess.run(["dot", "-Tpng", "diagramas/flujo_antes.dot", "-o", "diagramas/flujo_antes.png"], check=True)

subprocess.run(["dot", "-Tsvg", "diagramas/flujo_despues.dot", "-o", "diagramas/flujo_despues.svg"], check=True)
subprocess.run(["dot", "-Tpng", "diagramas/flujo_despues.dot", "-o", "diagramas/flujo_despues.png"], check=True)

print("Diagramas generados exitosamente en ./diagramas/")
