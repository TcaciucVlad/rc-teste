import socket
import threading
import time
from agent.mib import *
from snmp_protocol.ber import *

#Configurari initiale
AGENT_IP = "127.0.0.1"
AGENT_PORT = 16100
MANAGER_IP = "127.0.0.1"
MANAGER_TRAP_PORT = 50162 #Portul pe care se trimit trap-urile catre manager
ENCODING = "utf-8"

def get_next_oid(current_oid: str) : #are scopul de a genera urmatorul element din mib, pt cererile de tip GETNEXT

    #se extrag elementele din mib si se sorteaza lexicografic
    sorted_oids = sorted(
        MIB.keys(),
        key=lambda oid: [int(part) for part in oid.split(".") if part] #sparge oid-ul in mai multe parti, folosind "." ca separator, iar mai apoi converteste informatia in intreg
    )

    try:
        current_index = sorted_oids.index(current_oid) #cautam indexul oid_ului curent
        if current_index + 1 < len(sorted_oids): #verificam daca mai exista alt oid
            next_oid = sorted_oids[current_index+1]
            return next_oid
        else:
            return None

    except ValueError:
        raise KeyError(f"OID inexistent in MIB: {current_oid}") #daca oid-ul curent nu exista aruncam o eroare


def send_trap_text(message: str): #Trimite trap-uri catre manager prin MANAGER_TRAP_PORT definit anterior

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.sendto(message.encode(ENCODING), (MANAGER_IP, MANAGER_TRAP_PORT))


#Crearea mesajelor ber ce vor fi transmise catre manager
def build_ber_response(current_oid: str, value: int) -> bytes:

    #Forma generala a unui mesaj:
    """
    SEQUENCE {
        INTEGER version
        OCTET STRING community
        SEQUENCE {              -- PDU
            INTEGER request-id
            INTEGER error-status
            INTEGER error-index
            SEQUENCE {           -- VarBindList
                SEQUENCE { OID, INTEGER value }
            }
        }
    }
    """

    snmp_version = ber_code_integer(0)
    community_name = ber_code_octet(b"public")

    # Secventa { OID, INTEGER value }
    oid_numbers = [int(part) for part in current_oid.split(".")] #sparge oid-ul in mai multe parti, folosind "." ca separator, iar mai apoi converteste informatia in intreg pt a putea fi codificata BER
    encoded_oid = ber_code_oid(oid_numbers) #codificare OID
    encoded_value = ber_code_integer(int(value)) #codificare valoare extrasa din MIB
    varbind = ber_code_sequence(encoded_oid + encoded_value) #se concateneaza cele 2 reprezentari, dupa care se codifica secventa

    # Secventa SEQUENCE {  -- VarBindList SEQUENCE { OID, INTEGER value } }
    varbind_list = ber_code_sequence(varbind)

    # Secventa EQUENCE { -- PDU / INTEGER request-id / INTEGER error-status / INTEGER error-index
    request_id = ber_code_integer(1)
    error_status = ber_code_integer(0)
    error_index = ber_code_integer(0)
    pdu = ber_code_sequence(request_id + error_status + error_index + varbind_list) #concatenare + codificare secventa


    snmp_message = ber_code_sequence(snmp_version + community_name + pdu) #concatenare + codificare secventa
    return snmp_message

#procesarea cererilor venite de la MANAGER
def process_request(request: str) -> bytes:

        if not request:
            return ber_code_octet(b"ERROR: WRONG process_request() PARAMETER")

        aux = request.strip().split() #pdu-ul este spart in mai multe blocuri de info denumire_PDU + oid
        pdu = aux[0].upper() #se extrage denumirea PDU-ului

        #GET oid
        if pdu == "GET" and len(aux) == 2:
            oid = aux[1]
            value = get_value(oid) #se extrage din MIB valoarea oid-ului
            return build_ber_response(oid, int(value))

        #GETNEXT oid
        elif pdu == "GETNEXT" and len(aux) == 2:
            oid = aux[1]
            next_oid = get_next_oid(oid) #se apleeaza functia de gasire a urmatorului oid

            if not next_oid:
                return ber_code_octet(b"ERROR : NEXT_OID INEXISTENT")

            value = get_value(next_oid)
            return build_ber_response(next_oid, int(value))

        #SET oid val
        elif pdu == "SET" and len(aux) == 3:
            oid = aux[1]
            value = aux[2]

            set_tempUnit(oid, int(value))
            value = get_value(oid) #se citeste valoarea actualizata
            return build_ber_response(oid, int(value)) #se trimite pt confirmare

        else:
            return ber_code_octet(b"ERROR : process_request INVALID ")

#monitorizare si trimitere trap-uri
def checks():

    OID_CPU   = "1.3.6.1.4.1.99999.2.1.0"
    OID_MEM   = "1.3.6.1.4.1.99999.2.2.0"
    OID_TEMP  = "1.3.6.1.4.1.99999.2.4.0"

    while True:

        cpu_value  = int(get_value(OID_CPU))
        mem_value  = int(get_value(OID_MEM))
        temp_value = int(get_value(OID_TEMP))

        if cpu_value > praguri_maxime["cpuMax"]:
            send_trap_text(f"TRAP CPU_MAX: {cpu_value}% > {praguri_maxime['cpuMax']}%")

        if mem_value > praguri_maxime["memMax"]:
            send_trap_text(f"TRAP MEM_MAX: {mem_value}MiB > {praguri_maxime['memMax']}MiB")

        if temp_value > praguri_maxime["tempMax"]:
            send_trap_text(f"TRAP TEMP_MAX: {temp_value} > {praguri_maxime['tempMax']}")

            time.sleep(5)


def start_agent():

    #ACTIVAM FUNCTIA check() in thread
    monitor_thread = threading.Thread(target=checks, daemon=True)
    monitor_thread.start()

    # Socket UDP pentru agent + Pornire Agent
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.bind((AGENT_IP, AGENT_PORT)) #leaga socket-ul de portul pe care agentul primeste cereri
        print(f"[AGENT] UDP pornit pe {AGENT_IP}:{AGENT_PORT} se pot trimtie comenzi: GET / GETNEXT / SET")

        while True:
            data, client_address = udp_socket.recvfrom(4096) #cereri primite de la manager
            try:
                request_text = data.decode(ENCODING, errors="ignore").strip()
                print(f"[RECV {client_address}] {request_text}")

                response_bytes = process_request(request_text) #proceseaza cererea primita

            except Exception as e:
                response_bytes = ber_code_octet(f"ERROR {e}".encode(ENCODING))

            udp_socket.sendto(response_bytes, client_address) #trimite raspunsul catre Manager
            print(f"[SEND {client_address}] ({len(response_bytes)} biti codificati BER)")


if __name__ == "__main__":
    start_agent()