"""
Implementare de baza a protocolului SNMPv1 - PDU-uri si mesaje.
Referinte:
[1] RFC 1157 - Simple Network Management Protocol (SNMP)
    https://datatracker.ietf.org/doc/html/rfc1157

[2] ITU-T X.690 - ASN.1 encoding rules (BER/DER)
    https://www.itu.int/rec/T-REC-X.690/en

[3] A Layman's Guide to a Subset of ASN.1, BER, and DER
    https://luca.ntop.org/Teaching/Appunti/asn1.html

"""

from ber import (
    ber_code_integer, ber_decode_integer,
    ber_code_octet, ber_decode_octet,
    ber_code_oid, ber_decode_oid,
    ber_code_sequence, ber_decode_sequence,
    ber_code_null, ber_decode_null,
)

# ============================================================================
# CONSTANTE SNMP (RFC 1157, Section 4)
# ============================================================================

# SNMP version (RFC 1157, Section 4.1)
SNMP_VERSION_1 = 0

# PDU types - Context-specific constructed tags (RFC 1157, Section 4.1.1)
PDU_GET_REQUEST = 0xA0  # [0] IMPLICIT - citeste valori
PDU_GET_NEXT_REQUEST = 0xA1  # [1] IMPLICIT - parcurge MIB-ul
PDU_GET_RESPONSE = 0xA2  # [2] IMPLICIT - raspuns de la agent
PDU_SET_REQUEST = 0xA3  # [3] IMPLICIT - modifica valori
PDU_TRAP = 0xA4  # [4] IMPLICIT - notificare asincrona

# Error status codes (RFC 1157, Section 4.1.3)
ERROR_NO_ERROR = 0  # Operatie reusita
ERROR_TOO_BIG = 1  # Raspunsul ar depasi limita de transport
ERROR_NO_SUCH_NAME = 2  # OID inexistent sau inaccesibil
ERROR_BAD_VALUE = 3  # Valoare invalida in SetRequest
ERROR_READ_ONLY = 4  # incercare de modificare a unui obiect read-only
ERROR_GEN_ERR = 5  # Eroare generala

# Generic trap types (RFC 1157, Section 4.1.6)
TRAP_COLD_START = 0  # Agent reinitializat (configuratie resetata)
TRAP_WARM_START = 1  # Agent reinitializat (configuratie pastrata)
TRAP_LINK_DOWN = 2  # Interfata de comunicatie cazuta
TRAP_LINK_UP = 3  # Interfata de comunicatie activata
TRAP_AUTH_FAILURE = 4  # Autentificare esuata (community string gresit)
TRAP_EGP_NEIGHBOR_LOSS = 5  # Pierdere vecin EGP
TRAP_ENTERPRISE_SPECIFIC = 6  # Trap specific aplicatiei (custom)


# ============================================================================
# FUNCTII AUXILIARE PENTRU LUNGIME BER (ITU-T X.690, Section 8.1.3)
# ============================================================================

def encode_length(length):
    """
    Codeaza lungimea in format BER (Basic Encoding Rules).

    Conform ITU-T X.690, Section 8.1.3:
    - Forma scurta: 0-127 → un singur octet
    - Forma lunga: ≥128 → primul octet = 0x80 | nr_octeti_lungime

    Referinta: https://www.itu.int/rec/T-REC-X.690/en (Section 8.1.3)
    """
    if length < 128:
        return bytes([length])
    else:
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(length_bytes)]) + length_bytes


def decode_length(data, offset):
    """
    Decodeaza lungimea din format BER.

    Referinta: ITU-T X.690, Section 8.1.3
    """
    if offset >= len(data):
        raise ValueError("Date insuficiente pentru decodare lungime")

    first_byte = data[offset]
    offset += 1

    if first_byte < 128:
        return first_byte, offset
    elif first_byte == 0x80:
        raise ValueError("Forma indefinita de lungime nu este suportata in SNMP")
    else:
        num_bytes = first_byte & 0x7F
        if offset + num_bytes > len(data):
            raise ValueError("Date insuficiente pentru lungime in forma lunga")
        length_bytes = data[offset:offset + num_bytes]
        length = int.from_bytes(length_bytes, 'big')
        return length, offset + num_bytes


# ============================================================================
# CLASE DE DATE (RFC 1157, Section 4.1)
# ============================================================================

class VarBind:
    """
    Reprezinta o pereche (OID, valoare) - Variable Binding.

    Conform RFC 1157, Section 4.1.2:
    VarBind ::= SEQUENCE {
        name  ObjectName,
        value ObjectSyntax
    }
    """

    def __init__(self, oid, value=None, value_type=ber_code_null):
        if isinstance(oid, (tuple, list)):
            self.oid = ".".join(map(str, oid))
        else:
            self.oid = str(oid)

        self.value = value
        self.value_type = value_type

    def __repr__(self):
        return f"VarBind(oid={self.oid}, value={self.value}, type={hex(self.value_type)})"

    def __eq__(self, other):
        if not isinstance(other, VarBind):
            return False
        return (self.oid == other.oid and
                self.value == other.value and
                self.value_type == other.value_type)