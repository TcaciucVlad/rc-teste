# Etapa 1 — Implementare SNMPv1: documentare si proiectare


## 1) Scurta introducere
SNMP (Simple Network Management Protocol) este protocolul clasic prin care un **manager** interogheaza si controleaza **agenti** rulati pe dispozitive/hosturi pentru a citi sau modifica obiecte dintr-o baza denumita **MIB** (Management Information Base). in varianta v1, mesajele merg de regula peste **UDP 161** (cereri/raspunsuri) si **UDP 162** (trap-uri) si folosesc o autentificare simpla pe baza de **community string** (ex. „public”, „private”).

Aplicatia noastra: o demonstratie cu **doi agenti** care monitorizeaza cel putin 5 resurse locale si un **manager GUI/CLI** care interogheaza, seteaza praguri, comuta unitati de masura si primeste trap-uri la depasiri.

---

## 2) Ce ne ajuta la realizarea proiectului
- **MIB-II** pentru obiecte standard (uptime, interfete, IP, etc.) si un sub-arbore propriu pentru resursele custom (CPU, memorie, temperaturi, disc, procese).
- **SMI (ASN.1 + BER)**: structura OID-urilor si codarea campurilor.
- **UDP sockets** in Python: un singur `socket` pentru 161 (agent) si unul pentru 162 (manager) + multiplexare non-blocking.
- **Threading/timers** pentru actualizari periodice si expediere trap-uri.
- **Structura clean de cod**: module separate pentru codare/decodare BER, PDU-uri, MIB, agenti, manager, UI/CLI.

---

## 3) Elemente de implementat (descriere detaliata)

### 3.1 Arborele MIB
Vom folosi un PEN (Private Enterprise Number) fictiv pentru proiect: `1.3.6.1.4.1.99999` si organizam asa:
```

iso(1).org(3).dod(6).internet(1).private(4).enterprises(1).ourLab(99999)
├─ system(1)
├─ resources(2)
│    ├─ cpu(1)          → 1.3.6.1.4.1.99999.2.1.0    INTEGER (0..100) %
│    ├─ memoryUsed(2)   → 1.3.6.1.4.1.99999.2.2.0    INTEGER (MiB)
│    ├─ diskUsed(3)     → 1.3.6.1.4.1.99999.2.3.0    INTEGER (MiB)
│    ├─ tempValue(4)    → 1.3.6.1.4.1.99999.2.4.0    INTEGER (unit-scaled)
│    ├─ tempUnit(5)     → 1.3.6.1.4.1.99999.2.5.0    INTEGER {C(0),F(1),K(2)}
│    └─ procCount(6)    → 1.3.6.1.4.1.99999.2.6.0    INTEGER
└─ thresholds(3)
├─ cpuMax(1)       → 1.3.6.1.4.1.99999.3.1.0    INTEGER %
├─ memMax(2)       → 1.3.6.1.4.1.99999.3.2.0    INTEGER MiB
└─ tempMax(3)      → 1.3.6.1.4.1.99999.3.3.0    INTEGER unit-scaled

```
Nota: temperaturile se raporteaza in unitatea selectata prin `tempUnit`.

### 3.2 Tipuri de PDU implementate
- **GetRequest**: citeste unul sau mai multe OID-uri.
- **GetNextRequest**: permite parcurgerea secventiala a MIB-ului.
- **SetRequest**: seteaza un obiect (ex. `tempUnit`, praguri).
- **GetResponse**: raspunsul agentului (valori sau erori).
- **Trap**: notificare asincrona de la agent la manager (ex. depasire prag).

### 3.3 Codare/decodare ASN.1 BER
Implementam un modul `ber.py` cu urmatoarele primitive: INTEGER, OCTET STRING, NULL, OID, SEQUENCE. Functii: `encode_integer`, `encode_octets`, `encode_oid`, `encode_sequence`, respectiv perechile de decodare. Peste ele, `pdu.py` construieste structurile SNMP v1.

### 3.4 Agentul SNMP (socket UDP 161)
Responsabilitati:
- mentine tabelul MIB in-memory; actualizeaza resursele periodic;
- raspunde la Get/GetNext/Set;
- verifica pragurile; emite Trap catre managerul/managerii configurati (UDP 162).

Resurse pe care le monitorizam (minim 5):
- **CPU load** (%)
- **Memorie utilizata** (MiB)
- **Spatiu pe disc utilizat** (MiB)
- **Temperatura** (in C/F/K, control prin `tempUnit`)
- **Numar procese active**

Sursele valorilor pot fi implementate cross-platform:
- Python: `os`, `subprocess` catre comenzi locale (ex. `wmic`/`typeperf` pe Windows, `/proc` sau `ps`, `free`, `df` pe Linux).

### 3.5 Managerul SNMP (socket UDP 162 pentru trap-uri)
Functionalitati minime:
- inregistrare a cel putin **doi agenti** (IP:port);
- butoane pentru **Actualizare manuala** + **Auto-refresh (interval configurabil)**;
- lista/tabel cu valorile MIB curente;
- controale `Set` pentru: `tempUnit`, `cpuMax`, `memMax`, `tempMax`;
- panou de **notificari Trap** (timestamp, agent, OID, valoare, text);
- export JSON/CSV al citirilor.

### 3.6 Flux trap si praguri
Exemplu: daca `cpu > cpuMax` timp de N secunde, agentul emite un Trap `enterpriseSpecific` cu OID de eveniment, include `cpu` si pragul. Managerul afiseaza un toast/banner + logheaza evenimentul.

---

## 4) Structura mesajelor SNMPv1 (Corectat)

### 4.1 Structura generala a mesajului
Orice mesaj SNMPv1 este o secventa (`SEQUENCE`) care contine trei elemente:
```

+---------------------------+
| version (INTEGER: 0)      |
+---------------------------+
| community (OCTET STRING)  |
+---------------------------+
| PDU (Get/GetNext/Set/     |
|      GetResponse/Trap)    |
+---------------------------+

```

### 4.2 Structura PDU-urilor operationale (Get/GetNext/Set/GetResponse)
PDU-urile de tip `GetRequest` (tip 0), `GetNextRequest` (tip 1), `GetResponse` (tip 2) si `SetRequest` (tip 3) impartasesc o structura comuna:
```

PDU (tip 0, 1, 2, sau 3)
├─ request-id (INTEGER)      ; ID unic pentru a mapa cererea de raspuns
├─ error-status (INTEGER)    ; 0 = noError, 1 = tooBig, 2 = noSuchName, etc.
├─ error-index (INTEGER)     ; Indexul (din VarBindList) care a cauzat eroarea
└─ variable-bindings (SEQUENCE OF VarBind)

```

### 4.2.1 VarBind si VarBindList

### Ce este un VarBind?

Un **VarBind** (*Variable Binding*) este o pereche formata dintr-un **OID** (*Object Identifier*) si o **valoare** asociata acelui obiect din MIB.  
Pe scurt:  
> **VarBind = (numele variabilei, valoarea variabilei)**

---

### Exemplu clar

Daca vrei sa citesti incarcarea procesorului, OID-ul pentru CPU ar putea fi `1.3.6.1.4.1.99999.2.1.0`, iar valoarea citita este, sa zicem, `42 (%)`.

Un **VarBind** va arata astfel:
```python
{ name = 1.3.6.1.4.1.99999.2.1.0, value = 42 }
```

- La trimiterea unui request (**GetRequest**), VarBind-ul contine **OID** si valoare **NULL** (nu stim inca valoarea).
- intr-un raspuns (**GetResponse**), agentul completeaza valoarea corespunzatoare OID-ului.

---

### Ce este un VarBindList?

Un **VarBindList** este o lista (sau secventa) de astfel de perechi **OID + valoare**, adica mai multe VarBind-uri grupate intr-un singur mesaj SNMP.​

Exemplu:
```python
VarBindList = [
    { OID: 1.3.6.1.4.1.99999.2.1.0, value: 42 },
    { OID: 1.3.6.1.4.1.99999.2.2.0, value: 2048 },
    { OID: 1.3.6.1.4.1.99999.2.3.0, value: 150123 }
]
```

Astfel, poti cere sau returna mai multe valori dintr-o data — de exemplu **CPU**, **memorie**, **temperatura** etc.

---

### Pe scurt

Un **VarBind** este „cutia” in care asociezi obiectul gestionat (prin OID) cu valoarea sa (care poate fi NULL la cerere).  

Fiecare **PDU** (cerere sau raspuns SNMP) poate avea unul sau mai multe VarBind-uri grupate — adica un **VarBindList**.

SNMP foloseste VarBind ca **unitate fundamentala** pentru a transporta informatie despre resurse.​

---

### Exemple uzuale

- **GetRequest**: `VarBindList` cu valori **NULL** → ("Cauta-mi valorile pentru OID-urile astea").  
- **GetResponse**: `VarBindList` cu aceleasi OID-uri, dar valori completate → ("Iata valorile pe care le-ai cerut").  
- **Trap**: `VarBindList` cu una sau mai multe valori implicate in evenimentul respectiv.

---

### 4.3 Structura PDU-ului Trap (v1)
PDU-ul de tip `Trap` (tip 4) are o **structura complet diferita** de celelalte. Nu are `request-id`, `error-status` sau `error-index`.
```

PDU (tip 4)
├─ enterprise (OBJECT IDENTIFIER) ; OID-ul "parintelui" (ex. 1.3.6.1.4.1.99999)
├─ agent-addr (NetworkAddress)  ; Adresa IP a agentului
├─ generic-trap (INTEGER)       ; 0-5 (standard), 6 (enterpriseSpecific)
├─ specific-trap (INTEGER)      ; Cod custom (ex. 1 pt. cpuOver, 2 pt. tempOver)
├─ time-stamp (TimeTicks)       ; Timpul scurs de la initializarea agentului
└─ variable-bindings (SEQUENCE OF VarBind) ; Date suplimentare (ex. OID-ul si valoarea)

```
Trap-urile sunt asincrone (agent → manager) si nu primesc raspuns.

---

## 5) Interactiuni intre entitati (diagrame de secventa)

### 5.1 Read (GetRequest)
```

Manager                              Agent
   |   GetRequest {oid=tempValue}      |
   |---------------------------------->|
   |                                   |
   |   GetResponse {tempValue=299}     |
   |<----------------------------------|

```

### 5.2 Walk (GetNextRequest)
```

Manager                              Agent
   |   GetNextRequest {oid=resources}   |
   |----------------------------------->|
   |   GetResponse {cpu=23}             |
   |<-----------------------------------|
   |   GetNextRequest {oid=cpu}         |
   |----------------------------------->|
   |   GetResponse {memoryUsed=2048}    |
   |<-----------------------------------|
   |   ...                              |

```

### 5.3 Set prag si schimbare unitate
```

Manager                              Agent
   |   SetRequest {cpuMax=85}           |
   |----------------------------------->|
   |   GetResponse {noError}            |
   |<-----------------------------------|
   |   SetRequest {tempUnit=F}          |
   |----------------------------------->|
   |   GetResponse {noError}            |
   |<-----------------------------------|

```

### 5.4 Trap la depasire prag
```

Agent detecteaza: cpu=92 > cpuMax=85
Agent ---------------------> Manager : Trap {event=cpuOver, value=92}
Manager: afiseaza notificare + log

```

---

## 6) Structura aplicatiei

```

snmp-protocol/
ber.py          # Implementeaza codarea/decodarea ASN.1 BER (INTEGER, OCTET STRING, OID, SEQUENCE, NULL)

pdu.py          # Implementeaza logica de constructie si parsare pentru PDU-uri (Get/Next/Set/Response + Trap)
                # Include si functiile de serializare/deserializare a mesajului complet (version + community + PDU)

agent/
agent.py        # Bucla principala (socket UDP 161), parsare CLI logica de procesare Get/GetNext/Set (folosind MIB)
                # Logica de verificare praguri si trimitere Trap

sensors.py      # Colectarea datelor (CPU, mem, disc, temp)

mib.py          # Definitia MIB-ului (un dictionar) si logica de mapare OID -> functie (read/write), inclusiv GetNext

manager/
manager.py      # Trimite cereri prin UDP 161
                # Primteste alerte Trap prin UDP 162
                # Gestioneaza lista agentilor monitorizati, actualizarea periodica a valorilor preluate din MIB
                # si functionalitatile de export ale datelor colectate (CSV / JSON)


ui.py           # Interfata cu utilizatorul (Tkinter)
                # Apeleaza functii din manager.py si afiseaza datele

README.md

```

---

## 7) Design UI (figuri/mock-up)

### 7.1 Manager UI (desktop minimal)
```

┌───────────────────────────────────────────────────────────────┐
│ Agents: [192.168.1.10] [192.168.1.11]   Community: [ public ] │
│ Refresh: [ Manual ]  Auto-refresh [ 5s ▼ ]  [Start] [Stop]    │
├───────────────┬───────────┬───────────┬──────────┬────────────┤
│ OID           │ Valoare   │ Unitate   │ Agent    │ Timestamp  │
├───────────────┼───────────┼───────────┼──────────┼────────────┤
│ cpu           │ 23        │ %         │ .10      │ 12:03:01   │
│ memoryUsed    │ 2048      │ MiB       │ .10      │ 12:03:01   │
│ diskUsed      │ 150000    │ MiB       │ .10      │ 12:03:01   │
│ tempValue     │ 299       │ K         │ .10      │ 12:03:01   │
│ procCount     │ 178       │           │ .10      │ 12:03:01   │
└───────────────┴───────────┴───────────┴──────────┴────────────┘
[Set tempUnit: (C/F/K)] [Set cpuMax: 85] [Set memMax: 6000] [Set tempMax: 330]

Trap log: 192.168.1.10 cpuOver value=92 threshold=85

```

### 7.2 Agent CLI 
```

$ python agent.py --listen 0.0.0.0:161 --manager 192.168.1.100:162  
--community public --cpuMax 85 --tempUnit C
[agent] MIB ready; polling sensors/2s; traps→192.168.1.100:162

```

---

## 8) Cazuri de eroare si coduri de raspuns
(Mapate la campul `error-status` din PDU-urile operationale)
- `tooBig`: raspunsul ar depasi MTU... trimitem eroare.
- `noSuchName`: OID inexistent sau lipsa acces.
- `badValue` / `readOnly`: incercare de `Set` pe obiect read-only sau valoare invalida.
- `genErr`: alta eroare interna.

---

## 9) Plan de testare
- **Unitare**: `test_ber.py` pentru codari BER, `test_pdu.py` pentru PDU.
- **Functionale**: secvente Get/Next/Set intre manager si 2 agenti (local + VM).
- **Trap-uri**: generare artificiala (fortam depasiri) si verificam log/GUI.
- **Robustete**: community gresit, OID invalid, agent oprit, timeout, UDP re-try.

---

## 10) Anexa: mapping OID ↔ senzori (exemplu)
| OID                                       | Acces | Tip     | Exemplu     |
|-------------------------------------------|-------|---------|-------------|
| 1.3.6.1.4.1.99999.2.1.0 cpu               | RO    | INTEGER | 37          |
| 1.3.6.1.4.1.99999.2.2.0 memoryUsed        | RO    | INTEGER | 3124        |
| 1.3.6.1.4.1.99999.2.3.0 diskUsed          | RO    | INTEGER | 155000      |
| 1.3.6.1.4.1.99999.2.4.0 tempValue         | RO    | INTEGER | 299         |
| 1.3.6.1.4.1.99999.2.5.0 tempUnit          | RW    | INTEGER | C=0/F=1/K=2 |
| 1.3.6.1.4.1.99999.2.6.0 procCount         | RO    | INTEGER | 182         |
| 1.3.6.1.4.1.99999.3.1.0 cpuMax            | RW    | INTEGER | 85          |
| 1.3.6.1.4.1.99999.3.2.0 memMax            | RW    | INTEGER | 6000        |
| 1.3.6.1.4.1.99999.3.3.0 tempMax           | RW    | INTEGER | 330         |

---

## 11) Bibliografie minimala
1) https://datatracker.ietf.org/doc/html/rfc1157
2) https://luca.ntop.org/Teaching/Appunti/asn1.html
3) https://en.wikipedia.org/wiki/X.690
4) https://www.zytrax.com/tech/survival/asn1.html
5) https://www.dpstele.com/snmp/basics.php
