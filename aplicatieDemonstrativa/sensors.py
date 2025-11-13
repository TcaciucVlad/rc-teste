import psutil


def cpu_load_procent():
    return int(psutil.cpu_percent(interval=0.1))

def mem_used_MiB():

    mem = psutil.virtual_memory() #se va intoarce un obiect cu mai multe atribute( .used este cel ce ne intereseaza)
    used_mib = int(mem.used / 1024 / 1024) #se realizeaza conversia din byte in megabyte
    return used_mib

def disk_used_MiB():

    disk = psutil.disk_usage('/') #     / - reprezinta radacina sistemului de fisiere( un fel de director ce contine toate directoarele)
    used_gb = int(disk.used / 1024 / 1024) #se realizeaza conversia din byte in megabyte
    return used_gb


def cpu_temp_c():

    temps = psutil.sensors_temperatures() #se returneaza un dictionar cu temperaturile de pe mai multi senzori

    for name, entries in temps.items():
        if 'coretemp' in name.lower():  # se cauta senzorul "coretemp" unde vom regasi temperatura CPU
            for entry in entries:
                if entry.current is not None: #prima inregistrare pe care o gaseste o returneaza
                    return int(entry.current)

    return 40 #de rezerva, in caz ca nu se poate citi


def proc_counter():

    nr_procese = len(psutil.pids()) #se extrage numarul de procese active
    return int(nr_procese)


