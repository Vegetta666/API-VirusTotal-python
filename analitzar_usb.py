import usb.core
import sqlite3
import os
import usb.util
import platform
from asyncio import events
from colorsys import rgb_to_yiq
from contextlib import nullcontext
from nturl2path import url2pathname
from turtle import goto
from urllib import response
import json
import requests
import os
import datetime
import time
import shutil

#api_key = "2b6790295ef293069d1767bfa2ab8af0a5a6564e67479237b811fed81e3492fb"
api_key = "ab83372fbf3fe9435ac86031d858f60957c388df58d93ac1794943265788cc92"

ruta_quarantena = "C:/Users/cf2021166/Documents/visual studio code/"

# Conectarse a la base de datos (si no existe se creará)
conn = sqlite3.connect('USB_fitxers.sql')

conn.execute('''CREATE TABLE IF NOT EXISTS archivos
                (ID TEXT NOT NULL,
                Hash TEXT NOT NULL,
                serial_usb TEXT NOT NULL,
                nombre TEXT NOT NULL,
                ruta_archiu TEXT,
                Malware TEXT,
                Report TEXT
                );''')

def llegir_fixers():
    #llista_archius = os.listdir(ruta_fixers)
    #os.path.join(root, name)--> la ruta dels fixers
    SerialUSB  = SerialNumeber()
    usb_ruta = usb_ruta()
    for root, dirs, files in os.walk(usb_ruta, topdown=False):
        for name in files:
            hash = hash(name)
            BaseDades(name,SerialUSB)
            Analitzar_fitxers(files,root,name,hash,usb_ruta)
            BaseDades_ruta((usb_ruta + name),hash)

            
def hash(name):
    import hashlib
    # Abre el archivo en modo lectura binaria
    with open(name, 'rb') as archivo:
        # Crea un objeto hashlib para el algoritmo de hash que desees utilizar
        objeto_hash = hashlib.sha256()
        
        # Lee el archivo en bloques y actualiza el objeto hashlib con cada bloque
        while bloque := archivo.read(4096):
            objeto_hash.update(bloque)
        
        # Obtiene el hash final en formato hexadecimal
        hash_archivo = objeto_hash.hexdigest()

    return hash_archivo

def usb_ruta():
    if platform.system() == 'Windows':
        import win32gui
        import win32api
        import win32con
        # Ejecutar la función detectar_usb para obtener una lista de dispositivos conectados
        dispositivos_conectados = detectar_usb()
        print("Dispositivos conectados: ", dispositivos_conectados)
        # Obtener la ruta del primer dispositivo de la lista (puedes modificar esto para que sea el que necesites)
        ruta_usb = obtener_ruta_usb(dispositivos_conectados[0])
        print("Ruta del USB: ", ruta_usb)
        return ruta_usb
    else:
        import pyudev
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by('block')
        for device in iter(monitor.poll, None):
            if device.action == 'add' and 'usb' in device.sys_path:
                print('Dispositivo USB conectado:', device.sys_path)
                ruta_usb  = device.sys_path
        return ruta_usb


def SerialNumeber():
    if platform.system() == 'Windows':
        import win32api
        import win32file
        import win32con
        # Buscar dispositivos USB conectados
        drives = win32api.GetLogicalDriveStrings()
        drives = drives.split('\000')[:-1]
        for drive in drives:
            drive_type = win32file.GetDriveType(drive)
            # Verificar si el dispositivo es un almacenamiento de masa USB
            if drive_type == win32file.DRIVE_REMOVABLE:
                # Obtener el número de serie del dispositivo
                #volume_name = win32api.GetVolumeInformation(drive)[1]
                #print(volume_name)
                file_system_flags = win32api.GetVolumeInformation(drive)[4]
                if file_system_flags & win32con.FILE_READ_ONLY_VOLUME == 0:
                    serial_number = win32file.GetDiskFreeSpace(drive)[0]
                    print(f"El número de serie del dispositivo USB es: {serial_number}")
                    return serial_number
    else:
        import pyudev
        # Buscar dispositivos USB conectados
        context = pyudev.Context()
        for device in context.list_devices(subsystem='usb'):
            # Verificar si el dispositivo es un almacenamiento de masa USB
            if device.get('ID_USB_INTERFACE_NUM') == '08' and device.get('ID_VENDOR_ID') is not None and device.get('ID_MODEL_ID') is not None:
                # Obtener el número de serie del dispositivo
                serial_number = device.get('ID_SERIAL_SHORT')
                print(f"El número de serie del dispositivo USB es: {serial_number}")
                return serial_number

def Analitzar_fitxers(files,root,name,hash,usb_ruta):
        if (os.path.getsize(os.path.join(root, name)) >> 20) > 32:          #Veure el temany del fixer si es mes gran de 32MB
            id = obtenir_id_gran(os.path.join(root, name),name)    
            report = analysis_fixer(id)
            BaseDades_report(report,hash)
            malware = mirar_reports(report,name)
            BaseDades_malware(malware,hash)
            BaseDades_id(id,hash)    

        else:                                                               #Mes petit de 32MB
            id = obtenir_id_petit(os.path.join(root, name),name)
            report = analysis_fixer(id)
            BaseDades_report(report,hash)
            malware = mirar_reports(report,name)
            BaseDades_malware(malware,hash)
            BaseDades_id(id,hash)

        print(name)

def BaseDades_hash(name,hash):
    conn.execute("UPDATE archivos SET Hash = " + hash +" WHERE nombre = " + name + ";")

def BaseDades_malware(malware,hash):
    conn.execute("UPDATE archivos SET Report = " + malware +" WHERE Hash = " + hash + ";")

def BaseDades_report(report,hash):
    conn.execute("UPDATE archivos SET Report = " + report +" WHERE Hash = " + hash + ";")

def BaseDades_id(id,hash):
    conn.execute("UPDATE archivos SET ID = " + id +" WHERE Hash = " + hash + ";")

def BaseDades_ruta(usb_ruta,hash):
    conn.execute("UPDATE archivos SET ruta_archiu = " + usb_ruta +" WHERE Hash = " + hash + ";")

def BaseDades(name,SerialNumber):
    # Conectarse a la base de datos (si no existe se creará)
    # Crear tabla para almacenar los nombres de archivo, rutas y números de serie USB
    conn.execute('''CREATE TABLE IF NOT EXISTS archivos
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                ID TEXT NOT NULL,
                Hash TEXT NOT NULL,
                serial_usb TEXT NOT NULL,
                nombre TEXT NOT NULL,
                ruta_archiu TEXT,
                Malware TEXT,
                Report TEXT
                );''')

    #Insertar el nombre del arxiu i el Serial Number del USB
    conn.execute("INSERT INTO archivos (nombre, serial_usb) VALUES (?, ?)", (name,SerialNumber))

    # Guardar los cambios en la base de datos
    conn.commit()
    

def Quarantena_exlosa():
     for root, dirs, files in os.walk(ruta_quarantena, topdown=False):
        for name in files:
            print(name)
        return files

print(Quarantena_exlosa())

def mirar_reports(report,nombre):
    malisius = (str(report).split(sep=',')[6]).split(sep=':')[1]
    suspicius= (str(report).split(sep=',')[2]).split(sep=':')[1]
    
    if int(malisius) > 0 or int(suspicius) > 0:
        archiu_ruta = str(archiu_ruta)
        shutil.copy(archiu_ruta, ruta_quarantena + "quarantena1/" + nombre)
        return ((str(report).split(sep=',')[6]),(str(report).split(sep=',')[2]))

def analysis_fixer(id):                                     #Analisis del ficher 
    i = 0
    while True:
        url = "https://www.virustotal.com/api/v3/analyses/" + id

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        response = requests.get(url, headers=headers)
        date = datetime.datetime.now()
        
        if(response.status_code == 429):
            print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            print("Codigo de error : " + str(response.status_code))

            exit()

        if(response.status_code == 200):
            result = response.json()
            if(result.get("data").get("attributes").get("status") == "completed"):          #IF per comprovar si se ha complatat
                analysis = result.get("data").get("attributes").get("stats")
                return analysis
            elif(i >= 5):
                analysis = result.get("data").get("attributes").get("stats")
                return analysis
            elif result.get("data").get("attributes").get("status") == "queued":  #Else if quan esta en cua o la reposta del analisis es nula

                print("[" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + "Temps comenca el temps de espera")
                i = i + 1
                print("Resposta : " + str(response.status_code))
                print("Status : " + str(result.get("data").get("attributes").get("status")))
                print("Contador : " + str(i))
                print("Maxims intens : " + str(5-i) + "/5")

                time.sleep(60)
                
                print("[" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + "Temps de espera Finalitzat")
                False
            else: 
                break
        else:
            print("ERROR :!")
            print("Codigo de error : " + str(response.status_code))

    return analysis

def obtenir_id_gran(fitxer,name):                                                   #Pujar archius mes grans que 32MB
    while True:
        files = {"file": open(fitxer, "rb")}
        url = "https://www.virustotal.com/api/v3/files/upload_url"
        
        headers = {
        "accept": "application/json",
        "x-apikey": api_key
        }

        response = requests.get(url, headers=headers)
        if(response.status_code == 429):
            print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            print("Codigo de error : " + str(response.status_code))

            exit()
        
        if response.status_code == 200:
            result = response.json()
            url_upload = result.get("data")
            True
        else:
            print ("No s'ha pogut obtenir la URL :(")
            print ("ERROR al pujar el archiu :!")
            print ("Status code: " + str(response.status_code))
            False
        
        #Obtenim una id
        response = requests.post(url_upload, files=files, headers=headers)
        if(response.status_code == 429):
            print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            print("Codigo de error : " + str(response.status_code))
            exit()
        
        if response.status_code == 200:
            result = response.json()
            id = result.get("data").get("id")
            
            return id

        else:
            print("No s'ha pogut obtenir el ID :(")
            print ("Status code: " + str(response.status_code))
            False



def obtenir_id_petit(fitxer,name):                                           #Pujar achius mes petits que 32MB
    while True:
        files = {"file": open(fitxer, "rb")}
        
        url = "https://www.virustotal.com/api/v3/files"

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        response = requests.post(url, files=files, headers=headers)
        if(response.status_code == 429):
            print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            exit()
        
        if response.status_code == 200:
            result = response.json()
            id = result.get("data").get("id")
            return id

        else:
            print("No s'ha pogut obtenir el ID :(")
            print ("Status code: " + str(response.status_code))
            False


def execfile(filepath, globals=None, locals=None):
    if globals is None:
        globals = {}
    globals.update({
        "__file__": filepath,
        "__name__": "__main__",
    })
    with open(filepath, 'rb') as file:
        exec(compile(file.read(), filepath, 'exec'), globals, locals)
#execfile("api_analitzar_fitxers.py")


# Define una función para detectar dispositivos conectados
def detectar_usb():
    import win32api
    import win32file
    # Obtener información sobre los dispositivos conectados
    drive_list = []
    drives = win32api.GetLogicalDriveStrings()
    drives = drives.split('\000')[:-1]
    
    for drive in drives:
        drive_type = win32file.GetDriveType(drive)
        if drive_type == win32file.DRIVE_REMOVABLE:
            drive_list.append(drive)

    return drive_list

# Define una función para obtener la ruta de un dispositivo específico
def obtener_ruta_usb(usb):
    import win32api
    import win32file
    # Obtener la letra de unidad asignada al dispositivo
    path = None
    drives = win32api.GetLogicalDriveStrings()
    drives = drives.split('\000')[:-1]
    
    for drive in drives:
        drive_type = win32file.GetDriveType(drive)
        if drive_type == win32file.DRIVE_REMOVABLE:
            if drive == usb:
                path = drive

    return path

#llegir_fixers()


# Cerrar la conexión a la base de datos
conn.close()


