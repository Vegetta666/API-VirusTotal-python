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


ruta_fixers = "C:/Users/cf2021166/Documents/analitzar/"

#api_key = "2b6790295ef293069d1767bfa2ab8af0a5a6564e67479237b811fed81e3492fb"
api_key = "ab83372fbf3fe9435ac86031d858f60957c388df58d93ac1794943265788cc92"


def llegir_fixers(ruta_fixers):
    #llista_archius = os.listdir(ruta_fixers)
    #os.path.join(root, name)--> la ruta dels fixers
    
    for root, dirs, files in os.walk(ruta_fixers, topdown=False):
        for name in files:
            crear_log_programa("\n")
            crear_log_programa("(=================================================================)")
            crear_log_programa(str("Archiu : " + name + " Escanajat Correctament"))
            if (os.path.getsize(os.path.join(root, name)) >> 20) > 32:          #Veure el temany del fixer si es mes gran de 32MB
                crear_log_programa("Archiu GRAN detectat correctament --> " + name)
                id = obtenir_id_gran(os.path.join(root, name),name)                  
            else:                                                               #Mes petit de 32MB
                crear_log_programa("Archiu PETIT detectat correctament -->  " + name)
                id = obtenir_id_petit(os.path.join(root, name),name)
            
            crear_log(id,name,os.path.join(root, name))
            crear_log_programa("(=================================================================)")
            print(name)
                


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

            crear_log_programa("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            crear_log_programa("Codigo de error : " + str(response.status_code))
            exit()
        
        if response.status_code == 200:
            result = response.json()
            url_upload = result.get("data")
            crear_log_programa("URL fixer gran obtinguda correctament")
            True
        else:
            print ("No s'ha pogut obtenir la URL :(")
            print ("ERROR al pujar el archiu :!")
            print ("Status code: " + str(response.status_code))

            crear_log_programa ("No s'ha pogut obtenir la URL :(")
            crear_log_programa ("ERROR al pujar el archiu :!")
            crear_log_programa ("Status code: " + str(response.status_code))
            False
        
        #Obtenim una id
        response = requests.post(url_upload, files=files, headers=headers)
        if(response.status_code == 429):
            print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            print("Codigo de error : " + str(response.status_code))
            crear_log_programa("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            crear_log_programa("Codigo de error : " + str(response.status_code))
            exit()
        
        if response.status_code == 200:
            result = response.json()
            id = result.get("data").get("id")
            crear_log_programa("ID del archiu " + name + " obtingut correctament")
            return id

        else:
            print("No s'ha pogut obtenir el ID :(")
            print ("Status code: " + str(response.status_code))
            crear_log_programa("No s'ha pogut obtenir el ID :(" + " del archiu" + name)
            crear_log_programa ("Status code: " + str(response.status_code))
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
            crear_log_programa("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            exit()
        
        if response.status_code == 200:
            result = response.json()
            id = result.get("data").get("id")
            crear_log_programa("ID del archiu " + name + " obtingut correctament")
            return id

        else:
            print("No s'ha pogut obtenir el ID :(")
            print ("Status code: " + str(response.status_code))
            crear_log_programa("No s'ha pogut obtenir el ID :(" + " del archiu" + name)
            crear_log_programa ("Status code: " + str(response.status_code))
            False
    

def crear_log(id,archiu,ruta):                                               #Creem un log amb les id i el nom
    file = open("log_id.txt", "a")
    crear_log_programa("Escriure log ID")
    date = datetime.datetime.now()
    file.write("[" + date.strftime("%d") + ":" + date.strftime("%m") + ":" + date.strftime("%y") + "/" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + id + " >-->-->Ruta>-->--> " + ruta +  " >-->-->Nom_archiu>-->-->  " + str(archiu) + " \n")
    file.close()
    
def crear_log_programa(text):                                               #Creem un log amb les id i el nom
    file = open("log_programa.txt", "a")
    date = datetime.datetime.now()
    file.write("[" + date.strftime("%d") + ":" + date.strftime("%m") + ":" + date.strftime("%y") + "/" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + text + " \n")
    file.close()
    
crear_log_programa("\n")
crear_log_programa("(=================================================================)")
crear_log_programa("Archiu 1 ejecutatse")
crear_log_programa("(=================================================================)")
crear_log_programa("\n")

llegir_fixers()

crear_log_programa("\n")
crear_log_programa("(=================================================================)")
crear_log_programa("Final Archiu 1")
crear_log_programa("(=================================================================)")
crear_log_programa("\n")

#Per executar automaticament el segon script
def execfile(filepath, globals=None, locals=None):
    if globals is None:
        globals = {}
    globals.update({
        "__file__": filepath,
        "__name__": "__main__",
    })
    with open(filepath, 'rb') as file:
        exec(compile(file.read(), filepath, 'exec'), globals, locals)
execfile("api_analitzar_fitxers.py")
