from asyncio import events
from nturl2path import url2pathname
import re
from urllib import response
import json
import requests
import os
import datetime
import shutil
import time


ruta_log = "C:/Users/cf2021166/Documents/visual studio code/"
ruta_analitzar = "C:/Users/cf2021166/Documents/analitzar/"

#api_key = "2b6790295ef293069d1767bfa2ab8af0a5a6564e67479237b811fed81e3492fb"
api_key = "ab83372fbf3fe9435ac86031d858f60957c388df58d93ac1794943265788cc92"




def id_analizer():                                          #Es el bucle que llegeix 
    file = open(ruta_log + "log_id.txt", "r")
    crear_log_programa("Arhiu log_id obert satisfactoriament")
    count = 0
    while True:
            count += 1
        # Get next line from file
            line = file.readline()
            crear_log_programa("\n")
            crear_log_programa("(=================================================================)")
            crear_log_programa("Linea del archiu llegida correctament")
            crear_log_programa("Linea {}: {}".format(count, line.strip()))
        # if line is empty
            # end of file is reached
            if not line:
                crear_log_programa("Archiu log_id llegit correctament")
                break
            #print("Line{}: {}".format(count, line.strip()))
            #id  = line.split(sep=' >-->-->Nom archiu>-->--> ',maxsplit=2)[0]
            

            id  = line.split(sep=' ')[1]
            crear_log_programa("ID separat correctament : " + id)
            archiu_ruta = line.split(sep=' ',)[3]
            crear_log_programa("Ruta dels fixers serparada correctament : " + archiu_ruta)
            nombre = re.sub("\!|\'|\\n","",str(line.split(sep='  ',)[1]))
            crear_log_programa("Nom del archiu separat correctament : " + nombre)
            report = analysis_fixer(id)
            report_ananlisis_fitxer(nombre,report)
            mirar_reports(report,archiu_ruta,id,nombre)
            crear_log_programa("(=================================================================)")

    file.close()
    return id


def mirar_reports(report,archiu_ruta,id,nombre):
    malisius = (str(report).split(sep=',')[6]).split(sep=':')[1]
    suspicius= (str(report).split(sep=',')[2]).split(sep=':')[1]
    crear_log_programa("separar informacio: " + " malicius : " + malisius + " suspicius: " +suspicius)
    
    if int(malisius) > 0 or int(suspicius) > 0:
        log_malware(archiu_ruta,id,(str(report).split(sep=',')[6]),(str(report).split(sep=',')[2]))
        archiu_ruta = str(archiu_ruta)
        shutil.copy(archiu_ruta, ruta_log + "quarantena/" + nombre)
        crear_log_programa("Archiu malicios copiat al directori quarantena :S")

def log_malware(archiu_ruta,id,malisius,suspicius):              #Escriu el report dels archius maliciosos 
    plantilla =  " >-->-->Nom_archiu_ruta>-->--> "
    file = open("log_malware.txt", "a")
    crear_log_programa("Escriure log malware")
    date = datetime.datetime.now()
    file.write("[" + date.strftime("%d") + ":" + date.strftime("%m") + ":" + date.strftime("%y") + "/" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + "ID--> "+ str(id) + " Report --> " + malisius + suspicius + str(plantilla) + str(archiu_ruta) + "\n")
    #print(" Report --> " + malisius + suspicius + str(plantilla) + str(archiu_ruta))
    file.close()
    

def report_ananlisis_fitxer(nombre,report):                 #Escriure totes els reports dels archius
    plantilla =  " >-->-->Nom_archiu>-->--> "
    file = open("log_report.txt", "a")
    date = datetime.datetime.now()
    crear_log_programa("Escriure log report")
    file.write("[" + date.strftime("%d") + ":" + date.strftime("%m") + ":" + date.strftime("%y") + "/" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + str(report) + str(plantilla) + str(nombre) + "\n")
    #print(str(report) + str(plantilla) + str(nombre))
    file.close()


def analysis_fixer(id):                                     #Analisis del ficher 
    i = 0
    while True:
        url = "https://www.virustotal.com/api/v3/analyses/" + id

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        response = requests.get(url, headers=headers)
        crear_log_programa("Peticio rebuda correctament :)")
        date = datetime.datetime.now()
        
        if(response.status_code == 429):
            print("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            print("Codigo de error : " + str(response.status_code))

            crear_log_programa("Error de cuota excedida :! o Error de demasiadas solicitudes controlate ;)")
            crear_log_programa("Codigo de error : " + str(response.status_code))
            exit()

        if(response.status_code == 200):
            result = response.json()
            if(result.get("data").get("attributes").get("status") == "completed"):          #IF per comprovar si se ha complatat
                crear_log_programa("Analisis extret correctament")
                analysis = result.get("data").get("attributes").get("stats")
                return analysis
            elif(i >= 5):
                crear_log_programa("Intens de pujar el archiu maximes 5")
                analysis = result.get("data").get("attributes").get("stats")
                return analysis
            elif result.get("data").get("attributes").get("status") == "queued":  #Else if quan esta en cua o la reposta del analisis es nula

                print("[" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + "Temps comenca el temps de espera")
                i = i + 1
                print("Resposta : " + str(response.status_code))
                print("Status : " + str(result.get("data").get("attributes").get("status")))
                print("Contador : " + str(i))
                print("Maxims intens : " + str(5-i) + "/5")

                crear_log_programa("Archiu esta an cua ;(")
                crear_log_programa("Resposta : " + str(response.status_code))
                crear_log_programa("Status : " + str(result.get("data").get("attributes").get("status")))
                crear_log_programa("Contador : " + str(i))
                crear_log_programa("Maxims intens : " + str(5-i) + "/5")
                crear_log_programa("[" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + "Temps comenca el temps de espera")

                time.sleep(60)
                
                print("[" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + "Temps de espera Finalitzat")
                crear_log_programa("[" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + "Temps de espera Finalitzat")
                False
            else: 
                break
        else:
            print("ERROR :!")
            print("Codigo de error : " + str(response.status_code))

    return analysis


def crear_log_programa(text):                                               #Creem un log amb les id i el nom
    file = open("log_programa.txt", "a")
    date = datetime.datetime.now()
    file.write("[" + date.strftime("%d") + ":" + date.strftime("%m") + ":" + date.strftime("%y") + "/" + date.strftime("%X") + ":" + date.strftime("%f") + "] " + text + " \n")
    file.close()

crear_log_programa("\n")
crear_log_programa("(=================================================================)")
crear_log_programa("Iniciat el Segon Script")
crear_log_programa("(=================================================================)")
crear_log_programa("\n")


id_analizer()

crear_log_programa("\n")
crear_log_programa("(=================================================================)")
crear_log_programa("Final del Segon Script")
crear_log_programa("Srcipt Finalitzat Correctament ;)")
crear_log_programa("(=================================================================)")
crear_log_programa("\n")





