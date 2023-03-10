import os
import sys
import time
import json
import requests
import argparse
import hashlib



LLAVE_API = "2b6790295ef293069d1767bfa2ab8af0a5a6564e67479237b811fed81e3492fb"


URL_API = "https://www.virustotal.com/api/v3/"

class VTScan:
    def __init__(self):
        self.headers = {
            "x-apikey" : LLAVE_API,
            "User-Agent" : "PRJ ASIX",
            "Accept-Encoding" : "gzip, deflate",
        }

    def upload(self, malware_path):
        print ("Subir archivo: " + malware_path + "...")
        self.malware_path = malware_path
        upload_url = URL_API + "files"
        files = {"file" : (
            os.path.basename(malware_path),
            open(os.path.abspath(malware_path), "rb"))
        }
        print ("Subir a " + upload_url)
        res = requests.post(upload_url, headers = self.headers, files = files)
        if res.status_code == 200:
            result = res.json()
            self.file_id = result.get("data").get("id")
            print (self.file_id)
            print ("Archivo subido correctamente: OK")
        else:
            print ("Fallo al subir el archivo :(")
            print ("status code: " + str(res.status_code))
            sys.exit()

    def analyse(self):
        print ("Obtener informacion de los resultados del analisis...")
        analysis_url = URL_API + "analyses/" + self.file_id
        res = requests.get(analysis_url, headers = self.headers)
        if res.status_code == 200:
            result = res.json()
            status = result.get("data").get("attributes").get("status")
            if status == "completed":
                stats = result.get("data").get("attributes").get("stats")
                results = result.get("data").get("attributes").get("results")
                print ("malicious: " + str(stats.get("malicious")))
                print ("undetected : " + str(stats.get("undetected")))
                print ()
                for k in results:
                    if results[k].get("category") == "malicious":
                        print ("==================================================")
                        print (results[k].get("engine_name"))
                        print ("version : " + results[k].get("engine_version"))
                        print ("category : " + results[k].get("category"))
                        print ("method : " + results[k].get("method"))
                        print ("update : " + results[k].get("engine_update"))
                        print ("==================================================")
                        print ()
                    elif results[k].get("category") == "undetected":
                        print ("==================================================")
                        print (results[k].get("engine_name"))
                        print ("version : " + results[k].get("engine_version"))
                        print ("category : " + results[k].get("category"))
                        print ("method : " + results[k].get("method"))
                        print ("update : " + results[k].get("engine_update"))
                        print ("==================================================")
                        print ()
                print ("Analisis satisfactorio: OK")
                sys.exit()
            elif status == "queued":
                print ("status: en cola...")
                with open(os.path.abspath(self.malware_path), "rb") as malware_path:
                    b = f.read()
                    hashsum = hashlib.sha256(b).hexdigest()
                    self.info(hashsum)
        else:
            print ("Fallo al obtener los resultados del analisis :(")
            print ("status code: " + str(res.status_code))
            sys.exit()

    def run(self, malware_path):
        self.upload(malware_path)
        self.analyse()

    def info(self, file_hash):
        print ("Obtener informacion del archivo mediante ID: " + file_hash)
        info_url = URL_API + "files/" + file_hash
        res = requests.get(info_url, headers = self.headers)
        if res.status_code == 200:
            result = res.json()
            if result.get("data").get("attributes").get("last_analysis_results"):
                stats = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                print ("malicious: " + str(stats.get("malicious")))
                print ("undetected : " + str(stats.get("undetected")))
                print ()
                for k in results:
                    if results[k].get("category") == "malicious":
                        print ("==================================================")
                        print (results[k].get("engine_name"))
                        print ("version : " + results[k].get("engine_version"))
                        print ("category : " + results[k].get("category"))
                        print ("method : " + results[k].get("method"))
                        print ("update : " + results[k].get("engine_update"))
                        print ("==================================================")
                        print ()
                    elif results[k].get("category") == "undetected":
                        print ("==================================================")
                        print (results[k].get("engine_name"))
                        print ("version : " + results[k].get("engine_version"))
                        print ("category : " + results[k].get("category"))
                        print ("method : " + results[k].get("method"))
                        print ("update : " + results[k].get("engine_update"))
                        print ("==================================================")
                        print ()
                print ("Analisis satisfactorio: OK")
                sys.exit()
            else:
                print ("Fallo al analizar :(...")

        else:
            print ("Fallo al obtener la informacion :(")
            print ("status code: " + str(res.status_code))
            sys.exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-m','--mal', required = True, help = "Ruta del archivo a analizar")
    args = vars(parser.parse_args())
    vtscan = VTScan()
    vtscan.run(args["mal"])