import readTorList
import requests
import sys
import psycopg2
#import psycopg2.extras
import time
import datetime

TEMPO_RODADA = 120

def buscaTOR(valor,tipo="ip"):

    start_time = datetime.datetime.now()

    resp=readTorList.buscaIP(valor)
    print(valor,resp)

    end_time = datetime.datetime.now()

    time_diff = (end_time - start_time)
    execution_time = time_diff.total_seconds() * 1000

    print("Tempo TOR:",execution_time)

    return resp

#--------------------------------------------------------------------------------------------------------

def buscaVT(valor, tipo="ip"):

    start_time = datetime.datetime.now()

    resp = {"erro":0}
    headers = {'x-apikey' : 'xxxxxx'}

    if tipo == "ip":
        r = requests.get('https://www.virustotal.com/api/v3/ip_addresses/'+valor, headers=headers)
    else:
        r = requests.get('https://www.virustotal.com/api/v3/domains/'+valor, headers=headers)

    #  "harmless": 75,
    #  "malicious": 7,
    #  "suspicious": 0,
    #  "undetected": 12,
    #  "timeout": 0

    if r.ok:
        d = r.json()
        if 'attributes' in d['data']:
            result = d['data']['attributes']['last_analysis_stats']
            for key,data in result.items():
                print(key,"-",data)
            resp['maliciosos']=result['malicious']
            resp['suspeitos']=result['suspicious']
        else:
            print('resposta invalida - sem atributos')
            resp['erro'] = 1
                
    else:
        if (r.status_code == "404"):
            print("erro da api VirusTotal. Informacao nao econtrada")
            resp['erro'] = 2
        if (r.status_code == "400"):
            print("erro da api VirusTotal. Numero de consultas ultrapassou o permitido pela API")
            resp['erro'] = 3

    end_time = datetime.datetime.now()

    time_diff = (end_time - start_time)
    execution_time = time_diff.total_seconds() * 1000

    print("Tempo VT:",execution_time)

    return resp

#--------------------------------------------------------------------------------------------------------

def iniciar_robo():
    con = psycopg2.connect(host='localhost', database='dbrootkit', user='datalab', password='datalab')
    cur = con.cursor()

    print("Robo iniciado:")


    while(True):

        list_ids_enriquecidos = []

        cur.execute('select id,"ipDestino","enriqVT","enriqTOR","dominios".nome as dominios from "fluxosDetectados" LEFT JOIN "dominios" ON "fluxosDetectados".id = "dominios".fk_id')
        #column_names = [row[0] for row in cur.description]
        #print("Column names: {}\n".format(column_names))
        recset = cur.fetchall()


        for rec in recset:
            if rec[2] == False:  #enriqVT nao foi feito, inicia enriquecimento
                print(rec[0],"nao enriquecido no Virustotal. Iniciar processo...")
                if rec[1] not in list_ids_enriquecidos: #significa que precisa enriquecer o ipDestino
                    resp = buscaVT(rec[1],"ip")
                    if resp['erro']==0: #sem erro, adicionar na base de dados
                        print("enriquecer o id",rec[0],", IP:",rec[1])
                        cur.execute('INSERT INTO "enriquecimentoVT" ("fk_id","deteccao", "ip", "data") VALUES({},{},\'{}\',NOW())'.format(rec[0],resp['maliciosos'],rec[1]))
                        con.commit()
                        list_ids_enriquecidos.append(rec[0]) #esse id foi enriquecido
                if rec[4] != None: #significa que existe um dominio a ser enriquecido
                    resp = buscaVT(rec[4],"dominio")
                    if resp['erro']==0: #sem erro, adicionar na base de dados
                        print("enriquecer o id",rec[0],", dominio:",rec[4])
                        cur.execute('INSERT INTO "enriquecimentoVT" ("fk_id","deteccao", "dominio", "data") VALUES({},{},\'{}\',NOW())'.format(rec[0],resp['maliciosos'],rec[4]))
                        con.commit()
                        if rec[1] not in list_ids_enriquecidos:
                            list_ids_enriquecidos.append(rec[0]) #esse id foi enriquecido
                print("esperar 22 segundos:")
                time.sleep(22)
        for ids in list_ids_enriquecidos:
            cur.execute('UPDATE "fluxosDetectados" SET "enriqVT" = True WHERE id = {}'.format(ids))
            con.commit()


        cur.execute('select id,"ipDestino","enriqTOR" from "fluxosDetectados";')
        #column_names = [row[0] for row in cur.description]
        #print("Column names: {}\n".format(column_names))
        recset = cur.fetchall()

        for rec in recset:
                if rec[2] == False:  #enriqTOR nao foi feito, inicia enriquecimento
                    print(rec[0],"nao enriquecido no Tor. Iniciar processo...")
                    resp = buscaTOR(rec[1])
                    if resp['erro']==0: #sem erro, adicionar na base de dados
                        cur.execute('INSERT INTO "enriquecimentoTOR" ("fk_id","nome", "flags", "versao", "data") VALUES({},\'{}\',\'{}\',\'{}\',NOW())'
                                                .format(rec[0],resp['nome'],resp['flags'],resp['versao']))
                        cur.execute('UPDATE "fluxosDetectados" SET "enriqTOR" = True WHERE id = {}'.format(rec[0]))
                        con.commit()
                    elif resp['erro']==1: #nao encontrado. Mesmo nao sendo nó TOR, atualizar base informando que o enriquecimento foi feito
                        cur.execute('UPDATE "fluxosDetectados" SET "enriqTOR" = True WHERE id = {}'.format(rec[0]))
                        con.commit()
                    time.sleep(1)
 
        print("Robo finalizado. Aguardando",TEMPO_RODADA,"segundos para nova rodada")
        time.sleep(TEMPO_RODADA)
    cur.close()
    con.close()

#--------------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    inserir = False
    tipo = "ip"

    if len(sys.argv) < 2:
        print("necessario informar ip ou dominio")
        print("python3 enriquecimento.py valor [ip|dominio]")
        exit(-1)
    valor = sys.argv[1]
    if len(sys.argv) > 2:
        if sys.argv[2] == "dominio":
            tipo = "dominio"
        if sys.argv[2] == "robo":
            tipo = "robo"

    if tipo == "robo":
        iniciar_robo()

    exit(0)

    if inserir == True:
        con = psycopg2.connect(host='localhost', database='dbrootkit', user='datalab', password='datalab')
        cur = con.cursor()


        #VirusTotal
        #------------------------------------------
        resp = buscaVT(valor,tipo)
        if resp['erro']==0: #sem erro, adicionar na base de dados
            if tipo=="ip":
                cur.execute('INSERT INTO "enriquecimentoVT" ("fk_id","deteccaoIP", "data") VALUES(28,{},NOW())'.format(resp['maliciosos']))
                
            else:
                cur.execute('INSERT INTO "enriquecimentoVT" ("fk_id","deteccaoDominio", "data") VALUES(28,{},NOW())'.format(resp['maliciosos']))
            con.commit() # <- We MUST commit to reflect the inserted data


        #TOR
        #------------------------------------------
        resp = buscaTOR(valor,tipo)
        if resp['erro']==0: #sem erro, adicionar na base de dados
            cur.execute('INSERT INTO "enriquecimentoTOR" ("fk_id","nome", "data","flags","versao") VALUES(28,\'{}\',NOW(),\'{}\',\'{}\')'.format(resp['nome'],resp['flags'],resp['versao']))
            con.commit() # <- We MUST commit to reflect the inserted data


        cur.close()
        con.close()



