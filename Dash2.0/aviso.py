import readTorList
import requests
import sys
import psycopg2
#import psycopg2.extras
import time
import datetime
from stix2.v21 import (Indicator, Malware, Relationship, Bundle)
import stixCreator
import snortCreator

TEMPO_RODADA = 600


#--------------------------------------------------------------------------------------------------------


#SELECT count("ipOrigem"),"ipDestino" FROM "public"."fluxosDetectados" where "bloqueado"=False group by "ipDestino";

#SELECT count("ipOrigem"),"ipDestino" FROM "public"."fluxosDetectados" where "bloqueado"=False and "quantidade">1 group by "ipDestino"  HAVING COUNT("ipDestino")>1;

def iniciar_robo():
    con = psycopg2.connect(host='localhost', database='dbrootkit', user='datalab', password='datalab')
    cur = con.cursor()

    print("Robo iniciado:")


    while(True):

        list_ids_bloqueados = []
        lista_ips_tratados = []

        #---------------------------------------------------------------
        #   Primeira regra:
        #   2 terminais com 2 fluxos não detectados  - essa regra eh feita antes da detecção simples (6 fluxos do mesmo IP) pq senão a regra simples colocaria bloqueado=True em um dos fluxos que deveria ser analisado por essa regra
        #
        cur.execute('SELECT "id","ipDestino","fk_id" FROM "fluxosDetectados" LEFT JOIN "enriquecimentoTOR" ON "id" = "fk_id" WHERE "ipDestino" IN (SELECT "ipDestino" FROM "fluxosDetectados" where "bloqueado"=False and "quantidade">1 group by "ipDestino" HAVING COUNT("ipDestino")>1);')
        recset = cur.fetchall()
        for rec in recset:  #se teve resultado, tem novos fluxos para bloquear
            list_ids_bloqueados.append({'id':rec[0], 'ipDest':rec[1], 'tor':rec[2]})
        #print(list_ids_bloqueados)

        #  iniciar criação dos STIX_2.0 e SNORT (estou ignorando IPs de origem por enquanto)
        #------------------
        #
        for ids in list_ids_bloqueados:

            #evita criar stix duplicados (mesmo ip de destino)
            #if ids['ipDest'] in lista_ips_tratados:
            #    continue;
            #lista_ips_tratados.append(ids['ipDest'])

            indicadores = []
            indicadores_snort = []

            #malware = ""
            label = ['malicious-activity']

            if ids['tor'] != "NULL":
                label.append('anonymization')

            indicadores.append(stixCreator.add_indicator_ip(ids['ipDest'],label,"IPs utilizados por rootkit com ofuscação de tráfego no terminal infectado"))
            indicadores_snort.append([ids['ipDest'],ids['id'],"IP utilizado por rootkit com ofuscação de tráfego no terminal infectado","ip"])

            cur.execute('SELECT "nome" FROM "dominios" WHERE fk_id = {};'.format(ids['id']))
            recset = cur.fetchall()
            for rec in recset:
                indicadores.append(stixCreator.add_indicator_domain(rec[0],label,"Dominios utilizados por rootkit com ofuscação de tráfego no terminal infectado"))
                indicadores_snort.append([rec[0],ids['id'],ids['id'],"Dominio utilizado por rootkit com ofuscação de tráfego no terminal infectado","dominio"])
        
            resultado = stixCreator.cria_stix(indicadores)
            #grava o stix no arquivo
            with open("assets/cti-stix-visualization/stixs.txt",'a') as fw:
                fw.write("\nid{}=`{}`".format(ids['id'],resultado))

            # pega e grava o snort no arquivo
            resultado = snortCreator.cria_snortrule(indicadores_snort,"<br>")  #<br> é utilizado como separador de regra (padrao é '\n')
            with open("assets/cti-stix-visualization/snorts.txt",'a') as fw:
                fw.write("\nid{}=`{}`".format(ids['id'],resultado))
            

        #  atualizar informação de bloqueio no Banco de Dados
        #------------------
        #
        for ids in list_ids_bloqueados:
            cur.execute('UPDATE "fluxosDetectados" SET "bloqueado" = True WHERE id = {}'.format(ids['id']))
            con.commit()
 

        #---------------------------------------------------------------
        #   Segunda regra:
        #   1 terminal com 6 fluxos não detectados
        #
        list_ids_bloqueados = []

        cur.execute('SELECT "id","ipDestino","fk_id" FROM "fluxosDetectados" LEFT JOIN "enriquecimentoTOR" ON "id" = "fk_id" WHERE "bloqueado" = False AND "quantidade">5;')
        recset = cur.fetchall()
        for rec in recset:  #se teve resultado, tem novos fluxos para bloquear
            list_ids_bloqueados.append({'id':rec[0], 'ipDest':rec[1], 'tor':rec[2]})

        for ids in list_ids_bloqueados:

            indicadores = []
            indicadores_snort = []

            label = ['malicious-activity']

            if ids['tor'] != "NULL":
                label.append('anonymization')

            indicadores.append(stixCreator.add_indicator_ip(ids['ipDest'],label,"IPs utilizados por rootkit com ofuscação de tráfego no terminal infectado"))
            indicadores_snort.append([ids['ipDest'],ids['id'],"IP utilizado por rootkit com ofuscação de tráfego no terminal infectado","ip"])

            cur.execute('SELECT "nome" FROM "dominios" WHERE fk_id = {};'.format(ids['id']))
            recset = cur.fetchall()
            for rec in recset:
                indicadores.append(stixCreator.add_indicator_domain(rec[0],label,"Dominios utilizados por rootkit com ofuscação de tráfego no terminal infectado"))
                indicadores_snort.append([rec[0],ids['id'],"Dominio utilizado por rootkit com ofuscação de tráfego no terminal infectado","dominio"])
        
            #grava o stix no arquivo
            resultado = stixCreator.cria_stix(indicadores)
            with open("assets/cti-stix-visualization/stixs.txt",'a') as fw:
                fw.write("\nid{}=`{}`".format(ids['id'],resultado))


            # pega e grava o snort no arquivo
            resultado = snortCreator.cria_snortrule(indicadores_snort,"<br>")  #<br> é utilizado como separador de regra (padrao é '\n')
            with open("assets/cti-stix-visualization/snorts.txt",'a') as fw:
                fw.write("\nid{}=`{}`".format(ids['id'],resultado))
            

        for ids in list_ids_bloqueados:
            cur.execute('UPDATE "fluxosDetectados" SET "bloqueado" = True WHERE id = {}'.format(ids['id']))
            con.commit()

        #---------------------------------------------------------------
        #   Terceira regra:
        #   1 terminal com 2 fluxos não detectados
        #       - destino seja TOR; 

        list_ids_bloqueados = []

        cur.execute('SELECT distinct("id"),"ipDestino" FROM "fluxosDetectados" INNER JOIN "enriquecimentoTOR" ON "id" = "fk_id" WHERE "quantidade">1 AND "bloqueado"=False;')
        recset = cur.fetchall()
        for rec in recset:  #se teve resultado, tem novos fluxos para bloquear
            list_ids_bloqueados.append({'id':rec[0], 'ipDest':rec[1]})

        for ids in list_ids_bloqueados:

            indicadores = []
            indicadores_snort = []
            #malware = ""
            label = ['malicious-activity','anonymization']

            indicadores.append(stixCreator.add_indicator_ip(ids['ipDest'],label,"IPs utilizados por rootkit com ofuscação de tráfego no terminal infectado"))
            indicadores_snort.append([ids['ipDest'],ids['id'],"IP utilizado por rootkit com ofuscação de tráfego no terminal infectado","ip"])

            cur.execute('SELECT "nome" FROM "dominios" WHERE fk_id = {};'.format(ids['id']))
            recset = cur.fetchall()
            for rec in recset:
                indicadores.append(stixCreator.add_indicator_domain(rec[0],label,"Dominios utilizados por rootkit com ofuscação de tráfego no terminal infectado"))
                indicadores_snort.append([rec[0],ids['id'],"Dominio utilizado por rootkit com ofuscação de tráfego no terminal infectado","dominio"])

            resultado = stixCreator.cria_stix(indicadores)
            #grava o stix no arquivo
            with open("assets/cti-stix-visualization/stixs.txt",'a') as fw:
                fw.write("\nid{}=`{}`".format(ids['id'],resultado))

            # pega e grava o snort no arquivo
            resultado = snortCreator.cria_snortrule(indicadores_snort,"<br>")  #<br> é utilizado como separador de regra (padrao é '\n')
            with open("assets/cti-stix-visualization/snorts.txt",'a') as fw:
                fw.write("\nid{}=`{}`".format(ids['id'],resultado))
            

        for ids in list_ids_bloqueados:
            cur.execute('UPDATE "fluxosDetectados" SET "bloqueado" = True WHERE id = {}'.format(ids['id']))
            con.commit()
 
        #---------------------------------------------------------------
        #   Quarta regra:
        #   1 terminal com 2 fluxos não detectados
        #       - IP com 4 detecoes pelo VT

        list_ids_bloqueados = []

        cur.execute('SELECT distinct("id"),"ipDestino" FROM "fluxosDetectados" INNER JOIN "enriquecimentoVT" ON "id" = "fk_id" WHERE "quantidade">1 AND "bloqueado"=False AND "deteccao" > 3;')
        recset = cur.fetchall()
        for rec in recset:  #se teve resultado, tem novos fluxos para bloquear
            list_ids_bloqueados.append({'id':rec[0], 'ipDest':rec[1]})

        for ids in list_ids_bloqueados:

            indicadores = []
            indicadores_snort = []

            #malware = ""
            label = ['malicious-activity']

            indicadores.append(stixCreator.add_indicator_ip(ids['ipDest'],label,"IPs utilizados por rootkit com ofuscação de tráfego no terminal infectado"))
            indicadores_snort.append([ids['ipDest'],ids['id'],"IP utilizado por rootkit com ofuscação de tráfego no terminal infectado","ip"])

            cur.execute('SELECT "nome" FROM "dominios" WHERE fk_id = {};'.format(ids['id']))
            recset = cur.fetchall()
            for rec in recset:
                indicadores.append(stixCreator.add_indicator_domain(rec[0],label,"Dominios utilizados por rootkit com ofuscação de tráfego no terminal infectado"))
                indicadores_snort.append([rec[0],ids['id'],"Dominio utilizado por rootkit com ofuscação de tráfego no terminal infectado","dominio"])
        
            resultado = stixCreator.cria_stix(indicadores)
            #grava o stix no arquivo
            with open("assets/cti-stix-visualization/stixs.txt",'a') as fw:
                fw.write("\nid{}=`{}`".format(ids['id'],resultado))


            # pega e grava o snort no arquivo
            resultado = snortCreator.cria_snortrule(indicadores_snort,"<br>")  #<br> é utilizado como separador de regra (padrao é '\n')
            with open("assets/cti-stix-visualization/snorts.txt",'a') as fw:
                fw.write("\nid{}=`{}`".format(ids['id'],resultado))
            

        for ids in list_ids_bloqueados:
            cur.execute('UPDATE "fluxosDetectados" SET "bloqueado" = True WHERE id = {}'.format(ids['id']))
            con.commit()

        #break
        print("Robo finalizado. Aguardando",TEMPO_RODADA,"segundos para nova rodada")
        time.sleep(TEMPO_RODADA)
    cur.close()
    con.close()

#--------------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    inserir = False
    tipo = "ip"

    if len(sys.argv) < 2:
        print("necessario informar se deve iniciar o robô ou busca por fluxo")
        print("python3 enriquecimento.py (fluxo|robo) [id do fluxo]")
        exit(-1)

    if len(sys.argv) > 2:
        valor = sys.argv[1]
    
    if sys.argv[1] == "fluxo":
        tipo = "fluxo"
    elif sys.argv[1] == "robo":
        tipo = "robo"

    if tipo == "robo":
        start_time = datetime.datetime.now()
        iniciar_robo()
        end_time = datetime.datetime.now()
        time_diff = (end_time - start_time)
        execution_time = time_diff.total_seconds() * 1000
        print("Tempo Aviso:",execution_time)

    else:
        print("nao implementado")


    exit(0)




    resp=readTorList.buscaIP(valor)
    print(valor,resp)

    

