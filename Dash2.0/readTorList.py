import csv
import sys

#site de onde peguei os valores: https://www.dan.me.uk/tornodes

def buscaIP(ip):
    resp = {"erro":0}
    print("-{}-".format(ip))
    arquivo = "torlist.csv"
    #ip|name|router-port|directory-port|flags|uptime|version|contactinfo
    cabecalho = ["ip","nome","router-port","directory-port","flags","uptime","versao","contactinfo"]
    encontrou = 0
    colunas_aproveitadas = [0,1,4,6] #colunas que serão aproveitadas do CSV
    line_count = 0
    with open(arquivo, newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter='|')
        for row in spamreader:
            #print(ip,"-",row[0])
            if ip == row[0]:
                for c in colunas_aproveitadas:
                    resp[cabecalho[c]]=row[c]
                    encontrou = 1
                break  #se ja encontrou, nao precisa continuar a busca
            line_count = line_count + 1
            #if line_count > 3360:
            #    break
    if encontrou == 0:
        resp['erro'] = 1  #nao encontrado
    
    return resp

if __name__ == "__main__":
    if len(sys.argv) >1:
        print("iniciar busca:")
        print(buscaIP(sys.argv[1]))
    else:
        print("readTorList.py <ip>")