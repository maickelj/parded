
#id fluxo: dict contendo id, ipDest, tor

def cria_snortrule(indicadores,nl="\n"):
    regra = ""
    nl1 = ""
    #msg = "IP utilizado por rootkit com ofuscação de tráfego no terminal infectado;"
    #if tipo == 'destino':
    for indicador in indicadores:
        if indicador[3] == "ip":
            regra = regra + '{}drop tcp any any -> {} any (msg:"{}";rev:1; sid=100000{})'.format(nl1,indicador[0],indicador[2],indicador[1])
        elif indicador[3] == "dominio":
            dominio = ""
            for d in indicador[0].split('.'):
                dominio = dominio + "|{:02x}|{}".format(len(d),d)
            regra = regra + '{}drop tcp any any -> any any (msg:"{}";content:"{}"; nocase; rev:1; sid=100001{})'.format(nl1,indicador[2],dominio,indicador[1])
        nl1 = nl

    return regra



if __name__ == "__main__":
    resultado = cria_snortrule([["1.2.3.4",35,"teste","ip"],["dominiodddd.com.br","35","teste","dominio"]])
    #with open("assets/cti-stix-visualization/snorts.txt",'a') as fw:
    #    fw.write("\nid{}=`{}`".format(40,resultado))

    print(resultado)
    exit(0)