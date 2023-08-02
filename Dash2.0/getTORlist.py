import requests


def texto_tmp():

    url = "https://www.dan.me.uk/tornodes"

    r = requests.get(url,allow_redirects=True) #, stream=True)

    with open('tor.tmp', 'wb') as fw:
        fw.write(r.content)



def cria_csv():

    isList = False
    with open('tor.tmp', 'r') as f:
    
        conteudo = []

        for linha in f:
            #print(linha)
            

        #for linha in conteudo:
            if '__BEGIN_TOR_NODE_LIST__' in linha:
                isList = True
                continue
            if (isList):
                print(linha)
            if '__END_TOR_NODE_LIST__' in linha:
                isList = False
                break
        #else:
        #    print("erro da api")

if __name__ == "__main__":
    #texto_tmp()
    cria_csv()
