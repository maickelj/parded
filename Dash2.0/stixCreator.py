from stix2.v21 import (Indicator, Malware, Relationship, Bundle) #KillChainPhase


def cria_stix(indicadores, malware=""):

    malware = Malware(
        name="Rootkit ofuscador de trafego",
        malware_types=["backdoor", "remote-access-trojan"],
        description="Malware com característica de ofuscação de tráfego no terminal infectado",
        #kill_chain_phases=[foothold],
        is_family="false"
    )
    todos_objetos = [malware]

    for indicador in indicadores:
        #relationship = Relationship(indicador, 'indicates', malware)
        todos_objetos.append(indicador)
        todos_objetos.append(Relationship(indicador, 'indicates', malware))
        #relationship2 = Relationship(indicator2, 'indicates', malware)

    bundle = Bundle(objects=todos_objetos)
    #print(bundle)
    return bundle



def add_indicator_domain(dominio,tipo_acao,descricao):

    indicator = Indicator(name=dominio,
                      #pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                      pattern_type="stix",
                      labels = tipo_acao,
                      description=descricao,
                      pattern="[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = '{}']".format(dominio) #value IN ('dns.ddos.im', 'win2003ddos.3322.org')
    )
    return indicator

def add_indicator_ip(ip,tipo_acao,descricao):

    indicator = Indicator(name=ip,
                      #pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                      pattern_type="stix",
                      labels = tipo_acao,
                      description=descricao,
                      pattern="[ipv4-addr:value = '{}']".format(ip) #value IN ('dns.ddos.im', 'win2003ddos.3322.org')
    )
    return indicator


#    id="indicator--d81f86b9-975b-4c0b-875e-810c5ad45a4f",
#    created="2014-06-29T13:49:37.079Z",
#    modified="2014-06-29T13:49:37.079Z",
#    name="Malicious site hosting downloader",
#    description="This organized threat actor group operates to create profit from all types of crime.",
#    indicator_types=["malicious-activity"],,
#    pattern="[url:value = 'http://x4z9arb.cn/4712/']",
#    pattern_type="stix",
#    valid_from="2014-06-29T13:49:37.079000Z"
#)

#foothold = KillChainPhase(
#    kill_chain_name="mandiant-attack-lifecycle-model",
#    phase_name="establish-foothold"
#)



if __name__ == "__main__":
 
    indicator = Indicator(name="xxx.com",
                      #pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                      pattern_type="stix",
                      labels = ["malicious-activity"],
                      description="Dominios utilizados por rootkit com ofuscação de tráfego no terminal infectado",
                      pattern="[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'imddos.my03.com']", #value IN ('dns.ddos.im', 'win2003ddos.3322.org')
    )

    indicator2 = Indicator(name="IP 170.140.120.110",
                      #pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                      pattern_type="stix",
                      labels = ["malicious-activity"], #anonymization
                      description="IPs utilizados por rootkit com ofuscação de tráfego no terminal infectado",
                      pattern="[ipv4-addr:value = '170.140.120.110']",
    )

    malware = Malware(
        name="Rootkit ofuscador de trafego",
        malware_types=["backdoor", "remote-access-trojan"],
        description="Malware com característica de ofuscação de tráfego no terminal infectado",
        #kill_chain_phases=[foothold],
        is_family="false"
    )   

    relationship = Relationship(indicator, 'indicates', malware)
    relationship2 = Relationship(indicator2, 'indicates', malware)


    bundle = Bundle(objects=[indicator, indicator2, malware, relationship, relationship2])

    print(bundle)

    exit(0)

