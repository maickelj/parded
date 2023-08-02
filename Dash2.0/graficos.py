#from curses.ascii import NUL
from dash import Dash, html, dcc, dash_table, Input, Output, callback
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import psycopg2
import psycopg2.extras
import json
import plotly.express as px
import geoip2.database
import geoip2.errors
import statusEAud


app = Dash(title='PARDED')
# app = Dash(__name__)
#-------------------------------------------------------------------------------------------
# conexao banco de dados
#
con = psycopg2.connect(host='localhost', database='dbrootkit',
user='datalab', password='datalab')
cur = con.cursor(cursor_factory = psycopg2.extras.DictCursor)
#cur = con.cursor()
#sql = 'create table cidade (id serial primary key, nome varchar(100), uf varchar(2))'
#cur.execute(sql)
#sql = "insert into cidade values (default,'São Paulo,'SP')"
#cur.execute(sql)
#con.commit()
cur.execute('select id,"ipOrigem","ipDestino","enriqVT","enriqTOR","bloqueado","dominios".nome as dominios from "fluxosDetectados" LEFT JOIN "dominios" ON "fluxosDetectados".id = "dominios".fk_id WHERE id > 27')
column_names = [row[0] for row in cur.description]
#print("Column names: {}\n".format(column_names))
recset = cur.fetchall()

#ans1 = []
#for row in recset:
#    print(row)

#print(ans1)
#exit(0)

#result = [r[0] for r in cur.fetchall()]
#for rec in recset:
#    print (rec)
#-------------------------------------------------------------------------------------------


#dataframe do banco de dados
df_fluxos = pd.DataFrame(recset, columns = column_names)

#print(df_fluxos)
df_fluxos = df_fluxos.fillna("")
df_fluxos = df_fluxos.groupby(["id","ipOrigem","ipDestino","enriqVT","enriqTOR","bloqueado"],as_index=False)['dominios'].aggregate(lambda x: ','.join(x))    #.agg(list)
#print(df_fluxos)
#df_fluxos['dominio'] = df3['nome']
#exit(0)

#print(len(df_fluxos[df_fluxos['enriqVT']==False].index))
#len(df_fluxos[df_fluxos['enriqVT']==False])
#exit(0)
fluxos = len(recset)
fluxos_bloqueados= (df_fluxos['bloqueado'] == True).sum()
fluxos_enriquecidosVT= (df_fluxos['enriqVT'] == True).sum()
fluxos_enriquecidosTOR= (df_fluxos['enriqTOR'] == True).sum()
fluxos_ipdestino= (df_fluxos['ipDestino']).nunique()
fluxos_dominios= (df_fluxos['dominios'].loc[df_fluxos['dominios']!='']).nunique()

print("fluxos:"+str(fluxos))
print("bloqueados:"+str(fluxos_bloqueados))
print("enriquecidos VT:"+str(fluxos_enriquecidosVT))
print("enriquecidos TOR:"+str(fluxos_enriquecidosTOR))
print("dominios:"+str(fluxos_dominios))

#print(df_fluxos['ipDestino'].iloc[0])

lat = []
lon = []
local = []
with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
    for ip in df_fluxos['ipDestino']:
        try:
            response = reader.city(ip)
            lat.append(response.location.latitude)
            lon.append(response.location.longitude)

            if (response.city.name is not None):
                local.append(ip + ": " +str(response.city.name)+" - "+str(response.country.name))
            else:
                local.append(ip + ": " +str(response.country.name))                
            #print(local)
            #print(response)
            #if 'city' in response.:
            #else:
           #     local.append(str(response.country.name))
                #city.names.pt-BR
                #country.names.pt-BR
                #country.iso_code

        except geoip2.errors.AddressNotFoundError:
            lat.append(-50.0)
            lon.append(-150.0)
            local.append(ip+" sem georeferenciamento")

df_fluxos = df_fluxos.assign(lat=lat).assign(lon=lon).assign(local=local)

#permite style-conditional baseado na coluna "bloqueado" (tive que trocar 'boolean' para 'str' na coluna)
df_fluxos['bloqueado'] = df_fluxos['bloqueado'].map({True: 'true', False: 'false'})

fig_map = go.Figure(data=go.Scattergeo(
        lon = df_fluxos['lon'],
        lat = df_fluxos['lat'],
        hovertext = local,
        #text = str(df_fluxos['ip_destino']),
        #mode = 'markers',
        marker = dict(size=20)
        #marker_color = df['cnt'],
        ))

fig_map.update_geos(
    resolution=50,
    showcoastlines=True, coastlinecolor="lightgrey",
    showland=True, landcolor="white",
    showocean=True, oceancolor="LightBlue",
    showcountries=True, countrycolor="lightgrey",
    showlakes=False, lakecolor="Blue",
    showrivers=False, rivercolor="Blue"
)
fig_map.update_layout(height=750,margin=dict(l=25, r=25, t=40, b=25))#, title_text="Destino dos fluxos suspeitos")

#####################################################
# grafico de detecções VT

#cur.execute('SELECT "deteccao","ip","dominio" FROM "enriquecimentoVT";')
cur.execute('SELECT sum("deteccao") AS deteccoes FROM "enriquecimentoVT" group by "fk_id";')
column_names = [row[0] for row in cur.description]
#print("Column names: {}\n".format(column_names))
recset = cur.fetchall()

df_vt = pd.DataFrame(recset, columns = column_names)
valores=[0,0,0,0]
valores[0] = (df_vt['deteccoes']==0).sum()
valores[1] = (df_vt['deteccoes']<6).sum() - valores[0]
valores[2] = (df_vt['deteccoes']>=6).sum()
valores[3] = (df_fluxos['enriqVT']==False).sum()

fig = go.Figure(data=[go.Bar(x=["Sem detecção","Até 5 detecções","Mais de 5 detecções","Não Analisados"],y=valores,text=valores)])
#fig.update_layout(title_text="VirusTotal Detections")
fig.update_layout(margin=dict(l=25, r=25, t=40, b=25),height=350)


###################################################
# grafico de detecções TOR

valores = [0,0,0]
cur.execute('SELECT COUNT(*) FROM "enriquecimentoTOR";')
(valores[0],) = cur.fetchone()
valores[1] = len(df_fluxos[df_fluxos['enriqTOR']==True].index) - valores[0]
valores[2] = len(df_fluxos[df_fluxos['enriqTOR']==False].index)

fig2 = go.Figure(data=[go.Bar(x=["Detectado","Não detectado","Fluxo não analisado"],y=valores,text=valores,textposition='auto')])
#fig2.update_layout(title_text="Onion Network detections (TOR)")
fig2.update_layout(margin=dict(l=25, r=25, t=40, b=25),height=350)


###################################################
# status dos programas

statusAuditor = [
    {'nome':'Sistema de Análise Inicial','status':'Parado'},
    {'nome':'Sistema de Enriquecimento','status':'Parado'},
    {'nome':'Sistema de Aviso','status':'Parado'},

]
x = statusEAud.getProcessRunning("auditoragent")
if x: # processo encontrado
    statusAuditor[0]['status']='Executando ({} minutos)'.format(x[0][-1])

x = statusEAud.getProcessRunning("python")
for proc in x:
    if "enriquecimento.py" in proc[1]:
        statusAuditor[1]['status']='Executando ({} minutos)'.format(proc[-1])
    if "aviso.py" in proc[1]:
        statusAuditor[2]['status']='Executando ({} minutos)'.format(proc[-1])

#################################################
# estilos

style_data_conditional = [
    {
        "if": {"state": "active", 'filter_query': '{bloqueado} eq "true"',},
        "backgroundColor": '#fdd', #"rgba(150, 180, 225, 0.2)",
        "border": "1px solid blue",
    },
    {
        "if": {"state": "selected"},
        "backgroundColor": "rgba(0, 116, 217, .03)",
        "border": "1px solid blue",
    },
    {
        'if': {'row_index': 'odd'},
        'backgroundColor': '#f7f7ff',
    },
    {
        'if': {
            'column_id': 'bloqueado',
            'filter_query': '{bloqueado} eq "true"',
            },
        'backgroundColor': '#fdd',
    }
]

style_header={
        #'backgroundColor': '#D5F3FE',
        'fontWeight': 'bold',
        'textAlign': 'center',
        'backgroundColor': 'rgba(39, 39, 204, 0.6)',
        #'borderTopRightRadius': '15px',
        #'borderTopLeftRadius': '15px'
    }

style_header_none={
        'display':'none',

    }

style_cell={
        'paddingRight': '8px'
}
style_data={
        'color': 'black',
        'backgroundColor': 'white',
}


print("dominios ==:"+str(fluxos_dominios))


app.layout = html.Div(children=[


    html.Div([
        html.H1(children='PARDED'),
        html.H4('Passive Rootkit Detector With Enriched Data'),
        html.Div([
            html.Div("Detecções - Virustotal",className="tbl-header tbl-h"),
            dcc.Graph(
                id='virustotal',
                figure=fig,
                className='tbl-content-noscroll'),
            ],className="div-36pc"
        ),


        html.Div([
            html.Div("Detecções - Rede onion (TOR)",className="tbl-header tbl-h"),
            dcc.Graph(
                id='tor',
                figure=fig2,
                className='tbl-content-noscroll'),
            ],className="div-36pc"
        ),

        #html.Div(children='''
        #    Detected traffic analysis
        #''',style={'border-bottom':'1px solid #DDD','width':'60%','padding-bottom':'3px'}),


        html.Div([
            html.H3(
                "Fluxos - Resumo:"
            ),
            html.Table([
                # Header
                #[html.Tr([html.Th(col) for col in dataframe.columns]) ] +
                # Body
                html.Tr([html.Td("Fluxos Bloqueados:"),html.Td(fluxos_bloqueados)]),
                html.Tr([html.Td("Fluxos Enriquecidos (VT):"),html.Td(fluxos_enriquecidosVT)]),
                html.Tr([html.Td("Fluxos Enriquecidos(TOR):"),html.Td(fluxos_enriquecidosTOR)]),
                html.Tr([html.Td("Domínios Detectados:"),html.Td(fluxos_dominios)]),
                html.Tr([html.Td("IPS de Destino Detectados:"),html.Td(fluxos_ipdestino)])

            ],style={'width':'100%','border':'1px solid #CCC'}),
        ],className='div-28pc'),
        html.Div([
            html.H3(
                "Status do Auditor:"
            ),
            html.Table([
                # Header
                #[html.Tr([html.Th(col) for col in dataframe.columns]) ] +
                # Body
                html.Tr([html.Td(statusAuditor[0]['nome']),html.Td(statusAuditor[0]['status'])]),
                html.Tr([html.Td(statusAuditor[1]['nome']),html.Td(statusAuditor[1]['status'])]),
                html.Tr([html.Td(statusAuditor[2]['nome']),html.Td(statusAuditor[2]['status'])])
            ],id='status-data',style={'width':'100%','border':'1px solid #CCC'}),
            dcc.Interval(
                id='interval-component',
                interval=1*5000, # in milliseconds
                n_intervals=0),
        ],className='div-28pc')
    ],className='div-100pc'),
    html.Div([
        html.H3(
            "Fluxos Suspeitos:"
        ),
        
        #tabela Fluxos Suspeitos
        html.Div([
            html.Table([
                html.Thead([
                    html.Th("ID"),
                    html.Th("IP de Origem"),
                    html.Th("IP de Destino"),
                    html.Th("Enriquecimento VT"),
                    html.Th("Enriquecimento TOR"),
                    html.Th("Bloqueado"),
                    html.Th("Domínios")
                ]),
            ]),
        ],className="tbl-header"),
        html.Div(
            [
            dbc.Container([
                dash_table.DataTable(df_fluxos.to_dict('records'), [{"name": "id", "id": df_fluxos.columns[0]},{"name": "Source IP", "id": df_fluxos.columns[1]},{"name": "Destination IP", "id": df_fluxos.columns[2]},{"name": "VT Enriched", "id": df_fluxos.columns[3]},
                {"name": "TOR Enriched", "id": df_fluxos.columns[4]},{"name": "Blocked", "id": df_fluxos.columns[5]},{"name": "Domain list", "id": df_fluxos.columns[6]}], id='tbl',
                    css=[{'selector': 'tr:first-child','rule': 'display: none',}],
                    style_data_conditional=style_data_conditional,
                    style_data=style_data,
                    style_cell=style_cell), #, style_data_conditional=style_data_conditional,style_header=style_header
                #css=[{'selector': '.dash-spreadsheet-container','rule': 'border: 1px solid blue; border-radius: 15px; overflow: hidden;'}]
                dbc.Alert(id='tbl_out')
            ])
        ], className='tbl-content'),

        #tabela STIX Relatorios
        html.Div([
            html.Table([
                html.Tr([
                    html.Td(html.A("STIX - Visualização", href='', target="_blank", id="link-stixviewer")),
                    html.Td(html.A("STIX - Arquivo JSON", href='', target="_blank", id="link-stixjson")),
                    html.Td(html.A("SNORT - Arquivo de regra", href='', target="_blank", id="link-snortrule"))
                ]),
            ],style={'width':'100%','border':'1px solid #CCC'}),
        ],style={'visibility':'hidden'},className='tbl-content-noscroll',id='div_stix'),

        #-----
        #tabela de detecção do virustotal
        html.Div([
            html.Div("Fluxos Suspeitos - Virustotal",className="tbl-header tbl-h"),
            html.Div(
                dash_table.DataTable(columns=[{'name': 'Detecções maliciosas', 'id': 'deteccao'},{'name': 'Dominio', 'id': 'dominio'},{'name': 'IP', 'id': 'ip'},{'name': 'Data Coleta', 'id': 'data'}], 
                                id='resultadoVT', 
                                #css=[{'rule': 'table-layout: auto', 'selector': 'table'},{'selector': 'tr:first-child','rule': 'display: auto',}],
                                style_data=style_data,
                                style_header=style_header,
                                style_cell=style_cell
                ), className="tbl-content-noscroll"
            )
        ], className="div-50pc"),

        #tabela de detecção da Rede TOR
        html.Div([
            html.Div("Fluxos Suspeitos - Rede TOR",className="tbl-header tbl-h"),
            html.Div(
                dash_table.DataTable(columns=[{'name': 'Nome', 'id': 'nome'},{'name': 'Flags', 'id': 'flags'},{'name': 'Versão', 'id': 'versao'},{'name': 'Data Coleta', 'id': 'data'}], 
                                id='resultadoTOR', 
                                css=[{'rule': 'table-layout: auto', 'selector': 'table'}],
                                style_data=style_data,
                                style_header=style_header,
                                style_cell=style_cell
                ), className="tbl-content-noscroll"
            )
        ], className="div-50pc"),
    ],style={'width': '100%'}),


    #html.Table([
    #            html.Tr([html.Th(html.A("STIX", href='', target="_blank", id="link-stix")),html.Th("Relatório")]),
    #        ],id='tableStix',className='div-stix'),

    #html.Iframe(src="",name="iframe_stix"),
                #style={"height": "1067px", "width": "100%"})

    #  MAPA
    html.Div([
        html.Div([
            html.Div("Destino das Conexões (georeferenciamento)",className="tbl-header tbl-h"),
            dcc.Graph(
                id='mapa',
                figure=fig_map,
                className='tbl-content-noscroll'),
            ],className="div-100pc"
        ),
        #dcc.Graph(
        #    id='mapa1',
        #    figure=fig_map
        #)
    ],className='div-100pc')
])


#@callback(Output('tbl_out', 'children'), Input('tbl', 'active_cell'))
@callback(Output('tbl', 'style_data_conditional'), Output('resultadoVT', 'data'), Output('resultadoTOR', 'data'), Output('mapa', 'figure'), Output('div_stix','style'),Output('link-stixviewer', 'href'),Output('link-stixjson','href'),Output('link-snortrule', 'href'),Input('tbl', 'active_cell'))
def update_graphs(active_cell):
    #return str(active_cell) if active_cell else "Click the table"
    style = style_data_conditional.copy()
    dadosTOR = [{'tipo':'information not avaliable'}]
    dadosVT = [{'deteccaoIP':'information not avaliable'}]
    dadosMapa = fig_map
    dadosLinkViewer = ""
    dadosLinkJson = ""
    dadosLinkSnort = ""
    dadosDivStix = {'visibility':'hidden'}
    if active_cell:
        style.append(
            {
                "if": {"row_index": active_cell["row"]},
                "backgroundColor": "rgba(150, 180, 225, 0.2)",
                "border": "1px solid blue",
            },
        #cur.execute('select * from "enriquecimentoTOR" where ')
        #column_names = [row[0] for row in cur.description]
        #print("Column names: {}\n".format(column_names))   
        #recset = cur.fetchall()
        )

        dados = df_fluxos.loc[active_cell['row']]

        if dados['enriqTOR'] == True:
            cur.execute('select * from "enriquecimentoTOR" where fk_id = '+str(active_cell['row_id']))
            recset = cur.fetchall()
            if recset:
                column_names = [row[0] for row in cur.description]
                #dataframe da resposta
                dft = pd.DataFrame(recset, columns = column_names)
                dadosTOR = dft.to_dict('records')
            else:
                dadosTOR = [{'nome':'Rede TOR não detectada','flags':'','versao':'','data':''}]
            #print(dadosTOR)
        if dados['enriqVT'] == True:
            cur.execute('select * from "enriquecimentoVT" where fk_id = '+str(active_cell['row_id']))
            recset = cur.fetchall()

            column_names = [row[0] for row in cur.description]
            #dataframe da resposta
            dft = pd.DataFrame(recset, columns = column_names)
            dadosVT = dft.to_dict('records')
        
        if dados['bloqueado'] == True:
            pass
        
        #
        # print(df_fluxos.loc[active_cell['row']]['ipDestino'])

        #coord = df_fluxos.loc[active_cell['row']]
        #dadosMapa.update({'data': [{'lat': [coord[lat]],'lon': [coord[lon]],'marker': {'size': 20},'type': 'scattergeo'}],}) 
        print(dados['bloqueado'])
        if dados['bloqueado']=="true":
            dadosDivStix = {'visibility':'visible'}
            dadosLinkViewer = 'assets/cti-stix-visualization/index.html?id='+str(dados['id'])
            dadosLinkJson = 'assets/cti-stix-visualization/stixjson.html?id='+str(dados['id'])
            dadosLinkSnort = 'assets/cti-stix-visualization/snort.html?id='+str(dados['id'])
        
        dadosMapa = go.Figure(data=go.Scattergeo(
                lon = [dados['lon']],
                lat = [dados['lat']],
                hovertext = [dados['local']],
                #mode = 'markers',
                marker = dict(size=20)
                #marker_color = df['cnt'],
                ))

        dadosMapa.update_geos(
            resolution=50,
            showcoastlines=True, coastlinecolor="lightgrey",
            showland=True, landcolor="white",
            showocean=True, oceancolor="LightBlue",
            showcountries=True, countrycolor="lightgrey",
            showlakes=False, lakecolor="Blue",
            showrivers=False, rivercolor="Blue"
        )
        dadosMapa.update_layout(height=750,margin=dict(l=25, r=25, t=40, b=25))#, title_text="Destino dos fluxos suspeitos")

    return style, dadosVT, dadosTOR, dadosMapa, dadosDivStix, dadosLinkViewer, dadosLinkJson, dadosLinkSnort


@callback(Output('status-data', 'children'), Input('interval-component', 'n_intervals'))
def update_status(n):

    ###################################################
    # status dos programas

    statusAuditor = [
        {'nome':'Sistema de Análise Inicial','status':'Parado'},
        {'nome':'Sistema de Enriquecimento','status':'Parado'},
        {'nome':'Sistema de Aviso','status':'Parado'},

    ]
    x = statusEAud.getProcessRunning("auditoragent")
    if x: # processo encontrado
        statusAuditor[0]['status']='Executando ({} minutos)'.format(x[0][-1])

    x = statusEAud.getProcessRunning("python")
    for proc in x:
        if "enriquecimento.py" in proc[1]:
            statusAuditor[1]['status']='Executando ({} minutos)'.format(proc[-1])
        if "aviso.py" in proc[1]:
            statusAuditor[2]['status']='Executando ({} minutos)'.format(proc[-1])


    return [
        html.Tr([html.Td(statusAuditor[0]['nome']),html.Td(statusAuditor[0]['status'])]),
        html.Tr([html.Td(statusAuditor[1]['nome']),html.Td(statusAuditor[1]['status'])]),
        html.Tr([html.Td(statusAuditor[2]['nome']),html.Td(statusAuditor[2]['status'])])
    ]

#@callback(Output('tbl', 'data'), Input('virustotal', 'clickData'))
#def update_table(valor):
#    if valor:
#        opcao = valor['points'][0]['pointNumber']
#        #print(valor['points'][0]['pointNumber'])
#        if opcao == 0:
#            df_tmp = df_fluxos[df_fluxos['ipDestino'] in ]
#        return df_tmp.to_dict('records')
#    return df_fluxos.to_dict('records')

#con.close()

if __name__ == '__main__':
    app.run_server(debug=True)
