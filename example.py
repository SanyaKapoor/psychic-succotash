import io
import json
import uuid
import requests
import pandas as pd
from requests import get, HTTPError

#Script containing sql initialisation + fetching API keys being used
import SQL

mycursor = SQL.sql_init()
(xforce_apikey, xforce_pass, alient_apikey) = SQL.api_keys()

print("Connected to:", mydb.get_server_info())
r=requests.get('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=7',
               headers={'X-OTX-API-KEY':alient_apikey,
                        'User-Agent':  'OTX Python {}/1.5.12'.format("SDK"),
                       'Accept': 'application/json','Content-Type': 'application/json',  })
feed=r.json()
jfeed=json.dumps(feed)
pfeed=json.loads(jfeed)
obj=pfeed['results']
df=pd.json_normalize(obj)
df=df.drop(['id','description','revision','tlp','public','modified','adversary','tags','targeted_countries','attack_ids','references','industries','extract_source','more_indicators'],axis=1)
df2=pd.json_normalize(obj,"indicators",meta=['name','created','author_name','malware_families'],meta_prefix='event.')
df2=df2.rename({'event.name':'Threat Group','type':'Type','event.created':'DateTime','indicator':'ioc','event.malware_families':'Category','title':'Threat Name','event.author_name':'Source'},axis=1)
df2=df2[['ioc','Type','Category','Threat Name','Threat Group','Source','DateTime']]
for i, g in df2.groupby('Type'):
    g.to_csv('{}.csv'.format(i), header=True, index_label=False,index=False)
#domains
if(df2['Type']=='domain').any():
    dom=pd.read_csv('domain.csv')
    dom=dom.rename({'Filename':'Domain','ioc':'Domain'},axis=1)
    dom=dom.fillna("Null")
    dom=dom[['Domain','Category','Threat Name','Threat Group','Source','DateTime']]
    domdct=dom.to_dict('records')
    for i in range(len(domdct)):
        temp=domdct[i]
        iD=str(uuid.uuid1())
        domain=temp["Domain"]
        description=temp["Category"]
        tname=temp["Threat Name"]
        tgrp=temp["Threat Group"]
        src=temp["Source"]
        date=temp["DateTime"]
        sql="Insert into Domains(ID,Domain,Category,`Threat Name`,`Threat Group`,Source,DateTime) values (%s,%s,%s,%s,%s,%s,%s)"
        val=(iD,domain,description,tname,tgrp,src,date)
        mycursor.execute(sql,val)
        mydb.commit()
