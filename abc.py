# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
apikey='6ff13ffbc41a6c8f2b76f2c008a2d8d3036e5529e647ed7bc309541ebee05fe9'
import os
import requests
def scanRequest(apikey,url):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': apikey, 'url':url}
    response = requests.post(url, data=params)
    return (response)

def reportScan(apikey,resource):

    url = 'https://www.virustotal.com/vtapi/v2/url/report'

    params = {'apikey': apikey, 'resource':resource}

    response = requests.get(url, params=params)
    print(response.json())
    return(response)
def isSiteExist(conn, url):
    sql = "select * from sites where url=%s;"   
    site = (url, )
    mycursor = conn.cursor()
    mycursor.execute(sql, site)
    row = mycursor.fetchone()
    if row == None:
        return None
    return row[1]
def isSiteTestedWithinTimeframe(conn, url, minutes=30):
    sql = "select * from site_scan >  where url=%s;"   
    site = (url, )
    mycursor = conn.cursor()
    mycursor.execute(sql, site)
    row = mycursor.fetchone()
    if row == None:
        return None
    return row[1]

from psycopg2 import Error
import psycopg2
try:
    connection = psycopg2.connect(user = "postgres",
                                      password = "postgres",
                                      host = "127.0.0.1",
                                      port = "5432",
                                      database = "postgres")
    print("You are connected")
except (Exception, psycopg2.Error) as error :
    print ("Error while connecting to PostgreSQL", error)
    
import os
import pandas as pd
all_sites=pd.DataFrame()
for file in os.listdir("."):
    if file.endswith(".csv"):
        print(os.path.join("./", file))
        all_sites=all_sites.append(pd.read_csv(file,  header=None))
all_sites.columns=['url']
all_sites=all_sites.drop_duplicates()

all_sites['exist']=all_sites.url.apply(lambda x: isSiteExist(connection, x))

newSites=all_sites[all_sites['exist'].isna()]
newSites['resource']=newSites.apply(lambda x: scanRequest(apikey,x).json()['scan_id'])

#lack of time. i would continue from here to insert new sites
#add to new site the sites that havent been checked for the last 30 minutes
#invoke all the sites using reportScan (doing all checks, etc...)
#insert the results to table site_scan
#and commit...



#print(all_sites['exist'])
#if (all_sites['exist'])
#print(isSiteExist(connection, 'amit'))

        
        
    