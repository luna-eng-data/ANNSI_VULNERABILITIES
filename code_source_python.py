# -*- coding: utf-8 -*-
"""
Created on Sat Jan 18 21:03:54 2025

@author: DELL
"""

import feedparser
import pandas as pd
import requests
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import re
import time
from time import sleep
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import csv
from dotenv import load_dotenv
import os
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
import warnings
warnings.filterwarnings('ignore')

#fonction pour recuperer les flux RSS à partir des URLs
def get_rss_feeds(url):
     """
    Extraire les flux RSS depuis une URL
    Args:
        url (str): URL du flux RSS
        delay (int): Délai entre les requêtes en secondes
    Returns:
        list: Liste de dictionnaires contenant les entrées du flux
    """
     feeds = []
     try:
         rss_feed = feedparser.parse(url)
         for entry in rss_feed.entries:
            feed_data = {
                'title': entry.title,
                'description': entry.description,
                'link': entry.link,
                'date': entry.published,
                'type': 'Alerte' if 'alerte' in entry.link.lower() else 'Avis'
            }
            feeds.append(feed_data)
            
     except Exception as e:
        print(f"Error fetching RSS feed: {e}")
     return feeds
 
#fontion pour extraire les CVE à partir du JSON de chaque lien
def get_cves_from_json(url):
    """
    Extraire les CVE depuis une URL JSON
    Args:
        url (str): URL du JSON
        delay (int): Délai entre les requêtes en secondes
    Returns:
        list: Liste des identifiants CVE
    """
    json_url = f"{url}/json/"
    try:
        response = requests.get(json_url)
        data = response.json()
        ref_cves = [cve['name'] for cve in data.get('cves', [])]
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        all_cves = list(set(re.findall(cve_pattern, str(data))))
        
        
        return list(set(ref_cves + all_cves))
    except Exception as e:
        print(f"Error fetching CVEs from JSON: {e}")
        return []
    
#fonction pour recuperer les details de CVE depuis l'API MITRE
def get_cve_details(cve_id):
    """
    Récupérer les détails d'une CVE depuis l'API MITRE
    Args:
        cve_id (str): Identifiant CVE
        delay (int): Délai entre les requêtes en secondes
    Returns:
        dict: Dictionnaire contenant les détails de la CVE
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url)
        data = response.json()
        
       
        containers = data.get('containers', {}).get('cna', {})
           
        descriptions = containers.get('descriptions', [])
        description = descriptions[0].get('value') if descriptions else "Not available"
       
        metrics = containers.get('metrics', [])
        cvss_score = None
        severity = "Not available"
        all_metrics=[]
        for metric in metrics:
            if 'cvssV3_1' in metric:
                cvss_score = metric['cvssV3_1'].get('baseScore')
                severity = metric['cvssV3_1'].get('baseSeverity')
            elif 'cvssV3_0' in metric:
                cvss_score = metric['cvssV3_0'].get('baseScore')
                severity = metric['cvssV3_0'].get('baseSeverity')
                
           
        
       
        problemtype = containers.get('problemTypes', [])
        cwe = "Not available"
        cwe_desc = "Not available"
        if problemtype and 'descriptions' in problemtype[0]:
            cwe = problemtype[0]['descriptions'][0].get('cweId', "Not available")
            cwe_desc = problemtype[0]['descriptions'][0].get('description', "Not available")
        
    
        affected_products = []
        for product in containers.get('affected', []):
            vendor = product.get('vendor', "Unknown")
            product_name = product.get('product', "Unknown")
            versions = [v.get('version', "Unknown") for v in product.get('versions', []) 
                       if v.get('status') == "affected"]
            affected_products.append({
                'vendor': vendor,
                'product': product_name,
                'versions': versions
            })
        
        
        
        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'severity': severity,
            'cwe': cwe,
            'cwe_description': cwe_desc,
            'affected_products': affected_products
        }
    except Exception as e:
        print(f"Error fetching CVE details: {e}")
        return None
    
#fonction pour recuperer le score EPSS d'une CVE via l'API EPSS
def get_epss_score(cve_id):
    """
    Obtenir le score EPSS depuis l'API FIRST
    Args:
        cve_id (str): Identifiant CVE
        delay (int): Délai entre les requêtes en secondes
    Returns:
        float: Score EPSS
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url)
        data = response.json()
        epss_data = data.get("data", [])
        
        
        
        if epss_data:
            return epss_data[0].get("epss")
        return None
    except Exception as e:
        print(f"Error fetching EPSS score: {e}")
        return None
    
#fonction principale pour traiter les données de vulnérabilités et creer le dataframe
def recuperer_score_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url)
    data = response.json()
    epss_data = data.get("data", [])
    if epss_data:
        return epss_data[0]["epss"]
    else:
        print(f"Aucun score EPSS trouvé pour {cve_id}")
        return None
    
def process_vulnerability_data(rss_urls):
    # Charger les données existantes si elles existent
    try:
        df_existing = pd.read_csv('mes_donnees_vulnerabilites.csv', on_bad_lines='skip')
        print("Fichier existant chargé avec succès.")
        print("Colonnes disponibles :", df_existing.columns)
    except FileNotFoundError:
        print("Fichier 'mes_donnees_vulnerabilites.csv' introuvable. Initialisation d'un DataFrame vide.")
        df_existing = pd.DataFrame(columns=['cve_id', 'link'])  # Initialiser avec les colonnes nécessaires

    # Vérifier si les colonnes nécessaires sont présentes
    if df_existing.empty or 'cve_id' not in df_existing.columns:
        print("Initialisation des colonnes nécessaires.")
        df_existing = pd.DataFrame(columns=['cve_id', 'link'])

    # Collecter les nouvelles données
    all_data = []  # Liste pour stocker toutes les nouvelles vulnérabilités
    
    for url in rss_urls:
        feeds = get_rss_feeds(url)
        for feed in feeds:
            cves = get_cves_from_json(feed['link'])
            for cve_id in cves:
                cve_details = get_cve_details(cve_id)
                epss_score = get_epss_score(cve_id)
                
                if cve_details:  # Si des détails sur le CVE sont disponibles
                    for product in cve_details['affected_products']:
                        data_entry = {
                            'title': feed['title'],
                            'type': feed['type'],
                            'date': pd.to_datetime(feed['date'], errors='coerce'),
                            'link': feed['link'],
                            'cve_id': cve_id,
                            'description': cve_details['description'].replace("\n", ""),
                            'cvss_score': cve_details['cvss_score'],
                            'severity': cve_details['severity'],
                            'cwe': cve_details['cwe'],
                            'cwe_description': cve_details['cwe_description'],
                            'epss_score': epss_score,
                            'vendor': product['vendor'],
                            'product': product['product'],
                            'affected_versions': ', '.join(product['versions'])
                        }
                        # Vérifier si l'entrée existe déjà
                        if 'cve_id' in df_existing.columns and not df_existing[
                            (df_existing['cve_id'] == cve_id) &
                            (df_existing['link'] == feed['link'])
                        ].empty:
                            continue  # Passer si déjà existant
                        all_data.append(data_entry)

    # Créer un DataFrame pour les nouvelles données
    df_new_data = pd.DataFrame(all_data)

    # Concaténer les nouvelles données avec les données existantes
    df_final = pd.concat([df_existing, df_new_data], ignore_index=True)

    # Supprimer les doublons
    df_final = df_final.drop_duplicates(subset=['cve_id', 'link'])

    # Conserver uniquement les colonnes utiles
    useful_columns = ['title', 'type', 'date', 'link', 'cve_id', 'description', 'cvss_score', 'severity', 'cwe', 'cwe_description', 'epss_score', 'vendor', 'product', 'affected_versions']
    df_final = df_final[useful_columns]

    # Supprimer les lignes avec des informations inutiles
    df_final = df_final[df_final['description'] != 'Not available']
    df_final = df_final[df_final['vendor'] != 'Unknown']
    df_final = df_final[df_final['product'] != 'Unknown']
    df_final = df_final[df_final['affected_versions'] != '']
    
    return df_final

rss_urls = [
    "https://www.cert.ssi.gouv.fr/avis/feed",
    "https://www.cert.ssi.gouv.fr/alerte/feed"
]


print("Début de la collection des données...")
df_vulnerabilities = process_vulnerability_data(rss_urls)


print("Enregistrement CSV...")
if not df_vulnerabilities.empty:
    print(df_vulnerabilities.head()) 
    df_vulnerabilities.to_csv('mes_donnees_vulnerabilites.csv', index=False,encoding="utf-8-sig")
    print("Enregistré avec Succès!")
else:
    print("le Dataframe est vide")

print("\nBasic Statistics:")
print(f"Nombre total de vulnérabilités: {len(df_vulnerabilities)}")
print(f"Nombre de CVEs unisques: {df_vulnerabilities['cve_id'].nunique()}")
print(f"Nombre de vendeurs uniques: {df_vulnerabilities['vendor'].nunique()}")

# Charger les données depuis un fichier CSV
df = pd.read_csv('mes_donnees_vulnerabilites.csv')
df_vulnerabilities['cvss_score'] = pd.to_numeric(df_vulnerabilities['cvss_score'], errors='coerce')
df_vulnerabilities['epss_score'] = pd.to_numeric(df_vulnerabilities['epss_score'], errors='coerce')
#filtrer les données ou 'cvss_score' n'est pas NAN
df_vulnerabilities_clean=df_vulnerabilities.dropna(subset=['cvss_score'])

def send_email(to_email, subject, body):
    from_email = "e90450884@gmail.com"
    password = "nascuyzjeiohoczh"
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()


individus = [
    {"nom": "Individu1", "préférence": "Microsoft", "mail": "cexpediteur80104485@gmail.com"},
    
]

# Charger le fichier CSV contenant les vulnérabilités
df_vulnerabilities['date'] = pd.to_datetime(df_vulnerabilities['date'])
donnees_trie = df_vulnerabilities.sort_values(by='date', ascending=False)

for elt in individus:
    for index, row in donnees_trie.iterrows():
        if row['severity'] == "CRITICAL" and row['vendor'] == elt["préférence"]:
            body = f"Une vulnérabilité critique a été détectée\nCVE ID : {row['cve_id']}\nProduit affecté : {row['product']}\nMettez à jour votre serveur {elt['préférence']} immédiatement"
            send_email(elt["mail"], "Alerte CVE critique", body)
            break
