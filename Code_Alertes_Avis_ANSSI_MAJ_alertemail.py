import os
import feedparser
import pandas as pd
import requests
import re
import smtplib
from email.mime.text import MIMEText
import ssl
ssl._create_default_https_context = ssl._create_unverified_context


# Fonctions pour extraire les CVE d'une description
def extract_cve(description):
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    return re.findall(cve_pattern, description)

def extract_cve_from_json(url):
    json_url = url + "/json/"
    response = requests.get(json_url)
    if response.status_code == 200:
        data = response.json()
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        return list(set(re.findall(cve_pattern, str(data))))
    return []

def extract_all_cves(row):
    cve_json_list = extract_cve_from_json(row['Lien'])
    cve_list = extract_cve(row['Description'])
    return list(set(cve_list + cve_json_list))

# Fonction pour obtenir la description d'un CVE
def get_cve_description(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    data = response.json()
    if "containers" in data and "cna" in data["containers"] and "descriptions" in data["containers"]["cna"]:
        return data["containers"]["cna"]["descriptions"][0]["value"]
    else:
        return "Description non disponible"

# Fonction pour obtenir les détails d'un CVE
def get_cve_details(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        cvss_score = None
        cwe = "Non disponible"
        cwe_desc = "Non disponible"
        affected_products = []

        # Extraire le score CVSS
        if "containers" in data and "cna" in data["containers"] and "metrics" in data["containers"]["cna"]:
            metrics = data["containers"]["cna"]["metrics"][0]
            if "cvssV3_0" in metrics:
                cvss_score = metrics["cvssV3_0"]["baseScore"]
            elif "cvssV3_1" in metrics:
                cvss_score = metrics["cvssV3_1"]["baseScore"]
            elif "cvssV4_0" in metrics:
                cvss_score = metrics["cvssV4_0"]["baseScore"]

        # Extraire le type CWE et sa description
        problemtype = data["containers"]["cna"].get("problemTypes", {})
        if problemtype and "descriptions" in problemtype[0]:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")

        # Extraire les produits affectés
        affected = data["containers"]["cna"].get("affected", [])
        for product in affected:
            vendor = product.get("vendor", "Non disponible")
            product_name = product.get("product", "Non disponible")
            versions = [v["version"] for v in product.get("versions", []) if v.get("status") == "affected"]
            affected_products.append(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")

        return cvss_score, cwe, cwe_desc, affected_products
    return None, "Non disponible", "Non disponible", []

# Fonction pour séparer les produits affectés en colonnes distinctes
def split_affected_products(row):
    editeurs = []
    produits = []
    versions_list = []

    for entry in row:
        editeur = re.search(r"Éditeur\s*:\s*([^,]+)", entry)
        produit = re.search(r"Produit\s*:\s*([^,]+)", entry)
        versions = re.search(r"Versions\s*:\s*(.+)", entry)

        editeurs.append(editeur.group(1) if editeur else "Non disponible")
        produits.append(produit.group(1) if produit else "Non disponible")
        if versions:
            versions_split = [v.strip() for v in versions.group(1).split(",")]
            versions_list.extend(versions_split)
        else:
            versions_list.append("Non disponible")

    editeurs = ", ".join(sorted(set(editeurs)))
    produits = ", ".join(sorted(set(produits)))
    versions_list = ", ".join(sorted(set(versions_list)))

    return pd.Series([editeurs, produits, versions_list])

# Fonction pour envoyer un email
def send_email(to_email, subject, body):
    from_email = "leontine.quenupro@gmail.com"
    password = "zpkx ifng jotd lbrm"

    msg = MIMEText(body, "plain", "utf-8")
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()

# Fonction pour générer le contenu de l'email
def generate_alert_email(entry):
    email_subject = f"[ALERTE] {entry['Titre']}"
    email_body = f"""
    Un nouvel avis/alerte a été détecté :

    - Titre : {entry['Titre']}
    - Description : {entry['Description']}
    - Lien : {entry['Lien']}
    - Date : {entry['Date']}
    - Type : {entry['Type']}
    """
    return email_subject, email_body

# Fonction principale
def Avis_Alertes_ANSSI(csv_path='alerte_avis.csv'):
    if os.path.exists(csv_path):
        print("Fichier CSV existant trouvé du dataframe ANSSI.")

        # Charger le CSV existant
        df = pd.read_csv(csv_path)

        # Récupération des flux RSS
        url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"
        url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed"
        rss_feed_avis = feedparser.parse(url_avis)
        rss_feed_alerte = feedparser.parse(url_alerte)

        feed_avis = [entry.title for entry in rss_feed_avis.entries]
        feed_alerte = [entry.title for entry in rss_feed_alerte.entries]

        titres_df = set(df['Titre'].unique())

        titres_avis_absents = [titre for titre in feed_avis if titre not in titres_df]
        titres_alerte_absents = [titre for titre in feed_alerte if titre not in titres_df]
        print("Le nombre de titres avis manquants est de :", len(titres_avis_absents))
        print("Le nombre de titres alerte manquants est de :", len(titres_alerte_absents))

        # Demande d'une adresse Gmail valide
        while True:
            destinataire = input("Veuillez entrer une adresse Gmail pour avoir les nouveaux bulletins ANSSI : ")
            if destinataire.endswith("@gmail.com"):
                break
            print("Adresse invalide. Veuillez entrer une adresse Gmail valide.")

        # Début de l'ajout des avis manquants dans le dataframe
        if len(titres_avis_absents) > 0:
            avis_manquants_data = [
                {
                    'Titre': entry.title,
                    'Description': entry.description,
                    'Lien': entry.link,
                    'Date': entry.published,
                    'Type': 'Avis'
                }
                for entry in rss_feed_avis.entries if entry.title in titres_avis_absents
            ]
            df_avis_manquants = pd.DataFrame(avis_manquants_data)

            # Envoi d'email pour les nouveaux avis ANSSI 
            for entry in avis_manquants_data:
                subject, body = generate_alert_email(entry)
                send_email(destinataire, subject, body)
                print(f"Email envoyé pour l'avis : {entry['Titre']}")

            # Enrichissement des avis manquants
            df_avis_manquants['CVE_list'] = df_avis_manquants.apply(extract_all_cves, axis=1)
            df_avis_expanded = df_avis_manquants.explode('CVE_list').reset_index(drop=True)
            df_avis_expanded = df_avis_expanded.rename(columns={'CVE_list': 'CVE'})
            df_avis_expanded['Description_CVE'] = df_avis_expanded['CVE'].apply(get_cve_description)
            df_avis_expanded[['CVSS_Score', 'CWE', 'CWE_Description', 'Produits_Affectés']] = df_avis_expanded['CVE'].apply(
                lambda x: pd.Series(get_cve_details(x)))
            df_avis_expanded[['Éditeur', 'Produit', 'Versions']] = df_avis_expanded['Produits_Affectés'].apply(split_affected_products)
            df_avis_expanded = df_avis_expanded.drop(columns=['Produits_Affectés'])

            # Ajout au DataFrame existant
            df = pd.concat([df, df_avis_expanded], ignore_index=True)

        # Début de l'ajout des alertes manquantes dans le dataframe
        if len(titres_alerte_absents) > 0:
            alerte_manquants_data = [
                {
                    'Titre': entry.title,
                    'Description': entry.description,
                    'Lien': entry.link,
                    'Date': entry.published,
                    'Type': 'Alerte'
                }
                for entry in rss_feed_alerte.entries if entry.title in titres_alerte_absents
            ]
            df_alerte_manquants = pd.DataFrame(alerte_manquants_data)

            # Envoi d'email pour les nouvelles alertes ANSSI
            for entry in alerte_manquants_data:
                subject, body = generate_alert_email(entry)
                send_email(destinataire, subject, body)
                print(f"Email envoyé pour l'alerte : {entry['Titre']}")

            # Enrichissement des alertes manquantes
            df_alerte_manquants['CVE_list'] = df_alerte_manquants.apply(extract_all_cves, axis=1)
            df_alerte_expanded = df_alerte_manquants.explode('CVE_list').reset_index(drop=True)
            df_alerte_expanded = df_alerte_expanded.rename(columns={'CVE_list': 'CVE'})
            df_alerte_expanded['Description_CVE'] = df_alerte_expanded['CVE'].apply(get_cve_description)
            df_alerte_expanded[['CVSS_Score', 'CWE', 'CWE_Description', 'Produits_Affectés']] = df_alerte_expanded['CVE'].apply(
                lambda x: pd.Series(get_cve_details(x)))
            df_alerte_expanded[['Éditeur', 'Produit', 'Versions']] = df_alerte_expanded['Produits_Affectés'].apply(split_affected_products)
            df_alerte_expanded = df_alerte_expanded.drop(columns=['Produits_Affectés'])

            # Ajout au DataFrame existant
            df = pd.concat([df, df_alerte_expanded], ignore_index=True)

        # Sauvegarder le DataFrame mis à jour
        df.to_csv(csv_path, index=False)
        print("Mise à jour du fichier CSV terminée.")

    else:
        print("Aucun fichier CSV existant. Création du DataFrame initial...")

        # Récupération des flux RSS
        url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"
        url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed"
        rss_feed_avis = feedparser.parse(url_avis)
        rss_feed_alerte = feedparser.parse(url_alerte)

        avis_data = [
            {
                'Titre': entry.title,
                'Description': entry.description,
                'Lien': entry.link,
                'Date': entry.published,
                'Type': 'Avis'
            }
            for entry in rss_feed_avis.entries
        ]

        alerte_data = [
            {
                'Titre': entry.title,
                'Description': entry.description,
                'Lien': entry.link,
                'Date': entry.published,
                'Type': 'Alerte'
            }
            for entry in rss_feed_alerte.entries
        ]

        # Création du DataFrame combiné
        df_avis = pd.DataFrame(avis_data)
        df_alerte = pd.DataFrame(alerte_data)
        df_combined = pd.concat([df_avis, df_alerte], ignore_index=True)

        # Enrichissement initial
        df_combined['CVE_list'] = df_combined.apply(extract_all_cves, axis=1)
        df_expanded = df_combined.explode('CVE_list').reset_index(drop=True)
        df_expanded = df_expanded.rename(columns={'CVE_list': 'CVE'})
        df_expanded['Description_CVE'] = df_expanded['CVE'].apply(get_cve_description)
        df_expanded[['CVSS_Score', 'CWE', 'CWE_Description', 'Produits_Affectés']] = df_expanded['CVE'].apply(
            lambda x: pd.Series(get_cve_details(x)))
        df_expanded[['Éditeur', 'Produit', 'Versions']] = df_expanded['Produits_Affectés'].apply(split_affected_products)
        df_expanded = df_expanded.drop(columns=['Produits_Affectés'])

        # Sauvegarder le DataFrame dans le fichier CSV
        df_expanded.to_csv(csv_path, index=False)
        print("Création du dataframe sous format CSV créé.")
