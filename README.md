# Installation
```
python -m venv <NOM_ENVIRONNEMENT_VIRTUEL>
source <NOM_ENVIRONNEMENT_VIRTUEL>/bin/activate
git clone https://github.com/yapoc/certstream-server.git
cd certstream-server
pip install -r requirements.txt
```

# Utilisation, Exemples et Références

Pour toute question non référencée ici, consulter la [documentation d'origine du projet](https://github.com/CaliDog/certstream-python).

## Lancement sans proxy
```
source <NOM_ENVIRONNEMENT_VIRTUEL>/bin/activate
cd certstream-server
python run_server.py
```

## Lancement derrière un proxy
```
source <NOM_ENVIRONNEMENT_VIRTUEL>/bin/activate
cd certstream-server
python run_server.py --proxy-string "http[s]://[login[:mot_de_passe]@]proxy_host[:port]"
```

## Lancement intégrant un dossier de pérénisation des informations récupérées
```
source <NOM_ENVIRONNEMENT_VIRTUEL>/bin/activate
cd certstream-server
python run_server.py --persistance-folder <DOSSIER_DANS_LEQUEL_ON_SOUHAITE_STOCKER_LES_INDEX>
```
