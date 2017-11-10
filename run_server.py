import certstream
import argparse

parser = argparse.ArgumentParser(description='Lancement du serveur collectant les Certificates Transparency')
parser.add_argument('--proxy-string', required = False, help = 'Adresse du proxy', default = None)
parser.add_argument('--persistance-folder', required = False, help = 'Chemin du dossier de persistance.', default = None)
args = parser.parse_args()

certstream.run(proxy_string = args.proxy_string, persistance_folder = args.persistance_folder)
