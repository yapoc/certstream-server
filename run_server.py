import certstream
import argparse

parser = argparse.ArgumentParser(description='Lancement du serveur collectant les Certificates Transparency')
parser.add_argument('--proxy-string', required = False, help = 'Adresse du proxy', default = None)
args = parser.parse_args()

certstream.run(proxy_string = args.proxy_string)
