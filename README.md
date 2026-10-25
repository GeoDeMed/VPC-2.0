# Canevas de proposition de valeur

Outil en ligne pour remplir, partager et exporter des canevas de proposition de valeur, conçu pour un module de cours de Design Thinking. Il est réservé aux personnes qui ont un compte sur le site où il est installé.

Ce dépôt publie le code en service pour que chacun puisse vérifier ce qu'il fait des données, et pour que chacun puisse l'installer. Les adresses, le nom de l'éditeur et l'emplacement des fichiers y sont remplacés par des repères (voir `LISEZMOI.md`).

## Ce que fait le code

- **Chiffrement dans le navigateur :** le mot de passe ne quitte jamais le navigateur. Il y produit, avec PBKDF2-SHA-256 (600 000 itérations), une clé de chiffrement et une clé de connexion. Les canevas, leurs titres et les adresses de partage sont chiffrés avec AES-256-GCM avant l'envoi. Le partage passe par un échange de clés ECDH P-256.
- **Serveur :** `api.php` (PHP 8, SQLite) ne stocke que du texte chiffré, des empreintes d'adresses (HMAC-SHA-256) et le hachage de la clé de connexion. Chaque requête vers la base y est lisible.

## Vérifier la version en ligne

Le site ne lit rien en direct sur son serveur pour cette vérification : ce dépôt est la référence. Le fichier `index.html` du dépôt est celui du site, à trois mentions près : le nom de l'éditeur, l'adresse de contact et l'adresse du dépôt y sont remplacés par des repères. Pour comparer :

```sh
curl -s https://ADRESSE-DU-SITE/index.html -o en-ligne.html
diff en-ligne.html index.html
```

Seules les lignes qui contiennent ces trois mentions doivent différer.

## Fichiers

| Fichier | Rôle |
| --- | --- |
| `index.html` | Toute l'interface et le chiffrement |
| `api.php` | L'API côté serveur |
| `.htaccess`, `DOSSIER-DES-DONNEES/.htaccess` | HTTPS obligatoire, fichiers internes inaccessibles |
| `schema.sql` | Tables pour MySQL (SQLite crée les siennes seul) |
| `config.sample.php` | Modèle de réglages. Le vrai `config.php` n'est jamais publié |
| `fonts/` | Police Inter et sa licence |
| `img/` | Icônes (onglet, iPhone, Android) et `site.webmanifest` |
| `build/` | Sources de `index.html` |
| `LISEZMOI.md` | Notice d'installation |

## Reconstruire index.html

```sh
python3 build/make_app.py build/canevas-proposition-valeur.html index.html
```

Le résultat est identique, octet pour octet, au fichier `index.html` du dépôt.

## Licences

- Code : GNU General Public License v3 (voir `LICENSE`).
- Police Inter : SIL Open Font License 1.1 (voir `fonts/LICENSE-Inter.txt`).
- Le Value Proposition Canvas est une création de Strategyzer AG ([Strategyzer.com](https://www.strategyzer.com)). La licence du code ne s'applique pas au canevas lui-même.

Copyright © 2023-2026 Georges-Étienne Breton. Quorelix® est une marque déposée. Contact : georges-etienne.breton@quorelix.com
