# Canevas de proposition de valeur : installation sur OVH

L'application tient dans ce dossier.

- **Inscription :** l'adresse e-mail est validée par un code, puis chacun choisit son mot de passe et reçoit une clé de secours.
- **Connexion :** adresse e-mail + mot de passe.
- **Chiffrement :** les canevas et les adresses sont chiffrés dans le navigateur avec une clé issue du mot de passe. Le fichier de données ne contient aucune adresse ni aucun contenu lisible, y compris pour l'administrateur du site.
- **Partage :** chaque canevas n'est visible que par son créateur et les adresses qu'il ajoute.

## 0. Remplacer les repères

Les fichiers publiés contiennent des repères à remplacer par vos propres valeurs :

| Repère | À remplacer par | Fichiers |
| --- | --- | --- |
| `ADRESSE-DU-SITE` | l'adresse de votre site, sans `https://` | `config.sample.php`, `.htaccess` (si vous activez le renvoi) |
| `DOSSIER-DES-DONNEES` | le nom du dossier qui contiendra la base et la clé des empreintes (renommez aussi le dossier fourni, avec son `.htaccess`) | `api.php`, `config.sample.php`, `.htaccess` |
| `NOM DE L’ÉDITEUR` | le nom de l'éditeur du site, affiché dans les pages légales | `index.html` (ou `build/parts/app.js` avant reconstruction) |
| `contact@ADRESSE-DU-SITE` | l'adresse e-mail de contact des pages légales | `index.html` (ou `build/parts/app.js`) |
| `UTILISATEUR/DEPOT` | le chemin de votre dépôt GitHub, pour la page « Code source » | `index.html` (ou `build/parts/app.js`) |

Après une modification de `build/parts/`, reconstruisez `index.html` : `python3 build/make_app.py build/canevas-proposition-valeur.html index.html`.

## 1. Préparer config.php

1. Copiez `config.sample.php` en `config.php`.
2. Dans `config.php`, renseignez :
   - `APP_URL` : l'adresse de l'application, par exemple `https://ADRESSE-DU-SITE/`.
   - `CONTACT_RGPD` : facultatif. Adresse de contact pour les demandes sur les données personnelles.
   - `SMTP_USER` : l'adresse complète de la boîte OVH qui envoie les codes.
   - `SMTP_PASS` : le mot de passe de cette boîte. Ne le transmettez à personne.
3. Laissez la base sur SQLite. Le fichier `DOSSIER-DES-DONNEES/canevas.sqlite` est créé tout seul au premier usage, ainsi que `DOSSIER-DES-DONNEES/empreintes.key`, la clé qui sert à calculer les empreintes d'adresses.

## 2. Envoyer les fichiers par FTP

Le dossier `fonts` contient la police Inter (licence SIL Open Font License, jointe), utilisée par tout le site.

Le dossier `img` contient les icônes du site (onglet du navigateur, écran d’accueil iPhone et Android) et le fichier `site.webmanifest`.

Envoyez tout le contenu de ce dossier dans le dossier racine du sous-domaine (par exemple `DOSSIER-DU-SITE`), en remplaçant les fichiers existants. Ne touchez pas à `config.php` ni au dossier des données (`DOSSIER-DES-DONNEES`) déjà en ligne. Pensez aux fichiers qui commencent par un point (`.htaccess` et `DOSSIER-DES-DONNEES/.htaccess`) : certains logiciels FTP les masquent.

## 3. Vérifier

1. Ouvrez `https://ADRESSE-DU-SITE/api.php?a=check`. La réponse doit contenir `"ok":true` et une version PHP 8.0 ou plus. En dessous de 8.0, réglez la version PHP du site dans l'espace client OVH ou dans le fichier `.ovhconfig` à la racine FTP.
2. Ces adresses doivent être refusées (erreur 403 ou 404) :
   - `https://ADRESSE-DU-SITE/config.php`
   - `https://ADRESSE-DU-SITE/DOSSIER-DES-DONNEES/canevas.sqlite`
   - `https://ADRESSE-DU-SITE/DOSSIER-DES-DONNEES/empreintes.key`
3. Ouvrez `https://ADRESSE-DU-SITE/`, cliquez sur « Créer un compte » et vérifiez que le code arrive.

## Utilisation

- **Nouveau canevas** depuis « Mes canevas ».
- **Collaborer**, dans le menu :
  - Choisissez le canevas, tapez les adresses : chaque adresse complète devient une bulle bleue (validée par Entrée, une virgule ou un espace ; un collage de plusieurs adresses, même au format « Nom <adresse> », est découpé tout seul). Touchez une bulle puis Effacer, ou son ×, pour la retirer. Choisissez « Lecture seule » ou « Peut modifier », puis « Inviter ». Chaque personne reçoit un e-mail avec le lien.
  - « Vos collaborateurs » liste toutes les personnes invitées, sur tous vos canevas, avec leur statut (« Invitation envoyée », « En attente » ou « Accès actif ») et leur droit, modifiable. Seul le créateur d'un canevas peut inviter ou retirer quelqu'un.
  - Si la personne n'a pas encore de compte, son accès est finalisé automatiquement la prochaine fois que le créateur ouvre cette page, le canevas ou sa liste, après qu'elle a créé son compte.
  - « Retirer » coupe l'accès à un canevas, « Retirer de tous les canevas » à tous ; chaque canevas concerné est rechiffré avec une nouvelle clé.
- **Mon compte :**
  - changer de mot de passe ;
  - « Me déconnecter de partout » ;
  - supprimer le compte, après confirmation par un code.
- **Mot de passe oublié :**
  - Avec la clé de secours, tout est conservé.
  - Sans elle, le compte repart vide : les canevas de la personne sont perdus, personne ne peut les déchiffrer.
- **Collaboration en direct :** quand un canevas est partagé et ouvert, l'application vérifie discrètement s'il a changé (toutes les 2 secondes après une activité, puis jusqu'à toutes les 15 secondes au calme, et jamais dans un onglet masqué). Une bulle bleue annonce « … a modifié le canevas » ; la flèche ↻ met le canevas à jour sur place, les pastilles glissant vers leur nouvelle place. Si deux personnes enregistrent en même temps, les modifications sont fusionnées pastille par pastille ; sur un même élément modifié des deux côtés, la version de la personne qui enregistre est gardée et elle en est prévenue.

## Pied de page et pages légales

- Le pied de page, en bas de chaque écran, donne accès aux mentions légales, à la politique de confidentialité, aux conditions d'utilisation et à la page « Code source ».
- Le bouton « English » / « Français » change la langue de ces pages et du pied de page. Le choix est gardé dans le navigateur.
- Les textes sont dans `index.html`, dans la partie « Pages légales et pied de page ».
- **Code source :** la page renvoie vers le dépôt GitHub (github.com/UTILISATEUR/DEPOT) et son paquet à télécharger. Rien n'est lu en direct sur le serveur.

## Sécurité intégrée

- **Mot de passe :**
  - Il ne quitte jamais le navigateur : il y est transformé en deux clés, avec PBKDF2-SHA-256 et 600 000 itérations.
  - Le serveur garde seulement un hachage de la clé de connexion.
  - Après 10 essais ratés, le compte est bloqué 15 minutes.
- **Codes reçus par e-mail :**
  - valables 15 minutes ;
  - 5 essais au plus ;
  - un nouveau code par minute et par adresse ;
  - 60 codes par heure au plus depuis une même connexion.
- **Inscription :** une inscription non terminée est annulée à la fermeture du navigateur, ou 3 minutes après la validation du code.
- **Session :** 7 jours. La suppression du compte et le nouveau départ exigent un code reçu dans les 3 dernières minutes.
- **Partage :** 50 adresses par canevas au plus, et 30 invitations par heure et par personne.

## Sauvegarde

Les données sont dans `DOSSIER-DES-DONNEES/canevas.sqlite`, et la clé des empreintes dans `DOSSIER-DES-DONNEES/empreintes.key`.

- Sauvegardez les deux fichiers ensemble par FTP.
- Sans `empreintes.key`, plus personne ne peut se connecter : les adresses ne seraient plus reconnues.
- Les canevas restent chiffrés dans la sauvegarde.

## Si vous préférez MySQL

Créez une base dans l'espace client OVH, exécutez `schema.sql` dans phpMyAdmin, puis remplacez les trois lignes `DB_` de `config.php` par celles en commentaire.
