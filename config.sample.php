<?php
// Copiez ce fichier en config.php, puis remplissez les valeurs.

// Adresse publique de l'application, utilisée dans les e-mails d'invitation.
const APP_URL = 'https://ADRESSE-DU-SITE/';

// Domaine autorisé. Laissez vide ('') pour accepter toutes les adresses e-mail.
const ALLOWED_DOMAIN = '';

// Contact affiché dans la mention « Données personnelles » (adresse e-mail du responsable du site).
const CONTACT_RGPD = '';

// Boîte e-mail OVH qui envoie les codes (réglages SMTP de la documentation OVH MX Plan).
const SMTP_HOST = 'ssl0.ovh.net';
const SMTP_PORT = 465;
const SMTP_USER = 'adresse@votre-domaine.fr';
const SMTP_PASS = 'MOT_DE_PASSE_DE_LA_BOITE';
const MAIL_FROM_NAME = 'Canevas de proposition de valeur';

// Base de données SQLite : un simple fichier, créé automatiquement dans le dossier des données (fermé au web).
const DB_DSN = 'sqlite:' . __DIR__ . '/DOSSIER-DES-DONNEES/canevas.sqlite';
const DB_USER = null;
const DB_PASS = null;

// Pour MySQL à la place : créez la base chez OVH, exécutez schema.sql dans phpMyAdmin, puis utilisez :
// const DB_DSN = 'mysql:host=SERVEUR_MYSQL;port=3306;dbname=NOM_DE_LA_BASE;charset=utf8mb4';
// const DB_USER = 'UTILISATEUR';
// const DB_PASS = 'MOT_DE_PASSE';
