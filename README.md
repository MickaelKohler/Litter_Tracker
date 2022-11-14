# Litter_Tracker

Le projet L.I.T.T.E.R. Tracker vise à créer une REST API qui permette d'accéder à un modèle de Deep Learning capable de classficier différents déchets dans l'une des 7 catégories recyclables. 

## Sommaire

* [Cadre du projet](#cadre-du-projet)
* [Technologies](#technologies)
* [Déploiement](#deploiment)
* [Statut](#statut)

## Origine du projet

Le but du projet est de démontrer l'apport des réseaux de neurones dans le traitement des déchets. 

Le projet a été développé dans le cadre du passage de la Certification Développeur d'Application et se compose de plusieurs couches : 
- Un *modèle de Deep Learning* de reconnaissance d'images par ordinateur,
- Une *REST API* permettant de requêter facilement le modèle. Les profils utilisateurs sont gérés,
- Une *base de données SQL* permettant de connaitre les performances du modèle afin de l'améliorer.

Les différents fichiers sont Open Source et peuvent être montés dans un *conteneur Docker*. 

Pour donner un exemple d'utilisation de l'API, une WebApp a été développée avec le framework Anvil[^1] pour permettre à tout utilisateur t'interagir facilement avec l'API et la base de données. 

## Technologies 

Le modèle de Deep Learning est un modèle VGG16 de type Convolutional Neural Network, développé avec **Tensorflow**. 

La REST API est développée avec le micro-framework **Flask** et comporte 18 endpoints.

La base de données est construite sur la base du système de gestion de base de données relationnelle et objet **PostgreSQL**

## Deploiment 

*Pré-requis* : 
1. Modifier les variables d'environnement pour configurer l'accès au serveur SMTP et la clée secrête JSON Web Token. 
2. Modifier l'adresse d'accès de l'API dans le token du mail de récupération de mot de passes.
3. Avoir Docker et Docker-compose installé dans l'environnement. 

Pour déployer l'API télécharger l'ensemble des fichiers et dans le dossier racine et exécutez les commandes docker suivantes : 
```
docker-compose build
docker-compose up
```
Trois conteneurs seront créés et assemblés pour lancée l'API et la base de données, ainsi que le back-end de l'application Anvil.

## Statut

La version 1 a été rendue disponible le 14/11/2022

[^1]: https://anvil.works/