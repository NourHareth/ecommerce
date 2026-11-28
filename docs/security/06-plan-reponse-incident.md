# Plan de réponse à incident (§4.7)

Ce plan s'applique à la boutique AmCart déployée sur le cluster de l'équipe (minikube sur la VM). Il
suit les cinq phases demandées : **détecter, contenir, éradiquer, rétablir, apprendre**. Chaque
alerte de détection renvoie (lien `runbook_url`) au scénario correspondant, en fin de document.

Principe : on **préserve les preuves avant d'agir**, on **contient avant de corriger**, et toute
correction passe par le pipeline normal (branche, test de régression, contrôles bloquants, PR). Un
correctif poussé à la main pendant un incident contournerait exactement les contrôles qui protègent
la suite.

## 1. Rôles

L'équipe est petite : une même personne peut tenir deux rôles, sauf *responsable* et *opérateur*
pendant la phase de confinement (l'un décide, l'autre exécute et note).

| Rôle | Responsabilité |
|------|----------------|
| Responsable d'incident | décide de la gravité, du confinement et de la clôture ; tient la chronologie |
| Analyste | lit les journaux et le tableau de bord, reconstitue l'attaque, préserve les preuves |
| Opérateur plateforme | exécute les actions sur le cluster et la base (suspension, rotation, redéploiement) |
| Communication | informe l'équipe et l'enseignant ; évalue avec le responsable s'il faut notifier des utilisateurs |

## 2. Niveaux de gravité

| Niveau | Définition | Exemple | Délai de confinement visé |
|--------|------------|---------|---------------------------|
| **SEV-1** | Compromission avérée : données d'un client lues ou modifiées par un tiers, secret exposé et valide, code malveillant en production | une commande d'autrui renvoyée avec 200 | 1 h |
| **SEV-2** | Attaque en cours dont l'issue est inconnue, ou réponse anormale (500, temps de réponse) à une charge malveillante | injection qui provoque des erreurs 500 | 4 h |
| **SEV-3** | Tentative détectée, bloquée par les contrôles en place, sans impact | scanner automatique, force brute refusée | 1 jour ouvré |

En cas de doute, on classe au niveau supérieur et on redescend une fois les faits établis.

## 3. Les cinq phases

### 3.1 Détecter

**Sources.**
- Alertes Loki (règles `deploy/k8s/monitoring/rules/amcart-security.yaml`), visibles dans Grafana,
  *Alerting > Alert rules*, et par `GET /prometheus/api/v1/alerts` sur Loki ;
- tableau de bord Grafana *AmCart · Sécurité* (compteurs, événements récents) ;
- pipeline CI (une vulnérabilité ou un secret détecté dans le code est aussi un incident si la
  version vulnérable est déployée) ;
- signalement d'un utilisateur : chaque réponse de l'API porte un en-tête `X-Correlation-ID`, qui
  permet de retrouver la requête exacte.

**Accès.**
```bash
kubectl -n amcart-monitoring port-forward svc/grafana 3000:3000   # http://127.0.0.1:3000, utilisateur admin
kubectl -n amcart-monitoring port-forward svc/loki 3100:3100      # API Loki, pour les exports
```

**Requêtes de tri (LogQL, Grafana > Explore ou panneau « Suivre une requête »).**

| Question | Requête |
|----------|---------|
| Quels événements de sécurité ? | `{namespace="amcart-services"} \|= "security." \| json \| State_Event=~"security[.].+"` |
| Toute la vie d'une requête (passerelle et services) | `{namespace=~"amcart-web\|amcart-services"} \|= "<correlation-id>"` |
| Tout ce qu'a fait un utilisateur | `{namespace="amcart-services"} \| json \| State_UserId="<user-id>"` |
| Erreurs serveur à la passerelle | `{namespace="amcart-web", app="ui"} \| json \| status >= 500` |

**Tri, dans les 15 minutes suivant l'alerte.**
1. Ouvrir une fiche d'incident (modèle en annexe), heure de début = heure de l'alerte.
2. Confirmer que l'alerte correspond à des événements réels (requêtes ci-dessus), et non à un test
   de l'équipe (le rejeu `tests/detection/replay-attacks.sh` et le DAST utilisent des comptes
   `dast-*@example.test` et `replay-victim-*@example.test`).
3. Fixer la gravité (tableau §2) et appliquer le scénario A, B ou C.

### 3.2 Contenir

**D'abord, préserver les preuves** (avant toute suspension ou tout redémarrage, qui effacent des
traces) :
```bash
T0=$(date -u -d '-2 hours' +%s)000000000
INC=docs/incidents/$(date -u +%F)-<sujet>; mkdir -p "$INC/preuves"
# journaux de la fenêtre, tels que stockés dans Loki
curl -sG http://127.0.0.1:3100/loki/api/v1/query_range --data-urlencode 'query={namespace=~"amcart-.+"}' \
  --data-urlencode "start=$T0" --data-urlencode limit=5000 > "$INC/preuves/loki.json"
# état du déploiement : pods, images exactes (digest), événements
kubectl get pods -A -l app.kubernetes.io/part-of=amcart -o wide > "$INC/preuves/pods.txt"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{.status.containerStatuses[*].imageID}{"\n"}{end}' > "$INC/preuves/images.txt"
kubectl get events -A --sort-by=.lastTimestamp > "$INC/preuves/events.txt"
sha256sum "$INC"/preuves/* > "$INC/preuves/SHA256SUMS"   # intégrité des pièces
```
Les journaux ne contiennent ni mot de passe, ni jeton, ni adresse e-mail (C7), ils peuvent donc être
joints à la fiche. Le dossier reste hors des branches publiques tant que l'incident est ouvert.

**Leviers de confinement disponibles.**

| Levier | Commande | Effet / limite |
|--------|----------|----------------|
| Suspendre un compte | `kubectl -n amcart-databases exec deploy/postgres -- psql -U postgres -d amcart_users -c "UPDATE users SET status='suspended' WHERE id='<user-id>'"` | connexion et renouvellement refusés immédiatement |
| Révoquer ses sessions | `... -c "DELETE FROM refresh_tokens WHERE user_id='<user-id>'"` | plus de renouvellement ; le jeton d'accès en cours reste valide **15 min au plus** |
| Invalider **tous** les jetons | régénérer `JWT_SECRET` dans `~/.config/amcart/secrets.env` (`openssl rand -base64 48`) puis `deploy/scripts/deploy.sh` | tous les utilisateurs sont déconnectés ; à réserver au SEV-1 (clé de signature suspecte) |
| Couper un service | `kubectl -n amcart-services scale deploy/<service> --replicas=0` | arrêt du service : on échange la disponibilité contre l'arrêt de la fuite |
| Revenir à la version précédente | `kubectl -n amcart-services rollout undo deploy/<service>` | si la version déployée introduit la faille |

La passerelle limite déjà le débit par adresse (`limit_req`, 5 req/s sur la connexion). Dans ce
laboratoire, le trafic arrive par `port-forward` : toutes les requêtes semblent venir de la même
adresse, donc un blocage par IP n'a pas de sens ici. En production, il se ferait en amont (pare-feu
applicatif ou répartiteur de charge).

### 3.3 Éradiquer

- Identifier la cause racine : ligne de code, dépendance, configuration, secret.
- Corriger **par le pipeline** : branche `fix/...`, test de régression qui reproduit l'attaque (il
  échoue avant le correctif), contrôles bloquants verts, PR relue, fusion. C'est la démarche suivie
  pour F1 à F6 et C5 à C7 (`01-registre-des-failles.md`).
- Faire tourner tout secret qui a pu être exposé (procédure `05-procedure-revocation-purge.md` :
  révoquer d'abord, purger ensuite).
- Inscrire la faille au registre, avec sa cartographie STRIDE et OWASP.

### 3.4 Rétablir

```bash
deploy/scripts/deploy.sh                 # version corrigée, images étiquetées par commit
deploy/scripts/verify-hardening.sh       # admission, réseau, contexte de sécurité : rien n'a régressé
tests/detection/replay-attacks.sh        # l'attaque rejouée échoue ET reste détectée
```
- Réactiver les comptes légitimes suspendus par précaution (`status='active'`).
- Surveillance renforcée 24 h : tableau de bord ouvert, toute nouvelle alerte du même type rouvre
  l'incident.
- Clôture décidée par le responsable quand l'attaque ne fonctionne plus, que la détection est
  confirmée et qu'aucune alerte n'a reparu pendant la surveillance.

### 3.5 Apprendre

Retour d'expérience **sans recherche de coupable**, dans les 5 jours :
- chronologie (détection, confinement, correction, clôture) et délais obtenus ;
- ce qui a détecté l'attaque, ce qui aurait dû la détecter plus tôt ;
- actions : nouvelle règle de détection, seuil ajusté, test ajouté au pipeline, mise à jour du
  modèle de menace (`02-modele-de-menace.md`) et de ce plan.

## 4. Scénarios

### Scenario A : tentative d'injection

Alerte `AmcartInjectionAttempt` : des motifs SQL ou XSS ont été reçus dans la chaîne de requête ou le
chemin (événement `security.injection_attempt`, champs `Indicators`, `Fields`, `Route`, `Status`).

1. **Tri.** Le champ `Status` de chaque événement dit ce que l'application a répondu :
   - 200 ou 400 partout, aucune erreur associée : tentative sans effet (requête paramétrée, F1
     corrigée). **SEV-3**, souvent un scanner ;
   - 500, ou temps de réponse anormal : la charge a atteint un point fragile. **SEV-2**. Suivre le
     correlation ID pour trouver l'exception (`|= "<correlation-id>"`).
2. **Source.** `UserId` : un compte authentifié se suspend ; `anonymous` : regarder le volume et la
   durée dans le tableau de bord.
3. **Contenir.** SEV-3 : rien de plus que la limite de débit, surveiller. SEV-2 : suspendre le compte
   s'il y en a un ; si une route renvoie 500 sur charge malveillante, revenir à la version
   précédente ou couper le service le temps du correctif.
4. **Éradiquer.** Test de régression avec la charge, correction, règle SAST si le motif de code est
   nouveau (comme `efcore-raw-sql-non-constant` pour F1).

### Scenario B : énumération de commandes

Alerte `AmcartOrderEnumeration` : un même utilisateur a demandé au moins 5 commandes qui ne sont pas
les siennes en 5 minutes (événement `security.access_denied`, ressource `order`).

1. **Tri.** La question décisive : **a-t-il obtenu une commande d'autrui ?** Chercher, pour cet
   utilisateur, des lectures réussies de commandes :
   `{namespace="amcart-services", app="product-service"} | json | State_Event="http.request" | State_UserId="<user-id>" | State_Route="/api/v1/orders/{id:guid}" | State_Status="200"`
   puis vérifier en base que chaque commande lue lui appartient. Toutes refusées : **SEV-3** (la
   correction de F2 tient). Une seule commande d'autrui lue : **SEV-1** (fuite de données personnelles).
2. **Contenir.** Suspendre le compte et révoquer ses sessions (§3.2). SEV-1 : revenir à la dernière
   version saine du service de commandes.
3. **SEV-1 uniquement.** Lister les commandes exposées et leurs propriétaires ; avec le responsable,
   évaluer l'obligation d'informer les personnes concernées et l'autorité de protection des données
   (en Tunisie, l'INPDP, loi organique n° 2004-63).
4. **Éradiquer.** Contrôle de propriété dans la requête (correctif de F2) et test de régression ; vérifier
   les autres ressources par identifiant (adresses, avis, liste de souhaits).

### Scenario C : force brute sur un compte

Alerte `AmcartLoginBruteForce` : au moins 10 connexions refusées sur le même compte en 5 minutes
(événement `security.auth_failed`). Le compte est désigné par `AccountRef`, empreinte de son adresse,
pour ne pas écrire d'adresse e-mail dans les journaux.

1. **Identifier le compte** (accès base réservé à l'opérateur) :
   ```bash
   kubectl -n amcart-databases exec deploy/postgres -- psql -U postgres -d amcart_users -At -c \
     "SELECT id, status, last_login_at FROM users
       WHERE left(encode(sha256(convert_to(lower(trim(email)), 'UTF8')), 'hex'), 12) = '<AccountRef>'"
   ```
   Aucune ligne : l'adresse visée n'existe pas (énumération ou liste de mots de passe volés).
2. **Tri.** `last_login_at` **pendant ou après** la rafale : l'attaquant a peut-être trouvé le mot de
   passe. **SEV-1**, on suppose le compte compromis. Sinon, **SEV-3**.
3. **Contenir.** SEV-1 : suspendre le compte, révoquer ses sessions, puis réinitialiser le mot de
   passe avec le titulaire, par un canal sûr. SEV-3 : surveiller ; si la rafale se répète,
   suspendre temporairement.
4. **Apprendre.** Une alerte « un échec sur beaucoup de comptes » (bourrage d'identifiants) et un
   verrouillage progressif côté application sont des améliorations identifiées, pas encore en place.

## 5. Limites connues

- **Pas d'astreinte ni de notification** dans ce laboratoire : les alertes s'affichent dans Grafana
  et dans l'API de Loki, mais ne partent ni par e-mail ni par messagerie (pas d'Alertmanager). Une
  personne doit regarder. En production, le *ruler* de Loki enverrait à un Alertmanager relié à
  l'astreinte.
- La détection d'injection ne lit que la chaîne de requête et les valeurs de route, **pas les corps
  JSON** ; elle reconnaît des motifs courants, pas toutes les variantes obscurcies. Elle complète la
  protection (requêtes paramétrées), elle ne la remplace pas.
- Les journaux vivent dans le même cluster que l'application : un attaquant administrateur du cluster
  pourrait les effacer. Un envoi vers un stockage externe en écriture seule réglerait ce point.
- Rétention de 7 jours : une attaque découverte plus tard ne laisse plus de traces dans Loki.

## Annexe : modèle de fiche d'incident

```markdown
# Incident AAAA-MM-JJ <sujet>
- Gravité : SEV-? (justification)        - Statut : ouvert | contenu | clos
- Responsable : …  Analyste : …  Opérateur : …

## Chronologie (UTC)
| Heure | Événement / décision | Qui |
|-------|----------------------|-----|
| hh:mm | alerte <nom> reçue | |

## Faits établis
- requêtes en cause (correlation ID) : …
- compte(s) : …   données touchées : …

## Actions
| Phase | Action | Résultat |
|-------|--------|----------|

## Cause racine et correctif
## Retour d'expérience (actions, responsables, échéances)
```
