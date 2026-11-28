# Déploiement orchestré et durci (§4.5)

Cluster local **minikube** (profil `amcart`, pilote Docker, Kubernetes v1.37, CNI **Calico**), sur la
VM de l'équipe. Aucune ressource cloud : le cahier accepte un cluster local, et minikube avec le pilote
Docker ne demande pas `sudo`.

```
deploy/
├── k8s/base/                     manifestes (kustomize)
│   ├── namespaces.yaml           3 namespaces + Pod Security Admission "restricted"
│   ├── postgres.yaml             PostgreSQL 16, un rôle par service
│   ├── user-service.yaml
│   ├── product-service.yaml
│   ├── ui.yaml                   nginx (SPA + routage /api) : seul point d'entrée
│   └── network-policies.yaml     refus par défaut + flux autorisés
├── k8s/policies/
│   └── kyverno-pod-hardening.yaml  contrôle d'admission (Kyverno v1.20)
├── k8s/monitoring/               observabilité et détection (§4.7), voir « 6. Observabilité »
│   ├── alloy.yaml                collecte des journaux par l'API Kubernetes (RBAC lecture seule)
│   ├── loki.yaml                 stockage 7 jours + évaluation des règles de détection
│   ├── grafana.yaml              tableau de bord sécurité, non exposé
│   ├── rules/amcart-security.yaml  3 règles d'alerte (injection, énumération, force brute)
│   └── network-policies.yaml     refus par défaut dans amcart-monitoring
└── scripts/
    ├── deploy.sh        build, secrets d'exécution, déploiement
    ├── deploy-monitoring.sh      Loki, Alloy, Grafana (+ règle réseau vers l'API, générée)
    ├── install-kyverno.sh        Kyverno (version épinglée, empreinte SHA-256 vérifiée) + politique
    └── verify-hardening.sh       preuves : rejets d'admission, segmentation, application joignable
```

## Mise en route (sur la VM)

```bash
minikube start -p amcart --driver=docker --container-runtime=containerd \
  --kubernetes-version=v1.37.0 --cni=calico --cpus=4 --memory=5g
git clone https://github.com/NourHareth/ecommerce.git ~/amcart && cd ~/amcart
deploy/scripts/deploy.sh
deploy/scripts/install-kyverno.sh
deploy/scripts/verify-hardening.sh
deploy/scripts/deploy-monitoring.sh
tests/detection/replay-attacks.sh            # rejoue 3 attaques, vérifie journaux et alertes
kubectl -n amcart-web port-forward --address 0.0.0.0 svc/ui 8080:8080   # http://<IP-VM>:8080
```

## 1. Moindre privilège et contexte de sécurité

Chaque pod applique le même socle :

| Réglage | Valeur | Ce que cela empêche |
|---------|--------|---------------------|
| `runAsNonRoot` + `runAsUser` numérique | UID 1654 (.NET), 101 (nginx), 70 (PostgreSQL) | exécution en root, même si l'image le permet |
| `allowPrivilegeEscalation` | `false` | gain de privilèges via setuid/setgid |
| `capabilities.drop` | `[ALL]` | `NET_RAW` (usurpation réseau), `CHOWN`, etc. |
| `readOnlyRootFilesystem` | `true` + `emptyDir` sur `/tmp` | dépôt d'outils ou modification du code et de la config par un attaquant |
| `seccompProfile` | `RuntimeDefault` | appels système dangereux |
| `automountServiceAccountToken` | `false` + un ServiceAccount par service, sans aucun droit RBAC | utilisation d'un jeton Kubernetes depuis un pod compromis |
| `resources` | requests + limits CPU/mémoire | épuisement des ressources du nœud (DoS) |

**Base de données :** un rôle PostgreSQL par service (`users_app`, `products_app`), propriétaire de sa
seule base, avec `CONNECT` retiré à `PUBLIC`. Une injection SQL dans ProductService (F1) ne peut donc
pas lire `amcart_users`, qui contient les empreintes de mots de passe.

## 2. Secrets

Aucun secret n'est dans les manifestes. `deploy.sh` génère les mots de passe et la clé JWT avec
`openssl rand` dans `~/.config/amcart/secrets.env` (mode 600, hors du dépôt), puis crée les Secrets
Kubernetes. Les valeurs ne sont jamais affichées. Les variables d'environnement injectées
(`ConnectionStrings__DefaultConnection`, `Jwt__Secret`) **remplacent** les valeurs encore présentes
dans `appsettings.json` : l'application déployée n'utilise pas les secrets exposés (F5). Leur retrait
du dépôt et de l'historique reste à faire (procédure « révoquer d'abord, purger ensuite »).

## 3. Segmentation réseau : refus par défaut, puis autorisations ciblées

`default-deny-all` (entrée **et** sortie) dans chaque namespace, puis uniquement :

| Source | Destination | Port | Raison |
|--------|-------------|------|--------|
| tout client | ui | 8080 | point d'entrée de la boutique |
| ui | user-service, product-service | 8080 | routage `/api/*` |
| user-service | product-service | 8080 | historique de commandes (proxy) |
| user-service, product-service | postgres | 5432 | persistance |
| pods `amcart-web` et `amcart-services` | kube-dns | 53 | résolution de noms |

Tout le reste est bloqué, en particulier : ui → postgres, sortie vers Internet depuis les services, et
**aucune sortie** depuis PostgreSQL. Un service compromis ne peut ni exfiltrer vers l'extérieur, ni
atteindre la base sans passer par le service autorisé.

## 4. Contrôle d'admission : la charge non durcie est refusée

Deux couches :

1. **Pod Security Admission `restricted`** (labels des namespaces), intégrée à l'API server : root,
   conteneurs privilégiés, capacités ajoutées, namespaces de l'hôte, `hostPath`.
2. **Kyverno `ValidatingPolicy` `amcart-pod-hardening`** (CEL, `Deny`, `failurePolicy: Fail`). Elle
   ajoute ce que PSA ne vérifie pas :

| Règle | Exigence |
|-------|----------|
| R1 | `runAsNonRoot: true` |
| R2 | `allowPrivilegeEscalation: false` |
| R3 | `drop: [ALL]`, aucune capacité ajoutée |
| R4 | `readOnlyRootFilesystem: true` |
| R5 | image avec tag explicite ou digest, jamais `:latest` |
| R6 | limites CPU/mémoire et requête mémoire |
| R7 | `automountServiceAccountToken: false` |

La règle est aussi générée pour les Deployments, StatefulSets, Jobs, etc. (`autogen`) : un manifeste
non conforme est refusé dès le `kubectl apply`.

`failurePolicy: Fail` signifie qu'en cas d'indisponibilité de Kyverno, les pods AmCart sont refusés
(on préfère ne pas déployer plutôt que déployer sans contrôle). Le périmètre est limité aux
namespaces labellisés `app.kubernetes.io/part-of=amcart` pour ne pas bloquer le cluster lui-même.

## 5. Vérification

`deploy/scripts/verify-hardening.sh` produit la preuve demandée au §4.5 :

- **A.** un pod root/privilégié est refusé (PSA), un pod `:latest` sans limites ni FS en lecture seule
  est refusé (Kyverno), un Deployment non durci est refusé, et un pod durci est accepté (témoin) ;
- **B.** les flux nécessaires passent, les flux interdits sont bloqués ;
- **C.** la boutique reste joignable de bout en bout après la segmentation.

## 6. Observabilité et détection (§4.7)

```
 client ──> nginx (ui) ─────────────> user-service ──> product-service
             │ génère X-Correlation-ID     │ le transmet        │
             ▼                             ▼                    ▼
        une ligne JSON par requête, même correlation ID partout (chemin sans chaîne de requête)
                                   │
      Alloy (amcart-monitoring) ── lit les journaux des pods par l'API Kubernetes
                                   ▼
      Loki : stockage 7 jours + 3 règles LogQL évaluées toutes les 15 s ──> alerte « firing »
                                   ▼
      Grafana : tableau de bord « AmCart · Sécurité », alertes, suivi d'une requête par son ID
```

**Journaux.** Chaque service écrit une ligne `http.request` par appel (route *modèle*, statut, durée,
identifiant utilisateur, correlation ID) et des **événements de sécurité** à champ `Event` stable :

| Événement | Émis quand | Ce qui n'est **pas** journalisé |
|-----------|-----------|----------------------------------|
| `security.injection_attempt` | motif SQL/XSS dans la chaîne de requête ou le chemin | la valeur reçue (seuls le paramètre et le type de motif sont notés) |
| `security.input_rejected` | entrée refusée (C5, longueur, caractères de contrôle) | la valeur |
| `security.access_denied` | commande demandée qui n'appartient pas à l'utilisateur | — |
| `security.auth_failed` | connexion refusée | l'adresse e-mail (remplacée par `AccountRef`, empreinte de 12 caractères) |

C7 a montré que des jetons de réinitialisation finissaient dans les journaux : ni jeton, ni mot de
passe, ni adresse e-mail, ni chaîne de requête ne sont écrits.

**Règles de détection** (`k8s/monitoring/rules/amcart-security.yaml`), chacune reliée à un scénario
du plan de réponse (`docs/security/06-plan-reponse-incident.md`) :

| Alerte | Condition | Gravité |
|--------|-----------|---------|
| `AmcartInjectionAttempt` | au moins 1 tentative d'injection en 5 min | high |
| `AmcartOrderEnumeration` | au moins 5 commandes d'autrui demandées par un même utilisateur en 5 min | high |
| `AmcartLoginBruteForce` | au moins 10 échecs de connexion sur un même compte en 5 min | medium |

**Durcissement de la pile elle-même.** Même régime que l'application : namespace en Pod Security
« restricted » et soumis à Kyverno, conteneurs non-root, système de fichiers en lecture seule,
`drop ALL`, limites de ressources, NetworkPolicies en refus par défaut (Alloy et Grafana ne parlent qu'à
Loki, Alloy en plus au serveur d'API). Grafana : mot de passe aléatoire, pas d'accès anonyme, aucun
appel sortant, pas d'exposition (port-forward). Seule exception : le jeton de compte de service
d'Alloy (EXC-003), limité par RBAC à la lecture des pods et de leurs journaux dans les trois
namespaces AmCart. Ce choix évite le DaemonSet privilégié avec `hostPath` qu'utilisent la plupart
des collecteurs.

```bash
deploy/scripts/deploy-monitoring.sh
kubectl -n amcart-monitoring port-forward svc/grafana 3000:3000   # admin / mot de passe dans ~/.config/amcart/secrets.env
tests/detection/replay-attacks.sh   # preuve : $OUT_DIR/detection-replay.md
```

## DNS : `ndots: 2` (constat du premier déploiement)

**Symptôme observé sur la VM :**
- nginx (image Alpine) redémarrait en boucle avec `host not found in upstream` ;
- les services .NET n'étaient jamais *Ready* : chaque résolution de nom prenait environ 6 s, au-delà
  du délai de la sonde.

Pourtant, `nslookup` fonctionnait depuis les mêmes namespaces, avec les mêmes NetworkPolicies.

**Cause :**
- Le `resolv.conf` de la VM contient `search localdomain` (réseau NAT de VMware). Kubernetes ajoute ce
  suffixe à la liste de recherche des pods.
- Avec l'option par défaut `ndots:5`, un nom à 4 points comme
  `postgres.amcart-databases.svc.cluster.local` est d'abord essayé avec chaque suffixe, dont
  `…cluster.local.localdomain`. CoreDNS transmet cette requête au DNS externe de la VM, qui répond mal.
- glibc (images .NET) finit par aboutir, au bout d'environ 6 s par résolution.
- musl (image Alpine de nginx) **abandonne** dès qu'une requête de suffixe échoue.

**Correctif :** `dnsConfig.options: ndots=2` sur les pods applicatifs. Nos noms complets ayant plus de
2 points, ils sont résolus directement, sans passer par la liste de recherche.

**Effets de bord :**
- moins de requêtes DNS ;
- **les noms internes du cluster ne partent plus vers le résolveur externe**, ce qui supprime une
  fuite d'information.

Les délais des sondes passent aussi de 1 s (valeur par défaut) à 3 s, car `/health` inclut un aller-retour
vers la base.

Le problème n'apparaissait pas dans la CI : les runners GitHub n'ont pas ce suffixe de recherche. C'est
un exemple d'écart entre environnements que seul un déploiement réel révèle.

## Limites

- `port-forward` sert à la démonstration. Le trafic qu'il transporte entre par le kubelet et n'est pas
  soumis aux NetworkPolicies. Un Ingress avec terminaison TLS serait la cible en production.
- Un seul nœud : pas de haute disponibilité, et pas d'isolation entre nœuds.
- Les secrets Kubernetes ne sont qu'encodés en base64 dans etcd. Le chiffrement au repos d'etcd ou un
  coffre externe (Vault, External Secrets) relèverait d'un durcissement supplémentaire.
