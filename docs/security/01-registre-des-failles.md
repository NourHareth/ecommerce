# Registre des failles initiales

> **Statut :** rédigé et commité **avant** toute correction (exigence §4.2).
> L'historique Git en est la preuve : le commit qui ajoute ce fichier précède chaque commit `fix(security): Fx`.

L'application d'origine (AmCart) était plutôt saine : commandes filtrées par propriétaire, prix
recalculés côté serveur, recherches paramétrées. Pour disposer d'une vraie surface d'attaque, nous
avons **introduit** les failles F1 à F4. F5 et F6 existaient déjà dans le code d'origine.

Toutes les démonstrations se font **uniquement sur notre propre instance de test** (cluster local ou
cluster éphémère dans la CI), conformément au §6.

## Synthèse

| ID | Faille | OWASP Top 10:2025 | CWE | STRIDE | Gravité | Origine | Contrôle qui la détecte |
|----|--------|-------------------|-----|--------|---------|---------|-------------------------|
| F1 | Injection SQL (recherche rapide) | A05 Injection | CWE-89 | I, T | Critique | Introduite | SAST + DAST |
| F2 | IDOR sur le détail d'une commande | A01 Broken Access Control | CWE-639 | I | Élevée | Introduite | DAST authentifié |
| F3 | Altération du prix dans le panier | A06 Insecure Design | CWE-472 | T | Élevée | Introduite | DAST authentifié |
| F4 | Dépendance vulnérable `crypto-js` 4.1.1 | A03 Software Supply Chain Failures | CWE-1395 | — | Critique (CVSS) / faible en contexte | Introduite | SCA |
| F5 | Secrets en dur (clé JWT, mot de passe BDD) | A07 Authentication Failures | CWE-798 | S, E | Critique | Existante | Détection de secrets |
| F6 | Conteneur UI exécuté en root | A02 Security Misconfiguration | CWE-250 | E | Moyenne | Existante | Scan image/IaC + admission |

STRIDE : **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege.

Le socle exige au moins quatre failles démontrées : F1, F2, F3, F5 et F6 le sont. **F4 est détectée
mais pas exploitable en l'état**, car la bibliothèque n'est appelée nulle part. Elle sert à prouver que
l'étape SCA bloque le pipeline, et le rapport le dit explicitement.

---

## F1 — Injection SQL dans la recherche rapide

- **Emplacement :** `src/Services/ProductService/ProductService.Infrastructure/Repositories/ProductRepository.cs:54`
  (méthode `QuickSearchAsync`), exposée par `GET /api/v1/products/quick-search` (accès anonyme).
- **Cause :** le terme saisi par l'utilisateur est **concaténé** dans la requête SQL exécutée par
  `Database.SqlQueryRaw`. La requête n'est pas paramétrée, et le terme n'est ni validé ni limité en longueur.
- **Impact :** un visiteur **non authentifié** peut altérer la logique de la requête et lire d'autres
  tables de la base `amcart_products`, dont les commandes, qui contiennent les noms, adresses,
  téléphones et e-mails des clients.
- **Démonstration :** dans l'environnement de test, le scanner DAST détecte que le paramètre `q`
  modifie le comportement de la requête SQL. Le SAST signale aussi le flux de données non fiable
  qui arrive jusqu'à `SqlQueryRaw`.
- **Correctif prévu :** requête paramétrée (LINQ `EF.Functions.ILike`), longueur maximale du terme et
  compte PostgreSQL applicatif à privilèges minimaux.

## F2 — IDOR : lecture de la commande d'un autre client

- **Emplacement :** `src/Services/ProductService/ProductService.Infrastructure/Repositories/OrderRepository.cs:47`
  (méthode `GetByIdForUserAsync`), via `GET /api/v1/orders/{id}`.
- **Cause :** la requête ne filtre que sur l'identifiant de la commande. La condition de propriété
  (`UserId == userId`) a été retirée, alors que la méthode reçoit bien `userId`.
  L'**authentification** est vérifiée, mais pas l'**autorisation sur l'objet**.
- **Impact :** un client connecté qui obtient l'identifiant d'une commande peut lire les données
  personnelles d'un autre client : adresses, téléphone, e-mail, articles et montants. Les
  identifiants sont des GUID, difficiles à deviner, mais ils peuvent fuir (F1, journaux, liens partagés).
- **Démonstration :** avec deux comptes de test, l'utilisateur B obtient une réponse 200 sur la
  commande de l'utilisateur A, alors que la réponse attendue est 404.
- **Correctif prévu :** rétablir le filtre de propriété dans la requête, répondre 404 pour ne pas
  révéler l'existence de la commande, et ajouter un test unitaire de non-régression.

## F3 — Altération du prix dans le panier

- **Emplacements :**
  - `ProductService.Application/DTOs/CartDtos.cs:34` : champ `UnitPrice` accepté en entrée
  - `ProductService.Application/Services/CartService.cs:37` : prix client utilisé à la place du prix catalogue
  - `ProductService.Application/Services/CartService.cs:208` : total du panier calculé sur le prix stocké
  - `ProductService.Infrastructure/Repositories/CheckoutRepository.cs:61` et `:129` : commande facturée au prix stocké
- **Cause :** le serveur **fait confiance à un prix fourni par le client**, sous prétexte de
  « stabilité des prix promotionnels ». Ce prix est enregistré dans la ligne de panier puis réutilisé
  au paiement, sans être comparé au prix du catalogue.
- **Impact :** perte financière directe, car un article peut être commandé à un prix arbitraire.
  L'intégrité des commandes n'est plus garantie.
- **Démonstration :** dans l'environnement de test, une requête d'ajout au panier qui contient un prix
  modifié produit une commande facturée à ce prix plutôt qu'au prix du catalogue.
- **Correctif prévu :** retirer `UnitPrice` du contrat d'entrée et recalculer systématiquement le prix
  depuis `products.price`, à l'ajout comme au paiement. Ajouter un test de non-régression.

## F4 — Dépendance vulnérable : `crypto-js` 4.1.1

- **Emplacement :** `src/Frontends/ui-app/package.json` (dépendance de production) et `package-lock.json`.
- **Cause :** version épinglée sur une release vulnérable connue, sans contrôle des dépendances dans la
  CI d'origine.
- **Vulnérabilité :** CVE-2023-46233. Les paramètres par défaut de PBKDF2 (SHA-1, une seule itération)
  rendent les empreintes très faibles. Gravité **critique** (CVSS 9.1), corrigée en 4.2.0.
- **Impact en contexte :** **faible**, car aucun code n'appelle la bibliothèque. Le risque relève de la
  chaîne d'approvisionnement : la dépendance pourrait être utilisée plus tard sans que personne sache
  qu'elle est vulnérable.
- **Démonstration :** l'étape SCA fait échouer le pipeline tant que cette version est présente (preuve §4.3).
- **Correctif prévu :** retirer la dépendance, qui est inutilisée. Sinon, passer en version ≥ 4.2.0.

## F5 — Secrets en dur dans le dépôt et dans l'image

- **Emplacements :**
  - `src/Services/UserService/UserService.Api/appsettings.json:10` (mot de passe BDD) et `:13` (clé JWT)
  - `src/Services/ProductService/ProductService.Api/appsettings.json:10` et `:13`
  - `src/Services/*/kubernetes/base/secret.yaml` et `src/Databases/postgres/kubernetes/base/secret.yaml` (en clair)
- **Cause :** valeurs de développement commitées puis jamais externalisées. `dotnet publish` copie
  `appsettings.json` dans l'image, donc les secrets s'y retrouvent aussi. Leur entropie est trop
  faible pour les règles par défaut de Gitleaks, qui ne les détectent pas.
- **Impact :** la clé de signature des jetons est publique. Un attaquant peut donc produire des jetons
  acceptés par les services, ce qui revient à une usurpation d'identité et à une élévation vers le
  rôle administrateur. Le mot de passe de la base est également exposé.
- **Démonstration :** la détection de secrets, avec des règles personnalisées, signale ces valeurs dans
  le dépôt et dans son historique.
- **Correctif prévu, procédure « révoquer d'abord, purger ensuite » (§4.4) :**
  1. générer une nouvelle clé JWT et un nouveau mot de passe BDD, injectés à l'exécution
     (Secret Kubernetes, secrets GitHub), puis invalider les anciennes valeurs ;
  2. retirer les valeurs des fichiers suivis ;
  3. **ensuite seulement**, purger l'historique (`git filter-repo`) et vérifier par un scan
     complet que l'historique est propre.

## F6 — Conteneur UI exécuté en root, sans durcissement

- **Emplacement :** `src/Frontends/ui-app/Dockerfile` (image `nginx:1.27-alpine`, aucune instruction `USER`)
  et manifestes Kubernetes sans `securityContext`.
- **Cause :** image de base standard qui démarre en root. Aucune contrainte n'est imposée au
  déploiement : système de fichiers inscriptible, capacités Linux non retirées, élévation de
  privilèges autorisée.
- **Impact :** si le conteneur est compromis, l'attaquant est root dans le conteneur. Il peut modifier
  la configuration nginx et les fichiers servis (défiguration, injection de script) et sa surface
  d'évasion vers l'hôte augmente.
- **Démonstration :** le conteneur s'exécute avec l'UID 0. Le scan de configuration le signale, et une
  fois la politique d'admission active, ce déploiement est refusé.
- **Correctif prévu :** image `nginx-unprivileged` (UID non nul, port 8080), `securityContext`
  restrictif (`runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`,
  `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`) et politique Kyverno en mode `Enforce`.

---

## Suivi

Exécution de référence du pipeline bloquant, sur la base vulnérable :
[CI #45490691771](https://github.com/NourHareth/ecommerce/actions/runs/45490691771), commit `2e9a65b`.

| ID | Documentée | Démontrée | Preuve | Corrigée | Vérifiée après correction |
|----|-----------|-----------|--------|----------|---------------------------|
| F1 | ✅ | ✅ statique + ✅ dynamique | job *SAST* : règle `efcore-raw-sql-non-constant`, `ProductRepository.cs` · job *DAST* ([CI #45502066755](https://github.com/NourHareth/ecommerce/actions/runs/45502066755)) : ZAP, injection SQL par erreur, `GET /api/v1/products/quick-search [q]`, une apostrophe → HTTP 500 | ✅ `7312739` : requête LINQ (terme envoyé en paramètre), longueur ≤ 100 · test `34196f8` | ✅ tests unitaires (avant : échec, après : succès) · ⬜ SAST et DAST sur la PR de correction |
| F2 | ✅ | ✅ dynamique | job *DAST* ([CI #45502066755](https://github.com/NourHareth/ecommerce/actions/runs/45502066755)) : bob lit la commande d'alice → **200** (attendu 404) ; témoin : alice lit sa commande → 200 | ✅ `dcbc2d9` : filtre de propriété rétabli dans la requête (404 pour la commande d'un autre) · test `34196f8` | ✅ tests unitaires (avant : échec, après : succès) · ⬜ DAST sur la PR de correction |
| F3 | ✅ | ✅ dynamique | job *DAST* ([CI #45502066755](https://github.com/NourHareth/ecommerce/actions/runs/45502066755)) : `unitPrice` 0.01 envoyé par le client → panier facturé **0.01** (prix catalogue 49.99) | ✅ `3802b6c` : champ de prix retiré du contrat d'API ; ajout, panier et paiement lisent le prix catalogue · test `34196f8` | ✅ tests unitaires (avant : échec, après : succès) · ⬜ DAST sur la PR de correction |
| F4 | ✅ | ✅ | job *Dependencies* : CVE-2023-46233, CRITICAL | ✅ `9a646c2` : dépendance retirée (inutilisée) | ✅ job *Dependencies* vert ([CI #45492295507](https://github.com/NourHareth/ecommerce/actions/runs/45492295507)) |
| F5 | ✅ | ✅ | job *Secrets* (historique complet, caviardé) + jobs *Image user/product* : secrets dans `/app/appsettings.json` | ⬜ | ⬜ |
| F6 | ✅ | ✅ | job *IaC* : DS-0002 sur le Dockerfile UI + job *Image ui* : « runs as root » | ✅ image : `f405e97` (nginx-unprivileged, `USER 101`, port 8080, écritures limitées à `/tmp`) · ⬜ Kubernetes : `securityContext` + Kyverno | ✅ image ([CI #45493010532](https://github.com/NourHareth/ecommerce/actions/runs/45493010532)) : job *Image ui* vert, conteneur démarré en lecture seule, sans capacité, UID ≠ 0, sert la SPA avec l'en-tête CSP. Dockerfile UI : 0 mauvaise configuration · ⬜ admission |

### Constats supplémentaires du pipeline (non introduits volontairement)

| ID | Constat | Source | Traitement prévu |
|----|---------|--------|------------------|
| C1 | Image UI basée sur `nginx:1.27-alpine` (Alpine 3.21.3, obsolète) : 70 CVE corrigeables, dont 3 CRITICAL | job *Image ui* | ✅ Résolu. Le passage à `nginx-unprivileged:1.31-alpine` (Alpine 3.24.2) ramène le compte à 14 : l'image de base publiée est en retard sur les correctifs Alpine. Un `apk upgrade` au build (`fe14009`) l'amène à 0 |
| C2 | Manifestes Kubernetes sans `securityContext` (KSV-0014, KSV-0118), y compris PostgreSQL et la passerelle | job *IaC* | Phase « déploiement durci » (§4.5) |
| C3 | KSV-0109 sur la ConfigMap UserService : **faux positif**, les clés `Jwt__Issuer`, `Jwt__Audience` et les durées ne sont pas secrètes | job *IaC* | Exception documentée lors de la réécriture des manifestes |
| C4 | Faux positif de notre propre règle Gitleaks `jwt-signing-secret` sur une référence de variable `${JWT_SECRET:?…}` | job *Secrets* | Règle corrigée (une valeur commençant par `$` n'est pas un secret) |
