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

| ID | Documentée | Démontrée | Corrigée | Vérifiée après correction |
|----|-----------|-----------|----------|---------------------------|
| F1 | ✅ | ⬜ | ⬜ | ⬜ |
| F2 | ✅ | ⬜ | ⬜ | ⬜ |
| F3 | ✅ | ⬜ | ⬜ | ⬜ |
| F4 | ✅ | ⬜ | ⬜ | ⬜ |
| F5 | ✅ | ⬜ | ⬜ | ⬜ |
| F6 | ✅ | ⬜ | ⬜ | ⬜ |
