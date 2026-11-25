# F5 : procédure « révoquer d'abord, purger ensuite » (§4.4)

**Ordre imposé :** rendre d'abord le secret inutile, puis seulement le retirer de l'historique. Purger
d'abord ne protège de rien : le secret a déjà été lu, cloné, mis en cache ou forké. Tant qu'il est
valide, l'effacer ne fait que masquer le problème.

Secrets concernés (F5) : la clé de signature JWT (HS256) et le mot de passe PostgreSQL `amcart`,
présents dans `appsettings*.json`, les manifestes Kubernetes, `.env.example`, `docker-compose.yml` et
plusieurs documents, depuis le premier commit.

## Étape 1 : révoquer (fait)

| Action | Preuve |
|--------|--------|
| Nouveaux secrets générés aléatoirement au déploiement (`openssl rand`), stockés hors dépôt (mode 600), injectés comme Secrets Kubernetes | `deploy/scripts/deploy.sh` |
| Les secrets déployés diffèrent des valeurs exposées ; le compte BDD exposé n'existe plus (un rôle par service) | `docs/evidence/2026-11-25-rotation-secrets.txt` |
| La CI (DAST) génère des secrets neufs à chaque exécution | job *DAST*, `SECRETS_FILE` dans `$RUNNER_TEMP` |
| À faire par l'équipe : arrêter le conteneur de test `amcart-postgres` de la VM, supprimer les anciennes images ECR | hors dépôt |

## Étape 2 : retirer des fichiers suivis (PR « F5 remove hardcoded secrets »)

- Plus de chaîne de connexion ni de `Jwt:Secret` dans `appsettings*.json`. Les services refusent de
  démarrer sans ces valeurs (échec immédiat plutôt que démarrage avec une clé connue).
- `POSTGRES_PASSWORD` est obligatoire dans le `docker-compose` local ; la documentation utilise des
  marqueurs `<POSTGRES_PASSWORD>` et `<JWT_SECRET>`.
- Vérification : Gitleaks en mode `dir` ne trouve rien, les règles de secrets de Trivy non plus. Les
  jobs *Image user/product* deviennent verts.

## Étape 3 : purger l'historique (nécessite l'accord explicite du propriétaire)

Prérequis :
- les étapes 1 et 2 sont fusionnées ;
- les PR ouvertes sont fusionnées ou fermées : leurs branches contiennent l'ancien historique ;
- GitHub Actions fonctionne, pour vérifier le résultat en CI.

```bash
# 1. Copie miroir de travail (jamais dans le clone habituel)
git clone --mirror https://github.com/NourHareth/ecommerce.git amcart-purge.git && cd amcart-purge.git

# 2. Remplacer les valeurs exposées dans TOUT l'historique (outil : git-filter-repo)
#    ../replacements.txt est créé HORS du dépôt et n'est jamais commité : une ligne par valeur exposée,
#    au format  <valeur exposée>==>REMOVED_SECRET
#    (les deux valeurs se retrouvent aux emplacements listés pour F5 dans 01-registre-des-failles.md).
#    Ce document ne les recopie pas, pour ne pas les réintroduire dans le dépôt.
git filter-repo --replace-text ../replacements.txt

# 3. Vérifier AVANT de pousser : historique complet, règles du dépôt
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.30.1 git /repo --config /repo/.gitleaks.toml --redact
#    (lire .gitleaks.toml depuis un clone normal si le miroir n'a pas d'arbre de travail)

# 4. Désactiver temporairement le ruleset (force-push interdit sur main), pousser, réactiver
gh api -X PUT repos/NourHareth/ecommerce/rulesets/28027598 -f enforcement=disabled
git push --force --mirror origin
gh api -X PUT repos/NourHareth/ecommerce/rulesets/28027598 -f enforcement=active
```

Après la purge :
- **chaque clone devient obsolète** (postes, VM `~/amcart` et `~/ecommerce`) : le recloner, ne pas le
  fusionner ;
- les identifiants de commit changent : les liens du registre vers des commits précis doivent être mis
  à jour (les liens vers les exécutions de CI restent valides) ;
- inscrire la désactivation du ruleset au registre des exceptions (durée : le temps du push) ;
- relancer la CI : le job *Secrets* (Gitleaks sur tout l'historique) doit passer au vert.

## Ce que la purge ne garantit pas

- GitHub conserve les références des pull requests (`refs/pull/*`) et des vues en cache. Seul le
  support GitHub peut les supprimer.
- Les clones et forks existants, et les artefacts déjà produits (images ECR, caches de CI), gardent
  les anciennes valeurs.

C'est pourquoi l'**étape 1 est la seule réellement protectrice** : après rotation, une valeur restée
visible quelque part est inutile.
