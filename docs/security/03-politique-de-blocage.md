# Politique de blocage du pipeline

Ce document définit **ce qui casse le build**, **quelles exceptions sont tolérées** et **dans quel délai
elles doivent être levées** (exigence §4.3). La politique est appliquée par `.github/workflows/ci.yml`.
Les fichiers de règles sont versionnés dans le dépôt : toute modification passe donc par une revue.

## 1. Les cinq contrôles

| Contrôle | Outil (version épinglée) | Périmètre | Casse le build si… | Rapport |
|----------|--------------------------|-----------|--------------------|---------|
| SAST | Semgrep 1.186.0 : `p/csharp`, `p/typescript`, `p/react` + règles maison `.semgrep/` | Code C# et TypeScript | au moins un résultat de sévérité **ERROR** | SARIF, toutes sévérités |
| Dépendances (SCA) | Trivy v0.76.2 `fs` | `package-lock.json`, `packages.lock.json` | une CVE **HIGH ou CRITICAL disposant d'un correctif** | JSON complet |
| Image | Trivy v0.76.2 `image` (vuln + secret) | Les 3 images construites | une CVE HIGH/CRITICAL corrigeable, **un secret quel qu'il soit**, ou une image qui tourne en root | Table |
| Secrets | Gitleaks v8.30.1 + `.gitleaks.toml` | **Tout l'historique Git** | **au moins un secret** (valeurs caviardées avec `--redact`) | SARIF |
| IaC | Trivy v0.76.2 `config` | Dockerfiles, manifestes Kubernetes | une mauvaise configuration **HIGH ou CRITICAL** | Table |

Le job `security-gate` ne réussit que si les cinq contrôles et les builds réussissent. Le déploiement et
les tests dynamiques dépendent de ce job : rien ne se déploie tant qu'un contrôle est rouge.

**Ce qui empêche de contourner la CI.** Un contrôle qui échoue ne bloque rien si l'on peut pousser
directement sur `main`. Le ruleset GitHub `protect-main` (`.github/rulesets/protect-main.json`) impose
donc une PR pour toute modification de `main`, interdit le force-push et la suppression, et n'accorde
**aucune dérogation**, y compris aux administrateurs. Les contrôles requis pour fusionner sont introduits
en deux temps :

| Phase | Contrôles requis | Raison |
|-------|------------------|--------|
| Base vulnérable (actuelle) | builds .NET et React, *Dependencies*, *IaC*, *Image ui* | contrôles déjà verts : toute régression est bloquée, et le travail sur les autres sujets reste possible |
| Après correction de F1, F2, F3, F5 | tous les contrôles + `Security gate` | aucune fusion sans pipeline entièrement vert |

Pendant la phase actuelle, *SAST*, *Secrets* et *Image user/product* restent rouges **à dessein**, à
cause des failles F1 et F5 non encore corrigées. Ils ne sont pas requis, sinon aucune PR ne pourrait
être fusionnée, mais leurs résultats restent visibles sur chaque PR. Désactiver le ruleset (par exemple
pour le force-push qu'impose la purge de l'historique, §4.4) est une opération exceptionnelle : elle est
consignée dans le registre des exceptions, avec sa durée.

En complément, CodeQL (`.github/workflows/codeql.yml`) tourne en **mode consultatif** : ses alertes
sont triées chaque semaine dans l'onglet Security de GitHub, mais il ne bloque pas. La justification
figure en §2.

## 2. Justification des seuils

**Secrets : tolérance zéro.** Un secret publié doit être considéré comme compromis : aucune gravité
n'est « acceptable ». Les règles par défaut de Gitleaks reposent sur l'entropie et ne voyaient pas nos
secrets réels (mot de passe lisible, longue clé JWT en clair, cf. F5). Nous avons donc ajouté trois
règles ciblées : mot de passe dans une chaîne de connexion, secret JWT, `POSTGRES_PASSWORD`. Tout
l'historique est scanné à chaque exécution, et pas seulement le dernier commit : un secret supprimé
dans un commit ultérieur reste lisible dans l'historique.

**Dépendances et images : HIGH/CRITICAL corrigeables.**
- *Pourquoi pas MEDIUM ?* Les images de base contiennent en permanence des dizaines de CVE MEDIUM ou
  LOW, souvent non exploitables dans notre contexte. Les bloquer rendrait le pipeline rouge en continu,
  et l'équipe finirait par ignorer le signal ou contourner le contrôle.
- *Pourquoi `ignore-unfixed` ?* Bloquer sur une CVE sans correctif publié arrête la livraison sans
  qu'aucune action ne soit possible. Ces CVE restent visibles dans le rapport JSON et sont revues
  chaque semaine.
- *Pourquoi un secret dans une image bloque-t-il toujours ?* L'image est distribuée au registre et au
  cluster : un secret embarqué y est lisible par toute personne qui peut tirer l'image (exigence §4.1).

**SAST : sévérité ERROR uniquement.** Les règles ERROR des jeux `p/csharp`, `p/typescript` et `p/react`
visent des vulnérabilités à fort niveau de confiance (injection, désérialisation, XSS, etc.). Les
WARNING et INFO contiennent davantage de faux positifs ou de remarques de qualité. Ils sont donc
conservés dans le rapport SARIF et revus manuellement, sans bloquer. Notre règle maison
`efcore-raw-sql-non-constant` est en ERROR parce qu'elle cible précisément l'API utilisée par F1.

**IaC : HIGH/CRITICAL.** Ces règles correspondent aux exigences explicites du §4.5 : exécution en root,
système de fichiers inscriptible, contexte de sécurité absent. Les règles MEDIUM et LOW (par exemple
l'absence de limite de stockage éphémère) relèvent du durcissement « bonus » et ne bloquent pas.

**CodeQL consultatif.** Il couvre un périmètre proche de Semgrep, avec plus de bruit dans notre
contexte (par exemple le stockage du vérificateur PKCE en `sessionStorage`, qui est la pratique
standard pour une SPA). Le rendre bloquant en plus de Semgrep doublerait le coût de triage sans
gain démontré. Nous le gardons comme défense en profondeur.

## 3. Exceptions tolérées

Une exception n'est acceptée que si les **quatre** conditions suivantes sont remplies :

1. elle est **inscrite** dans `docs/security/04-registre-des-exceptions.md`, avec un identifiant
   `EXC-NNN`, l'outil, la règle ou la CVE, la justification, le responsable et la date d'expiration ;
2. elle est **matérialisée au plus près de la règle** :
   - Trivy : entrée dans `.trivyignore.yaml`, **limitée par chemin** (`paths`) ou par paquet (`purls`),
     avec `expired_at` (Trivy ignore l'exception d'elle-même après cette date) et un `statement`
     qui commence par l'identifiant `EXC-NNN` ;
   - Semgrep : commentaire `// nosemgrep: <id-de-règle>` suivi de la référence `EXC-NNN` ;
   - Gitleaks : uniquement pour un **faux positif avéré** (empreinte dans `.gitleaksignore`). Un vrai
     secret n'est **jamais** une exception : il est révoqué, puis purgé ;
3. sa durée ne dépasse pas le plafond ci-dessous ;
4. elle est relue par un second membre de l'équipe (revue de la pull request).

| Gravité | Durée maximale d'une exception | Délai de correction (SLA) |
|---------|-------------------------------|---------------------------|
| CRITICAL | 7 jours | 7 jours |
| HIGH | 30 jours | 30 jours |
| MEDIUM | non bloquant | 90 jours |
| LOW / INFO | non bloquant | au mieux |

Les exceptions **interdites** sont : un secret réel, une CVE CRITICAL exploitable à distance dans un
composant exposé, et une image exécutée en root.

## 4. Preuves attendues (démonstration)

| Scénario | Commit de démonstration | Résultat attendu |
|----------|-------------------------|------------------|
| Secret poussé | ajout d'un faux secret dans un fichier suivi | job *Secrets* rouge, valeur caviardée dans les logs |
| Vulnérabilité critique | `crypto-js` 4.1.1 (F4) | job *Dependencies* rouge sur CVE-2023-46233 |
| Injection SQL | `QuickSearchAsync` (F1) | job *SAST* rouge, règle `efcore-raw-sql-non-constant` |
| Conteneur root | Dockerfile UI (F6) | jobs *IaC* (DS-0002) et *Image ui* rouges |
| Après correctifs | commits `fix(security): Fx` | tous les jobs verts, `security-gate` vert |

## 5. Ce que ce pipeline ne prouve pas

- Un pipeline vert signifie « aucune faille *connue de ces outils* au-dessus des seuils ». Il ne prouve
  pas l'absence de faille. F2 (IDOR) et F3 (prix) sont **invisibles** pour le SAST et le SCA, car ce
  sont des erreurs de logique métier. Seuls les tests dynamiques et la revue de code les révèlent.
- Les bases de vulnérabilités ont un temps de latence : une CVE publiée aujourd'hui peut n'apparaître
  que demain.
- `ignore-unfixed` laisse passer des CVE réelles qui n'ont pas encore de correctif.
- Les règles de secrets ne détectent que les formats qu'on leur a décrits.
