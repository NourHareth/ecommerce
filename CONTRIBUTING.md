# Comment contribuer

Un seul dépôt et une branche `main` **protégée**. Tout changement arrive par une pull request (PR),
après les contrôles de la CI.

## Protection de `main`

Le ruleset `protect-main` (définition versionnée dans `.github/rulesets/protect-main.json`) impose :

- **aucun push direct** sur `main` : passage obligatoire par une PR ;
- **ni force-push ni suppression** de `main` ;
- **contrôles CI requis** pour fusionner : `Build & test (.NET)`, `Build (React)`,
  `Security · Dependencies (Trivy fs)`, `Security · IaC (Trivy config)`, `Security · Image ui (Trivy image)` ;
- conversations de revue résolues avant fusion ;
- **aucune dérogation**, y compris pour les administrateurs.

**Étape suivante :** les contrôles encore rouges à cause des failles volontaires (SAST → F1,
Secrets et images .NET → F5) seront ajoutés aux contrôles requis, avec `Security gate`, dès que F1, F2,
F3 et F5 seront corrigées. Les exiger dès maintenant bloquerait toute fusion.

**Revue :** 0 approbation requise tant que le dépôt n'a qu'un contributeur actif (on ne peut pas
approuver sa propre PR). Passer à 1 dès que l'équipe travaille sur le dépôt.

## Cycle de travail

```bash
git switch main && git pull
git switch -c fix/F2-idor            # une branche par sujet
# ... modifications + commits ...
git push -u origin fix/F2-idor
gh pr create --fill                  # la CI s'exécute sur la PR
gh pr checks --watch                 # suivre les contrôles
gh pr merge --squash --delete-branch # possible seulement si les contrôles requis sont verts
```

Nommage des branches : `fix/Fx-...` (correction d'une faille du registre), `feat/...`, `ci/...`,
`docs/...`, `chore/...`. Messages de commit au format *Conventional Commits*
(`fix(security): F2 ...`, `ci(security): ...`).

## Où tester

| Environnement | Usage | Commande |
|---------------|-------|----------|
| CI d'une PR | builds, tests unitaires, 5 contrôles de sécurité | automatique |
| VM : minikube `amcart` | environnement dédié de test et de démonstration | `git switch <branche>` puis `deploy/scripts/deploy-minikube.sh` |
| Cluster éphémère (kind) dans la CI | DAST après déploiement (§4.6) | à venir |

## Où ranger les tests et les preuves

- **Tests** : dans le dépôt, rejoués par la CI à chaque PR.
  - tests unitaires : `src/Services/*/*.UnitTests/` (tests de non-régression des failles corrigées) ;
  - vérifications du déploiement : `deploy/scripts/verify-hardening.sh` ;
  - tests dynamiques : `tests/dast/` (à venir).
- **Preuves** (rapport et soutenance) : `docs/evidence/`. Voir `docs/evidence/README.md`.

## Démonstration « le pipeline bloque »

Ouvrir une PR qui ajoute un **faux** secret (valeur de test, jamais un secret réel : GitHub conserve
les commits d'une PR même fermée). Montrer le contrôle *Secrets* rouge et la fusion bloquée, puis
fermer la PR sans fusionner et supprimer la branche.
