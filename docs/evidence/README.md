# Preuves

Sorties courtes et datées qui servent de preuves pour le rapport et la soutenance. Les liens vers les
exécutions de CI sont consignés dans `docs/security/01-registre-des-failles.md`.

## Règles

- **Nom :** `AAAA-MM-JJ-<sujet>.txt` (ex. `2026-11-24-verify-hardening.txt`, `2026-11-25-dast-avant-correctifs.txt`).
- **En tête de fichier :** date, commit (`git rev-parse --short HEAD`), environnement (CI, VM), commande exécutée.
- **Contenu :** sortie texte ou résumé. Pas de rapport brut volumineux (les rapports complets sont des artefacts de CI).
- **Jamais de secret, de jeton ni de donnée personnelle réelle.** Vérifier la sortie avant de la commiter.
- **Captures d'écran :** directement dans le rapport, pas dans le dépôt.
- **Artefacts de CI :** conservés 30 jours. Télécharger ceux dont on a besoin avant la soutenance :
  `gh run download <run-id> -n <artefact> -D docs/evidence/<dossier>`.

## Exemple

```bash
{ echo "# $(date -I) · commit $(git rev-parse --short HEAD) · VM minikube amcart"
  echo "# deploy/scripts/verify-hardening.sh"
  deploy/scripts/verify-hardening.sh
} 2>&1 | tee "docs/evidence/$(date -I)-verify-hardening.txt"
```
