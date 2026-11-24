# Tests dynamiques (DAST, §4.6)

Exécutés par le job CI `Security · DAST` contre **notre propre** déploiement, dans un cluster kind
jetable (cahier §6 : aucun test contre un système tiers).

| Script | Rôle |
|--------|------|
| `seed.sh` | crée un admin, deux clients (alice, bob) avec des mots de passe aléatoires générés à chaque exécution, un produit et une commande d'alice |
| `business-logic.sh` | F2 : bob ne doit pas lire la commande d'alice (404 attendu). F3 : un `unitPrice` envoyé par le client doit être ignoré |
| `zap-scan.sh` | scan ZAP authentifié des API UserService et ProductService (descriptions OpenAPI), via la passerelle ; échec si alerte High |
| `lib.sh` | fonctions communes |

Rapports : artefact `dast-reports` de l'exécution CI (`business-logic.md`, `zap-summary.md`, rapports ZAP
HTML et JSON), et résumé dans l'onglet *Summary* du job.

## Lancer à la main contre la VM

Sur la VM, avec l'application déployée et un `port-forward` vers `svc/ui` sur le port 8080. Les
descriptions OpenAPI ne sont exposées qu'avec l'overlay `dast`, donc `zap-scan.sh` ne fonctionne que
contre ce déploiement :

```bash
OUT_DIR=/tmp/dast tests/dast/seed.sh
OUT_DIR=/tmp/dast tests/dast/business-logic.sh
```
