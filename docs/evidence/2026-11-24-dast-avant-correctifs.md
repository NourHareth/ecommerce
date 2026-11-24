# 2026-11-24 · DAST avant correctifs · confirmation dynamique de F1, F2, F3

- **Exécution :** [CI #45502066755](https://github.com/NourHareth/ecommerce/actions/runs/45502066755), branche `feat/dast` @ `4c5df61`
- **Environnement :** cluster kind jetable (Kubernetes v1.37.0) sur le runner GitHub, manifestes durcis + overlay `dast`, secrets aléatoires
- **Outils :** `tests/dast/business-logic.sh` ; OWASP ZAP 2.17.0 `zap-api-scan`, authentifié (jeton de la cliente de test « alice »), via la passerelle nginx
- **Rapports complets :** artefact `dast-reports` de l'exécution (conservé 30 jours)

## Contrôles de logique métier

| Contrôle | Résultat | Attendu | Observé |
|---|---|---|---|
| F2 témoin : alice lit sa propre commande | PASS | 200 | 200 |
| F2 bob lit la commande d'alice | **FAIL (vulnérable)** | 404 | **200** |
| F3 `unitPrice` envoyé par le client ignoré | **FAIL (vulnérable)** | 49.99 | **0.01** |

## ZAP : alertes High

| Classement | Alerte | Emplacement | Preuve |
|---|---|---|---|
| **Bloquante** (F1) | SQL Injection (40018, CWE-89) | `GET /api/v1/products/quick-search [q]` | une apostrophe provoque `HTTP/1.1 500 Internal Server Error` (erreur de syntaxe SQL) |
| Tri, EXC-002 (114 instances) | SQL Injection (40018), par déduction seule | endpoints LINQ paramétrés (`/products [search]`, `/checkout/orders [city]`, `/auth/login [email]`…) | aucune : comparaison de pages `AND 1=1` / `AND 1=2` ou `22-2` / `20` |

Alertes Medium, Low et Info (non bloquantes, 691 instances) : erreurs 500 génériques, en-tête
`Cross-Origin-Resource-Policy` absent, horodatages Unix dans les réponses, jeton de vérification dans
l'URL de `verify-email`. Elles sont à revoir et pourraient alimenter le durcissement « bonus ».

## Lecture

- Les trois failles introduites sont **confirmées sur l'application en marche**.
- F2 et F3 n'étaient détectées par **aucun** contrôle statique : ce sont des erreurs de logique métier.
  Il faut des tests qui connaissent les règles (à qui appartient une commande, quel est le vrai prix).
- ZAP détecte F1 par l'erreur qu'il provoque, mais il produit aussi 114 faux positifs par déduction.
  D'où la règle « High avec preuve » de la politique.
