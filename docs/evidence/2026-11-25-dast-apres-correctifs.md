# 2026-11-25 · DAST après correctifs · F1, F2, F3 ne sont plus détectées

- **Exécution :** [CI #45510111502](https://github.com/NourHareth/ecommerce/actions/runs/45510111502), PR #4 (`fix/F1-F2-F3` @ `1696c69`), fusionnée dans `main` en `ac37cdd`
- **Environnement et outils :** identiques à l'exécution « avant » (`2026-11-24-dast-avant-correctifs.md`) : cluster kind jetable, manifestes durcis, ZAP 2.17.0 authentifié, `tests/dast/business-logic.sh`
- **Rapports complets :** artefact `dast-reports` de l'exécution (conservé 30 jours)

## Contrôles de logique métier

| Contrôle | Avant | Après | Attendu |
|---|---|---|---|
| F2 témoin : alice lit sa propre commande | 200 | 200 | 200 |
| F2 bob lit la commande d'alice | **200** (vulnérable) | **404** | 404 |
| F3 `unitPrice` 0.01 envoyé par le client | **0.01** (vulnérable) | **49.99** | 49.99 |

## ZAP

| | Avant | Après |
|---|---|---|
| Alertes High **bloquantes** (avec preuve) | **1** : SQL Injection, `quick-search [q]`, une apostrophe → HTTP 500 | **0** |
| `quick-search` avec une apostrophe | HTTP 500 (erreur de syntaxe SQL) | plus d'erreur : l'apostrophe est traitée comme du texte |
| SQLi par déduction seule (EXC-002, tri) | 114 instances | 118 instances, même schéma de faux positifs |

## Résultat global de la PR #4

SAST ✅ (la règle `efcore-raw-sql-non-constant` ne trouve plus de SQL brut), DAST ✅, Build & test ✅
(dont les 9 tests de non-régression), Dependencies ✅, IaC ✅, Image ui ✅. Restent rouges, comme
prévu : *Secrets* et *Image user/product*, à cause de F5, qui n'est pas traitée dans cette PR.

## Nouveau constat : C5

Le même scan montre qu'un octet NUL (`q=%00`) provoque une **erreur 500** sur `quick-search`.

- Ce n'est **pas** une injection : la valeur est transmise en paramètre et PostgreSQL refuse un texte
  contenant le caractère NUL.
- C'est une **erreur non gérée** (OWASP A10:2025, *Mishandling of Exceptional Conditions*).
- Elle est inscrite au registre sous l'identifiant C5.
