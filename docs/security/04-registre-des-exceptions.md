# Registre des exceptions

Règles : voir `03-politique-de-blocage.md` §3. Toute exception expirée doit être retirée ou renouvelée,
avec une nouvelle justification.

| ID | Outil | Règle / CVE | Fichier | Justification | Responsable | Créée | Expire | Statut |
|----|-------|-------------|---------|---------------|-------------|-------|--------|--------|
| EXC-002 | ZAP (DAST) | 40018 « SQL Injection », instances **sans preuve** (déduction booléenne ou arithmétique) | toutes les API, **sauf** les instances avec preuve, qui restent bloquantes | **Faux positifs.** 114 instances sur des endpoints exclusivement LINQ (paramétrés par EF Core), dont les réponses varient d'une requête à l'autre. Elles restent listées dans le rapport pour être revues. Le risque résiduel (injection aveugle réelle) est couvert par la règle SAST `efcore-raw-sql-non-constant` et la revue de code. | Nour | 2026-11-25 | 2026-12-25 | Active |
| EXC-001 | Trivy config | KSV-0109 (HIGH) « ConfigMap stores secrets » | `deploy/k8s/base/postgres.yaml` uniquement | **Faux positif.** La ConfigMap `postgres-init` contient `LOGIN PASSWORD :'users_pw'`, une référence de variable psql ; la valeur vient du Secret `postgres-credentials` à l'exécution. L'exception est limitée à ce fichier : KSV-0109 continue de détecter un vrai secret dans toute autre ConfigMap. | Nour | 2026-11-24 | 2026-12-24 | Active |
