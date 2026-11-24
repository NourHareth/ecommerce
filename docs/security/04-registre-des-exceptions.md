# Registre des exceptions

Règles : voir `03-politique-de-blocage.md` §3. Toute exception expirée doit être retirée ou renouvelée,
avec une nouvelle justification.

| ID | Outil | Règle / CVE | Fichier | Justification | Responsable | Créée | Expire | Statut |
|----|-------|-------------|---------|---------------|-------------|-------|--------|--------|
| EXC-001 | Trivy config | KSV-0109 (HIGH) « ConfigMap stores secrets » | `deploy/k8s/base/postgres.yaml` uniquement | **Faux positif.** La ConfigMap `postgres-init` contient `LOGIN PASSWORD :'users_pw'`, une référence de variable psql ; la valeur vient du Secret `postgres-credentials` à l'exécution. L'exception est limitée à ce fichier : KSV-0109 continue de détecter un vrai secret dans toute autre ConfigMap. | Nour | 2026-11-24 | 2026-12-24 | Active |
