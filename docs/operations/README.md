# Documents opérationnels — Portail Captif SSO RBER

| Document | Rôle | Statut |
|---|---|---|
| `Dossier_fenetre_PROXY_protocol.md` | Exécution de la fenêtre PROXY protocol (dernier prérequis du pilote T-INT) : le pourquoi en langage simple, préparation J-1, déroulé minuté, vérifications, rollback | **Suspendu** — tentative du 20/11 annulée (rollback), remplacé par le jeton d'IP ; à reprendre plus tard avec l'équipe infra, voir `Jeton_IP.md` |
| `Jeton_IP.md` | Comment le portail connaît l'adresse réelle du client sans PROXY protocol (option retenue le 21/11) | En service |
| `Actions_Harris_banc_UAC.md` | Re-câblage du banc de test UAC vers la chaîne de production | Exécuté le 16/11/2026 (relevés conformes) |
| `Audit_code_v1_IT-Captive-Portal.md` | Audit de la v1 (branche `ojuwoni`) : pourquoi la v2 est une réécriture | Référence historique |

Les documents de cadrage (DAT v2.1, protocoles A1/T-INT, plannings,
relevés de test) sont au format Word et conservés dans l'espace projet
IDADU TECH / RBER, hors du dépôt.

Conventions apprises sur ce cluster (à connaître pour tout déploiement) :
- Tout nouveau backend servi par l'ingress exige une NetworkPolicy
  `allow-egress-to-<app>` dans le namespace `haproxy-controller`
  (default-deny strict) — sans elle : 503 « no server available ».
- Les Ingress doivent utiliser `spec.ingressClassName: haproxy`
  (l'annotation dépréciée est ignorée par le contrôleur).
- Tout nouveau domaine public doit être ajouté à l'ACL `host_known`
  du frontend HTTP du HAProxy externe (sinon il perd sa redirection
  https au profit du portail captif).
