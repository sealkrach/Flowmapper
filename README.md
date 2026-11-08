# FlowMapper — des flux Illumio aux architectures applicatives

FlowMapper ingère les flux réseau collectés par Illumio (VEN → PCE), reconstruit les
architectures applicatives sous forme de graphe (applications, tiers, dépendances, services
partagés) et expose le tout à un agent LangGraph capable de répondre à des questions
d'architecture et de proposer des labels pour les workloads non classés.

```
Illumio PCE ──┬─ export CSV Explorer ───────┐
              ├─ API traffic_flows/async ───┼─► parsers ─► FlowGraph ─► découverte ─► exports (Cytoscape, Mermaid, Markdown, GraphML)
              └─ syslog / Fluentd (JSON) ───┘                 │                │
                                                              │                └─► UI web (FastAPI + Cytoscape.js)
                                                              └─► outils LangChain ─► agent LangGraph (chat)
```

## Démarrage rapide

```bash
pip install -e .                 # ou: pip install .
cp .env.example .env             # clé LLM + réglages
flowmapper demo                  # génère un dataset synthétique et sert l'UI sur http://127.0.0.1:8000
```

Avec vos propres exports :

```bash
flowmapper stats   exports/explorer_export.csv            # résumé + applications découvertes
flowmapper report  exports/*.log --app "E-Commerce"        # rapport Markdown d'une application
flowmapper report  exports/*.json --format mermaid         # carte applicative Mermaid
flowmapper serve   exports/explorer_export.csv exports/syslog.log   # UI + API, plusieurs fichiers fusionnés
flowmapper chat    exports/explorer_export.csv             # agent en ligne de commande
flowmapper fetch   --start 2026-10-01 --end 2026-11-01 -o pce.json   # requête async Explorer sur le PCE
flowmapper snapshot exports/*.csv -o snapshot              # copie statique de l'UI à partager (sans backend)
```

Docker : `docker compose up --build` (déposez les exports dans `./exports`, renseignez `FLOWMAPPER_FILES`).

## Sources acceptées (détection automatique)

| Source | Comment l'obtenir | Particularités |
|---|---|---|
| **Export CSV Explorer** | PCE UI → Explorer → Export | En-têtes `Consumer/Provider` (≤ 21.x) ou `Source/Destination` (≥ 22.x) ; toute colonne `<côté> <type de label>` devient un label (types custom inclus). Les dates sans fuseau sont supposées UTC. |
| **API REST** | `POST /api/v2/orgs/:id/traffic_flows/async_queries` puis `GET …/download` (`flowmapper fetch` le fait) | Labels `[{key,value}]`, `num_connections`, `policy_decision`, `draft_policy_decision`, `timestamp_range`, IP lists. |
| **Syslog / Fluentd** | Export des *traffic flow summaries* du PCE, un objet JSON par ligne (préfixe syslog toléré) | `pd` 0/1/2/3 → allowed / potentially_blocked / blocked / unknown, `dir`, `pn`, `src_labels`/`dst_labels`. Pas de nom d'IP list : fournissez `FLOWMAPPER_IP_LISTS`. |

Plusieurs fichiers peuvent être fusionnés (CLI, `POST /api/ingest`, bouton *Importer*).

## Ce que fait la découverte

1. **Normalisation** — chaque flux devient `src → dst` sur un service `(proto, port)` avec décision de policy, nombre de connexions, process, horodatages.
2. **Graphe workloads** — identité = hostname (sinon IP) ; les flux sont agrégés par paire et par service.
3. **Rôles** — label `role` Illumio en priorité, sinon déduction des ports servis (5432 → base de données, 6379 → cache, 443 → web…), sinon indices du hostname. Les services d'administration (ssh, agents de supervision) sont ignorés.
4. **Applications** — groupées par labels `app`+`env` (configurable). Les IP sans VEN sont regroupées par IP list ou par /24.
5. **Infra partagée** — un nœud consommé par ≥ 3 applications est marqué *partagé* (`infra` pour AD/DNS/NTP/syslog/monitoring, `service` pour une base ou un bus consommés par plusieurs applis). Masquée par défaut dans les diagrammes.
6. **Workloads sans label** — clusterisés par communautés de Louvain sur le trafic qu'ils échangent entre eux ; un nom est suggéré à partir des hostnames et des services. Les isolés (et les IP sans VEN hors IP list) sont *rattachés* à la seule application avec laquelle ils échangent (ex. une appliance HSM utilisée uniquement par Payments).
7. **Tiers** — à l'intérieur d'une application, distance au tier data dans le DAG des flux internes : front → middle → data.
8. Seuls les flux effectifs (allowed / potentially blocked / unknown) façonnent l'architecture ; les flux bloqués restent visibles mais ne créent ni rattachement ni dépendance.

## Enrichissement IA (human-in-the-loop)

Le pipeline de découverte est déterministe ; le LLM intervient en batch sur ce qu'il ne peut pas
trancher, et **ne modifie rien sans validation** :

- **Clusters sans label** → nom d'application, labels Illumio `app`/`env`, rôle par workload, justification.
- **Rôles inconnus** (ni label, ni port connu) → classe de rôle + libellé, justification.

```bash
flowmapper enrich exports/*.csv                 # propositions en attente, affichées
flowmapper enrich exports/*.csv --apply --min-confidence 0.8 -o proposals.json
FLOWMAPPER_AUTO_ENRICH=true flowmapper serve …  # lance l'enrichissement à chaque ingestion
```

Dans l'UI : bouton *Enrichir avec l'IA*, panneau *Propositions* (accepter / rejeter), marquage des
nœuds concernés ; une proposition acceptée renomme le cluster, enregistre les labels à poser et
force le rôle (`role_source = ai`). API : `POST /api/enrich`, `GET /api/proposals`,
`POST /api/proposals/{clusters|workloads}/{id}` `{action}`. L'agent dispose de
`run_ai_enrichment`, `list_proposals`, `review_proposal`, `compare_periods`.

## Diff entre deux périodes (« qu'est-ce qui a changé dans CRM ce mois-ci ? »)

Les flux sont découpés en deux fenêtres temporelles (par défaut B = les N derniers jours, A = les N
jours précédents, bornées à l'étendue du dataset), un graphe est construit par fenêtre, puis comparé
structurellement : applications et workloads apparus/disparus, workloads ayant changé d'application,
dépendances applicatives ajoutées/retirées, nouveaux flux et flux disparus, **changements de décision de
policy** (ex. potentially_blocked → blocked après enforcement), variations de volume ×2/÷2 (en conn./jour),
rôles et tiers modifiés. Les flux d'administration et l'infra partagée autorisée sont ignorés pour ne
garder que l'architecture.

```bash
flowmapper diff exports/*.csv --app CRM --days 30            # rapport Markdown
flowmapper diff exports/*.csv --split 2026-11-01             # A = avant, B = après
flowmapper diff export_novembre.csv --baseline export_octobre.csv --app CRM   # deux exports
```

UI : section *Comparer deux périodes* → rapport dans le panneau de détail et surlignage sur le graphe
(vert apparu, rouge disparu, orange modifié). API : `GET /api/diff?app=&days=&split=&a_start=…`,
`POST /api/baseline` puis `GET /api/diff?mode=baseline`. Agent : `compare_periods` — l'outil renvoie le
diff structuré, l'agent rédige le narratif en commençant par les changements significatifs et les risques.

## UI

- Vue **Applications** (fcose) ou **Workloads** (diagramme déterministe : environnements → applications → tiers).
- Filtres : environnement, focus sur une application et ses voisines, infra partagée, IP externes, flux d'administration, décisions de policy, connexions minimales, ports, recherche.
- Panneau de détail : tiers, dépendances entrantes/sortantes avec services, flux à risque, renommage d'un cluster (modèle local, rien n'est écrit dans le PCE).
- Exports PNG, Mermaid, rapport Markdown, GraphML (Gephi / yEd). Thème clair/sombre.
- Chat avec l'agent et enrichissement IA (nécessitent une clé LLM).

## Agent

`FLOWMAPPER_MODEL` accepte n'importe quel modèle LangChain (`anthropic:claude-sonnet-5-5`,
`openai:gpt-5`, `ollama:qwen3`…). Outils exposés : `graph_overview`, `describe_application`,
`get_dependencies`, `search_flows`, `find_path`, `list_unlabeled_clusters`,
`rename_application`, `blocked_flows`, `workload_details`, `export_architecture`,
`run_ai_enrichment`, `list_proposals`, `review_proposal`, `compare_periods`.

Questions typiques : « Décris l'architecture de l'application CRM », « De quoi dépend Payments ? »,
« Qui appelle la base ecom-pg01 ? », « Propose un nom et des labels pour le cluster 1 »,
« Quels flux seront bloqués si je passe en enforcement ? », « Chemin entre Internet et pay-db01 ».

## API

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/api/ingest` (multipart `files`, `?replace=`) | importer un ou plusieurs exports |
| POST | `/api/ingest/pce` | requête Explorer async sur le PCE (variables `ILLUMIO_*`) |
| GET | `/api/graph?level=app|workload&env=&app=&hide_infra=&min_connections=&decisions=&ports=` | éléments Cytoscape |
| GET | `/api/apps`, `/api/apps/{name}` | applications et détail (tiers, dépendances, Mermaid, Markdown) |
| POST | `/api/apps/{key}/rename` | renommer / proposer des labels |
| GET | `/api/workloads/{name}` | détail d'un workload |
| GET | `/api/export?format=mermaid|markdown|graphml|json` | exports |
| POST | `/api/options` | re-paramétrer la découverte (group_by, seuil partagé, IP lists…) |
| POST | `/api/chat` `{message, thread_id}` | agent |

## Structure

```
flowmapper/
  models.py        modèle normalisé (Endpoint, Flow, PolicyDecision)
  parsers/         explorer_csv.py · api_json.py · syslog_json.py · détection de format
  knowledge.py     table ports → services / classes de rôle, services d'administration
  graph.py         FlowGraph : nœuds, arêtes agrégées, groupes, graphe applicatif, dépendances
  discovery.py     groupes labellisés, clustering Louvain, rattachements, infra partagée, tiers
  exports.py       Cytoscape JSON, Mermaid, Markdown, GraphML, JSON
  pce_client.py    client REST PCE (async queries)
  store.py         état partagé (flux, graphe, renommages, propositions IA, rôles forcés)
  enrich.py        enrichissement IA batch (sortie structurée) + validation HITL
  diff.py          diff structurel entre deux périodes / deux exports, rendu Markdown
  agent/           tools.py (LangChain tools) · agent.py (create_agent + mémoire par thread)
  api/             main.py (FastAPI) · static/ (UI Cytoscape, vendor bundlé pour usage hors-ligne)
  snapshot.py      export statique de l'UI
  sample.py        générateur du dataset synthétique
tests/             pytest (parsers, découverte, exports, API)
```

## Limites et pistes

- Les flux rapportés par les deux VEN (sortant côté source, entrant côté destination) sont additionnés ; les volumes sont donc des ordres de grandeur, pas des compteurs exacts.
- Les rôles déduits des ports sont des heuristiques : étendre `KNOWN_SERVICES` dans `knowledge.py` pour vos middlewares.
- Pistes : persistance (SQLite/Neo4j) et historisation des snapshots, génération de rulesets Illumio à partir des dépendances validées, application des labels validés dans le PCE via l'API.
