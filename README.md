AURA-GRAPH
AI-Assisted Infrastructure Intelligence & Risk Analysis
Graph Hacks 2026 · WeMakeDevs × FalkorDB
Primary track: Agents That Act on Connected Data
Repository: https://github.com/Prateek1122-d/DarkData-GraphOps12
Live deployment: https://darkdata-graphops12.onrender.com/
AURA-GRAPH is an infrastructure intelligence dashboard for exploring relationships between storage buckets, data pipelines, and application services. It combines an interactive graph view with backend analysis workflows to help engineers investigate lineage, understand dependencies, and review the potential impact of cleanup decisions.
Infrastructure risk is often a relationship problem: a resource that appears unused in isolation may still be connected to a pipeline or production service.

The problem
Infrastructure resources are interconnected. A bucket may be read by a pipeline, while a production service depends on that pipeline. Looking at a resource in isolation can hide indirect dependencies and make cleanup decisions risky.
AURA-GRAPH aims to help operators answer:
- Which pipelines read from this bucket?
- Which services depend on those pipelines?
- Is a production dependency connected to this resource?
- What graph evidence should be reviewed before cleanup?
What it does
1. Graph exploration: inspect connected infrastructure entities in an interactive network view.
2. Lineage investigation: retrieve context for a selected bucket and inspect connected dependencies.
3. Risk analysis: combine available infrastructure telemetry and dependency context in backend analysis workflows.
4. Safer cleanup review: identify production dependencies that should prevent an unsafe cleanup decision.
5. Explainable investigation: expose relationship context and analysis results for operator review.
AURA-GRAPH is a decision-support prototype. Do not treat a risk verdict as authorization to modify real infrastructure.
Why FalkorDB?
The core information is not only the properties of individual resources; it is how those resources connect. A graph database represents infrastructure objects as nodes and their dependencies as relationships. This makes multi-hop path traversal a natural way to investigate indirect impact.
FalkorDB is the graph data layer used by the backend for connected infrastructure context. Its OpenCypher/Cypher query capabilities allow the application to express relationship patterns and retrieve connected services and pipelines. The graph is intended to contribute to lineage and dependency analysis, not merely to decorate the dashboard.
Important: development versions have included an in-memory/demo fallback. A fallback result must never be described as a live FalkorDB-derived result. Verify reasoning_source and the actual query response during the demo.
Graph data model
The following labels and relationship patterns are reflected in the application's lineage logic. Confirm exact properties and directions against current seed data and graph before extending the model.
Nodes
Label	Meaning
Bucket	Storage resource
Pipeline	Data-processing pipeline
Service	Application or infrastructure service


Relationships
Pattern	Meaning
(:Pipeline)-[:READS_FROM]->(:Bucket)	Pipeline reads from a bucket
(:Service)-[:DEPENDS_ON]->(:Pipeline)	Service depends on a pipeline


Conceptual path:
(:Service {env: "PRODUCTION"})
       -[:DEPENDS_ON]->
(:Pipeline)
       -[:READS_FROM]->
(:Bucket)
Representative Cypher query
The following query illustrates the relationship traversal used by the lineage investigation. Adapt parameter handling and tenant/owner filtering to the exact deployed schema.
MATCH path =
  (s:Service {env: 'PRODUCTION'})
  -[:DEPENDS_ON*1..3]->
  (p:Pipeline)
  -[:READS_FROM]->
  (b:Bucket {id: $bucket_id})
RETURN
  b.id AS bucket_id,
  collect(DISTINCT s.id) AS production_services,
  collect(DISTINCT p.id) AS connected_pipelines,
  max(length(path)) AS maximum_hops
This pattern anchors the query on a bucket, traverses up to three dependency hops from a production service toward a pipeline, then follows the pipeline's READS_FROM relationship to the bucket. It returns connected services, pipelines, and path depth.
Use parameterized queries where supported. Validate tenant ownership at the application boundary; do not concatenate untrusted input into Cypher strings.
Architecture
Browser dashboard
HTML · CSS · JavaScript · Vis.js Network
             | HTTP / JSON
             v
FastAPI backend
API routes · tenant context · analysis workflows
             | FalkorDB client
             v
FalkorDB graph
Bucket · Pipeline · Service
READS_FROM · DEPENDS_ON
- Frontend: HTML, CSS, JavaScript, Vis.js Network 9.1.2.
- Backend: Python and FastAPI.
- Graph layer: FalkorDB Cloud and Cypher queries.
- Analysis: backend agent workflows using available telemetry and dependency context.
- Server: Uvicorn.
Run locally
Requirements
- Python 3.10+ (development environment: Python 3.12)
- Git
- Access to a FalkorDB instance
- Modern web browser
1. Clone
git clone https://github.com/Prateek1122-d/DarkData-GraphOps12.git
cd DarkData-GraphOps
2. Create a virtual environment
Windows PowerShell:
python -m venv .venv
.venv\\Scripts\\Activate.ps1
macOS/Linux:
python3 -m venv .venv
source .venv/bin/activate
3. Install dependencies
cd backend
pip install -r requirements.txt
4. Configure FalkorDB
Create .env in the repository root (one level above backend) with your own connection details:
FALKORDB_HOST=your-falkordb-host
FALKORDB_PORT=your-falkordb-port
FALKORDB_USER=your-falkordb-username
FALKORDB_PASSWORD=your-falkordb-password
FALKORDB_SSL=true
Use the SSL value required by your provider. The backend expects FALKORDB_USER, not FALKORDB_USERNAME. Never commit .env or expose credentials in screenshots, logs, or videos.
5. Start the backend
Run from the backend directory:
python -m uvicorn main:app --reload --port 8000
Open http://127.0.0.1:8000/. Keep the terminal running. Do not open index.html directly from the file system; use the FastAPI URL so frontend API calls reach the backend.
6. Check service endpoints
http://127.0.0.1:8000/api/health
http://127.0.0.1:8000/api/graph/stats
http://127.0.0.1:8000/api/buckets/dark
A successful health response does not prove that every analysis result came from FalkorDB. Check graph connection fields and reasoning_source.
API overview
These routes have been used by the application during development. Verify current request bodies, headers, response schemas, and authorization requirements in backend/main.py before relying on them.
Route	Purpose
GET /api/health	Backend and graph connection health
GET /api/graph/stats	Graph statistics
GET /api/buckets/dark	Bucket information for the dashboard
GET /api/graphrag/context/{bucket_id}	Lineage and graph context for a bucket
POST /api/agent/analyze-prune	Analyze a proposed cleanup
POST /api/agent/execute-prune	Execute cleanup workflow subject to safeguards


Demo and deployment
- Live app: https://darkdata-graphops12.onrender.com/
- YouTube demo: add a public or unlisted video URL before submitting.
- Source: https://github.com/Prateek1122-d/DarkData-GraphOps12
Suggested demo flow:
1. Open the dashboard and show the graph.
2. Select a bucket and run Inspect Lineage.
3. Show the actual API response and connected production dependencies.
4. Run risk analysis and explain the returned verdict and evidence.
5. Demonstrate a blocked or protected production-dependent cleanup.
6. Explain whether each result came from FalkorDB or a fallback path.
Use authorized public or synthetic data in the demo. Hide secrets and private infrastructure identifiers.
Security and safeguards
- Use only public, synthetic, or otherwise authorized data.
- Keep credentials in environment variables; add .env to .gitignore.
- Verify .env is not tracked by Git before pushing.
- Apply tenant-aware access checks to graph reads.
- Treat cleanup as potentially destructive and require appropriate authorization/review.
- A graph metadata/pruned-state change is not the same as deleting an external cloud storage object. Claim external deletion only if a verified integration performs it.
- Keep secrets and sensitive payloads out of logs.
Limitations and verification
AURA-GRAPH is an active prototype. For a fair technical evaluation:
1. Distinguish database connectivity from graph-backed reasoning.
2. If reasoning_source indicates an in-memory/demo fallback, label it honestly.
3. Verify bucket ID, tenant, returned services, pipelines, hop depth, and source of reasoning against the live graph.
4. Verify whether cleanup changes graph metadata only or also affects external cloud resources.
5. Confirm the live deployment is reachable before recording the demo.
These are important verification points; behavior can vary by code version and deployment configuration.
AI-use disclosure
AI coding assistants were used to support parts of development, including debugging, code review, implementation suggestions, and documentation drafting. The project author is responsible for reviewing, testing, understanding, and explaining the submitted code, graph model, Cypher queries, architecture, and technical decisions. Update this disclosure if additional AI tools were used.
Hackathon track
Primary track: Agents That Act on Connected Data
AURA-GRAPH targets this track because its intended workflow investigates connected infrastructure data and uses dependency context to support risk-aware operational decisions. The judging demo should show real graph traversal, graph-informed analysis, and explainable outcomes—not visualization alone.
References
- Graph Hacks 2026 — official challenge
- Graph Hacks — official rules
- FalkorDB documentation
- FalkorDB Python client
Project: AURA-GRAPH
Maintainer: Prateek Gupta
Event: Graph Hacks 2026 · WeMakeDevs × FalkorDB
