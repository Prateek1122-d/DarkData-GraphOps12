#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
AURA-GRAPH // DarkData-GraphOps Platform — Multi-Tenant FalkorDB Cloud Seeder
File        : backend/seed_graph.py
Lead Owner  : Prateek Gupta (@prateek)
Description : Populates and verifies 3 isolated multi-tenant graphs in FalkorDB
              Cloud (`darkdata_graphops`, `fincorp_sec_graph`, `healthcare_hipaa_graph`)
              with 45+ operational nodes, 81+ lineage relationships, episodic
              memories (:Memory), procedural rules (:ProceduralRule), and
              multi-hop blast-radius verification proofs.
================================================================================
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

try:
    from falkordb import FalkorDB
except ImportError:
    print(
        "[CRITICAL] The 'falkordb' package is not installed. "
        "Run: pip install falkordb"
    )
    sys.exit(1)

# ==============================================================================
# STRUCTURED LOGGING CONFIGURATION
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("darkdata.seeder")

# ==============================================================================
# FalkorDB credentials are provided via environment variables.
FALKORDB_HOST: str = os.getenv("FALKORDB_HOST", "").strip()
FALKORDB_PORT: int = int(os.getenv("FALKORDB_PORT", "6379"))
FALKORDB_USER: str = os.getenv("FALKORDB_USER", "").strip()
FALKORDB_PASSWORD: str = os.getenv("FALKORDB_PASSWORD", "")
FALKORDB_SSL: bool = os.getenv("FALKORDB_SSL", "true").strip().lower() in {"1", "true", "yes", "on"}
RESET_EXISTING_GRAPH: bool = "--reset" in sys.argv

ARCHITECT_NAME: str = "Prateek Gupta"
ARCHITECT_HANDLE: str = "@prateek"

TENANT_GRAPHS: List[str] = [
    "darkdata_graphops",
    "fincorp_sec_graph",
    "healthcare_hipaa_graph",
]

TENANT_METADATA: Dict[str, Dict[str, str]] = {
    "darkdata_graphops": {
        "prefix": "ops",
        "domain": "OPS PRODUCTION CLOUD",
        "primary_service": "Auth-Service",
        "secondary_service": "Billing-Engine",
    },
    "fincorp_sec_graph": {
        "prefix": "fin",
        "domain": "CORE FINANCE & SETTLEMENT",
        "primary_service": "Billing-Engine",
        "secondary_service": "PaymentLedgerSvc",
    },
    "healthcare_hipaa_graph": {
        "prefix": "hlth",
        "domain": "HEALTHCARE HIPAA INFRASTRUCTURE",
        "primary_service": "Patient-Portal",
        "secondary_service": "Auth-Service",
    },
}


def utc_now_iso() -> str:
    """Returns the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def escape_cypher(val: Any) -> str:
    """Escapes special characters for safe Cypher string interpolation."""
    text = str(val if val is not None else "")
    return text.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')


# ==============================================================================
# MODULE 1: FALKORDB CLOUD CONNECTION SETUP
# ==============================================================================
def connect_falkordb_cloud() -> FalkorDB:
    """
    Initializes the Falkordb client from environment-provided credentials.
    """
    logger.info(
        f"Connecting to FalkorDB Cloud instance at {FALKORDB_HOST}:{FALKORDB_PORT} (user='{FALKORDB_USER}')..."
    )
    if not FALKORDB_HOST or not FALKORDB_USER or not FALKORDB_PASSWORD:
        raise RuntimeError("Set FALKORDB_HOST, FALKORDB_USER and FALKORDB_PASSWORD before seeding.")
    return FalkorDB(
        host=FALKORDB_HOST,
        port=FALKORDB_PORT,
        username=FALKORDB_USER,
        password=FALKORDB_PASSWORD,
        ssl=FALKORDB_SSL,
    )


# ==============================================================================
# MODULE 2: GRAPH SEEDING & INITIALIZATION (`seed_database()`)
# ==============================================================================
def seed_tenant_graph(client: FalkorDB, tenant: str) -> None:
    """
    Safely populates a single tenant graph with (destructive reset requires --reset):
      - Command Teams (:Team) led by @prateek
      - Production & Staging Services (:Service) including Auth-Service, Billing-Engine, Patient-Portal
      - ETL & Streaming Pipelines (:Pipeline) including ETL-Stream-A, Analytics-Pipeline
      - 12 Storage Buckets (:Bucket) with idle_days, cost, mass_tb, sensitivity, owner
      - 3 Autonomous Agents (:Agent) with [:HANDOFF_TO] coordination chains
      - Cross-Session Episodic Memories (:Memory) and Governance Rules (:ProceduralRule)
      - Full lineage relationships: [:DEPENDS_ON], [:READS_FROM], [:WRITES_TO], [:OWNED_BY], [:OWNS]
    """
    meta = TENANT_METADATA[tenant]
    p = meta["prefix"]
    now_iso = utc_now_iso()

    logger.info("--------------------------------------------------------------------")
    logger.info(f"Seeding Tenant Graph: '{tenant}' [{meta['domain']}] (Prefix: '{p}')")
    logger.info("--------------------------------------------------------------------")

    graph = client.select_graph(tenant)

    # Step 1: Protect existing data. Destructive reset requires an explicit --reset.
    existing = graph.query("MATCH (n) RETURN count(n) AS cnt")
    existing_count = int(existing.result_set[0][0]) if existing and existing.result_set else 0
    if existing_count and not RESET_EXISTING_GRAPH:
        raise RuntimeError(
            f"Refusing to overwrite {tenant}: it already contains {existing_count} nodes. "
            "Re-run with --reset only if you intentionally want to delete that tenant graph."
        )
    if existing_count and RESET_EXISTING_GRAPH:
        graph.query("MATCH (n) DETACH DELETE n")
        logger.warning("[%s] Explicit --reset used; existing tenant graph was cleared.", tenant)

    # Step 2: Create Command Teams (:Team) — Solo Architect @prateek
    teams_data = [
        {"id": "Arch:@prateek-Core", "name": "Core Cloud Architecture (@prateek)", "handle": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-SecOps", "name": "Security & PII Governance (@prateek)", "handle": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-CloudOps", "name": "Production Reliability SRE (@prateek)", "handle": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-AI", "name": "Autonomous AI & GraphRAG (@prateek)", "handle": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-Data", "name": "Data Engineering & ETL (@prateek)", "handle": ARCHITECT_HANDLE, "tier": "TIER_1"},
        {"id": "Arch:@prateek-QA", "name": "Staging & Load Validation (@prateek)", "handle": ARCHITECT_HANDLE, "tier": "TIER_2"},
        {"id": "Arch:@prateek-Audit", "name": "Statutory Compliance & Audit (@prateek)", "handle": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-FinOps", "name": "Cloud FinOps & Carbon ESG (@prateek)", "handle": ARCHITECT_HANDLE, "tier": "TIER_1"},
    ]

    for t in teams_data:
        graph.query(
            f"CREATE (:Team {{"
            f"id: '{escape_cypher(t['id'])}', "
            f"name: '{escape_cypher(t['name'])}', "
            f"lead: '{ARCHITECT_HANDLE}', "
            f"handle: '{ARCHITECT_HANDLE}', "
            f"owner: '{ARCHITECT_HANDLE}', "
            f"tier: '{escape_cypher(t['tier'])}', "
            f"created_at: '{now_iso}'"
            f"}})"
        )
    logger.info(f"[{tenant}] Created {len(teams_data)} Command Team nodes (Owner: {ARCHITECT_HANDLE}).")

    # Step 3: Create Services (:Service) — including Auth-Service, Billing-Engine, Patient-Portal
    services_data = [
        {"id": "BillingService", "alias": "Billing-Engine", "env": "PRODUCTION", "criticality": "CRITICAL", "sla": "99.999%", "team_id": "Arch:@prateek-Core"},
        {"id": "OrderService", "alias": "Order-Engine", "env": "PRODUCTION", "criticality": "CRITICAL", "sla": "99.995%", "team_id": "Arch:@prateek-CloudOps"},
        {"id": "FraudDetectionEngine", "alias": "Fraud-Engine", "env": "PRODUCTION", "criticality": "CRITICAL", "sla": "99.999%", "team_id": "Arch:@prateek-SecOps"},
        {"id": "AuthGateway", "alias": "Auth-Service", "env": "PRODUCTION", "criticality": "CRITICAL", "sla": "99.999%", "team_id": "Arch:@prateek-SecOps"},
        {"id": "PaymentLedgerSvc", "alias": "Patient-Portal", "env": "PRODUCTION", "criticality": "CRITICAL", "sla": "99.999%", "team_id": "Arch:@prateek-Core"},
        {"id": "CheckoutAPI", "alias": "Checkout-Gateway", "env": "PRODUCTION", "criticality": "CRITICAL", "sla": "99.995%", "team_id": "Arch:@prateek-CloudOps"},
        {"id": "TaxComplianceSvc", "alias": "Tax-Compliance", "env": "PRODUCTION", "criticality": "CRITICAL", "sla": "99.99%", "team_id": "Arch:@prateek-Audit"},
        {"id": "InvoiceGenerator", "alias": "Invoice-Service", "env": "PRODUCTION", "criticality": "HIGH", "sla": "99.95%", "team_id": "Arch:@prateek-Core"},
        {"id": "RecommendationEngine", "alias": "Recommender-AI", "env": "PRODUCTION", "criticality": "HIGH", "sla": "99.90%", "team_id": "Arch:@prateek-AI"},
        {"id": "SearchDiscoveryAPI", "alias": "Search-API", "env": "PRODUCTION", "criticality": "HIGH", "sla": "99.95%", "team_id": "Arch:@prateek-AI"},
        {"id": "StagingAnalyticsSvc", "alias": "Staging-Analytics", "env": "STAGING", "criticality": "LOW", "sla": "95.0%", "team_id": "Arch:@prateek-QA"},
        {"id": "StagingLoadRunner", "alias": "Staging-Load-Test", "env": "STAGING", "criticality": "LOW", "sla": "95.0%", "team_id": "Arch:@prateek-QA"},
        {"id": "DevModelTrainer", "alias": "Dev-ML-Trainer", "env": "STAGING", "criticality": "LOW", "sla": "95.0%", "team_id": "Arch:@prateek-AI"},
        {"id": "SandboxReplayWorker", "alias": "Sandbox-Worker", "env": "STAGING", "criticality": "LOW", "sla": "95.0%", "team_id": "Arch:@prateek-QA"},
    ]

    for sv in services_data:
        graph.query(
            f"CREATE (:Service {{"
            f"id: '{escape_cypher(sv['id'])}', "
            f"name: '{escape_cypher(sv['id'])}', "
            f"service_alias: '{escape_cypher(sv['alias'])}', "
            f"env: '{escape_cypher(sv['env'])}', "
            f"criticality: '{escape_cypher(sv['criticality'])}', "
            f"sla: '{escape_cypher(sv['sla'])}', "
            f"owner: '{ARCHITECT_HANDLE}', "
            f"team_id: '{escape_cypher(sv['team_id'])}'"
            f"}})"
        )
    logger.info(f"[{tenant}] Created {len(services_data)} Service nodes (10 Production, 4 Staging).")

    # Step 4: Create Pipelines (:Pipeline) — including ETL-Stream-A, Analytics-Pipeline
    pipelines_data = [
        {"id": "pipe-quarterly-recon", "alias": "ETL-Stream-A", "engine": "Spark-3.5", "status": "ACTIVE", "team_id": "Arch:@prateek-Data"},
        {"id": "pipe-click-ingest-v1", "alias": "Analytics-Pipeline", "engine": "Airflow-Legacy", "status": "DEPRECATED", "team_id": "Arch:@prateek-Data"},
        {"id": "pipe-kyc-verifier", "alias": "KYC-Stream-ETL", "engine": "Flink-Streaming", "status": "ACTIVE", "team_id": "Arch:@prateek-SecOps"},
        {"id": "pipe-edi-clearinghouse", "alias": "EDI-Settlement-Pipe", "engine": "Spark-Batch", "status": "ACTIVE", "team_id": "Arch:@prateek-Core"},
        {"id": "pipe-perf-replay", "alias": "Perf-Replay-Pipe", "engine": "Locust-Replay", "status": "IDLE", "team_id": "Arch:@prateek-QA"},
        {"id": "pipe-tax-exporter", "alias": "Tax-Audit-Pipe", "engine": "Spark-SQL", "status": "ACTIVE", "team_id": "Arch:@prateek-Audit"},
        {"id": "pipe-feature-hydrator", "alias": "AI-Feature-Hydrator", "engine": "Ray-FeatureStore", "status": "ACTIVE", "team_id": "Arch:@prateek-AI"},
        {"id": "pipe-core-stream-etl", "alias": "Core-Event-Stream", "engine": "Kafka-Flink", "status": "ACTIVE", "team_id": "Arch:@prateek-CloudOps"},
        {"id": "pipe-profile-sync", "alias": "Profile-CDC-Sync", "engine": "Debezium-CDC", "status": "ACTIVE", "team_id": "Arch:@prateek-Core"},
        {"id": "pipe-ml-feature-gen", "alias": "ML-Checkpoint-Pipe", "engine": "PyTorch-Loader", "status": "IDLE", "team_id": "Arch:@prateek-AI"},
        {"id": "pipe-audit-archiver", "alias": "HIPAA-Audit-Pipe", "engine": "Compliance-Sync", "status": "ACTIVE", "team_id": "Arch:@prateek-Audit"},
    ]

    for pl in pipelines_data:
        graph.query(
            f"CREATE (:Pipeline {{"
            f"id: '{escape_cypher(pl['id'])}', "
            f"name: '{escape_cypher(pl['id'])}', "
            f"pipeline_alias: '{escape_cypher(pl['alias'])}', "
            f"engine: '{escape_cypher(pl['engine'])}', "
            f"status: '{escape_cypher(pl['status'])}', "
            f"owner: '{ARCHITECT_HANDLE}', "
            f"team_id: '{escape_cypher(pl['team_id'])}'"
            f"}})"
        )
    logger.info(f"[{tenant}] Created {len(pipelines_data)} Data & AI Pipeline nodes.")

    # Step 5: Create 12 Storage Buckets (:Bucket) with idle_days, cost, mass_tb, sensitivity, owner
    buckets_data = [
        {
            "id": f"bkt-{p}-legacy-clickstream-2023",
            "idle_days": 312,
            "size_gb": 18900,
            "mass_tb": 18.9,
            "cost": 2268,
            "carbon_kg": 529.2,
            "sensitivity": "PUBLIC",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_A_SAFE_ORPHAN",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "team_id": "Arch:@prateek-Data",
            "readers": ["pipe-click-ingest-v1"],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-q3-aggregates-archive",
            "idle_days": 147,
            "size_gb": 12400,
            "mass_tb": 12.4,
            "cost": 1488,
            "carbon_kg": 347.2,
            "sensitivity": "INTERNAL",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_B_PROD_TRAP",
            "verdict_label": "[BLOCKED: LIVE PROD DEPENDENCY]",
            "team_id": "Arch:@prateek-Core",
            "readers": ["pipe-quarterly-recon"],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-staging-loadtest-artifacts",
            "idle_days": 189,
            "size_gb": 11200,
            "mass_tb": 11.2,
            "cost": 1344,
            "carbon_kg": 313.6,
            "sensitivity": "PUBLIC",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_A_SAFE_ORPHAN",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "team_id": "Arch:@prateek-QA",
            "readers": ["pipe-perf-replay"],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-dev-sandbox-ml-checkpoints",
            "idle_days": 204,
            "size_gb": 9400,
            "mass_tb": 9.4,
            "cost": 1128,
            "carbon_kg": 263.2,
            "sensitivity": "INTERNAL",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_A_SAFE_ORPHAN",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "team_id": "Arch:@prateek-AI",
            "readers": [],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-customer-kyc-raw-dumps",
            "idle_days": 118,
            "size_gb": 6800,
            "mass_tb": 6.8,
            "cost": 952,
            "carbon_kg": 190.4,
            "sensitivity": "PII_LOCKED",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_C_PII_HOLD",
            "verdict_label": "[COMPLIANCE HOLD: PII LOCKED]",
            "team_id": "Arch:@prateek-SecOps",
            "readers": ["pipe-kyc-verifier", "pipe-audit-archiver"],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-ab-test-orphaned-logs",
            "idle_days": 275,
            "size_gb": 7600,
            "mass_tb": 7.6,
            "cost": 912,
            "carbon_kg": 212.8,
            "sensitivity": "INTERNAL",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_A_SAFE_ORPHAN",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "team_id": "Arch:@prateek-FinOps",
            "readers": [],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-realtime-feature-store-cold",
            "idle_days": 103,
            "size_gb": 5800,
            "mass_tb": 5.8,
            "cost": 754,
            "carbon_kg": 162.4,
            "sensitivity": "INTERNAL",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_B_PROD_TRAP",
            "verdict_label": "[BLOCKED: LIVE PROD DEPENDENCY]",
            "team_id": "Arch:@prateek-AI",
            "readers": ["pipe-feature-hydrator"],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-partner-edi-settlements",
            "idle_days": 96,
            "size_gb": 5200,
            "mass_tb": 5.2,
            "cost": 676,
            "carbon_kg": 145.6,
            "sensitivity": "PII_LOCKED",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_C_PII_HOLD",
            "verdict_label": "[COMPLIANCE HOLD: PII LOCKED]",
            "team_id": "Arch:@prateek-Audit",
            "readers": ["pipe-edi-clearinghouse"],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-tax-audit-vault-2024",
            "idle_days": 164,
            "size_gb": 4300,
            "mass_tb": 4.3,
            "cost": 559,
            "carbon_kg": 120.4,
            "sensitivity": "PII_LOCKED",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_C_PII_HOLD",
            "verdict_label": "[COMPLIANCE HOLD: PII LOCKED]",
            "team_id": "Arch:@prateek-Audit",
            "readers": ["pipe-tax-exporter"],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-deprecated-cdn-access-logs",
            "idle_days": 340,
            "size_gb": 3000,
            "mass_tb": 3.0,
            "cost": 360,
            "carbon_kg": 84.0,
            "sensitivity": "PUBLIC",
            "is_dark": True,
            "pruned": False,
            "case_type": "CASE_A_SAFE_ORPHAN",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "team_id": "Arch:@prateek-FinOps",
            "readers": [],
            "writers": [],
        },
        {
            "id": f"bkt-{p}-prod-events-live",
            "idle_days": 0,
            "size_gb": 16000,
            "mass_tb": 16.0,
            "cost": 1920,
            "carbon_kg": 448.0,
            "sensitivity": "INTERNAL",
            "is_dark": False,
            "pruned": False,
            "case_type": "ACTIVE_HOT_STORAGE",
            "verdict_label": "[ACTIVE PRODUCTION STREAM]",
            "team_id": "Arch:@prateek-CloudOps",
            "readers": ["pipe-core-stream-etl"],
            "writers": ["pipe-core-stream-etl"],
        },
        {
            "id": f"bkt-{p}-prod-user-vault",
            "idle_days": 0,
            "size_gb": 14000,
            "mass_tb": 14.0,
            "cost": 1680,
            "carbon_kg": 392.0,
            "sensitivity": "PII_LOCKED",
            "is_dark": False,
            "pruned": False,
            "case_type": "ACTIVE_HOT_STORAGE",
            "verdict_label": "[ACTIVE PRODUCTION VAULT]",
            "team_id": "Arch:@prateek-SecOps",
            "readers": ["pipe-profile-sync"],
            "writers": ["pipe-profile-sync"],
        },
    ]

    for b in buckets_data:
        graph.query(
            f"CREATE (:Bucket {{"
            f"id: '{escape_cypher(b['id'])}', "
            f"name: '{escape_cypher(b['id'])}', "
            f"idle_days: {int(b['idle_days'])}, "
            f"size_gb: {int(b['size_gb'])}, "
            f"mass_tb: {float(b['mass_tb'])}, "
            f"cost: {int(b['cost'])}, "
            f"monthly_cost_usd: {int(b['cost'])}, "
            f"carbon_kg: {float(b['carbon_kg'])}, "
            f"sensitivity: '{escape_cypher(b['sensitivity'])}', "
            f"owner: '{ARCHITECT_HANDLE}', "
            f"is_dark: {'true' if b['is_dark'] else 'false'}, "
            f"pruned: {'false' if not b['pruned'] else 'true'}, "
            f"case_type: '{escape_cypher(b['case_type'])}', "
            f"verdict_label: '{escape_cypher(b['verdict_label'])}'"
            f"}})"
        )
    logger.info(f"[{tenant}] Created {len(buckets_data)} Bucket nodes (10 Dark >90d, 2 Active Hot).")

    # Step 6: Establish Relationships ([:DEPENDS_ON], [:READS_FROM], [:WRITES_TO], [:OWNED_BY], [:OWNS])
    service_to_pipeline_deps = [
        ("BillingService", "pipe-quarterly-recon"),
        ("BillingService", "pipe-edi-clearinghouse"),
        ("OrderService", "pipe-core-stream-etl"),
        ("FraudDetectionEngine", "pipe-kyc-verifier"),
        ("FraudDetectionEngine", "pipe-audit-archiver"),
        ("AuthGateway", "pipe-profile-sync"),
        ("PaymentLedgerSvc", "pipe-edi-clearinghouse"),
        ("CheckoutAPI", "pipe-core-stream-etl"),
        ("TaxComplianceSvc", "pipe-tax-exporter"),
        ("TaxComplianceSvc", "pipe-quarterly-recon"),
        ("InvoiceGenerator", "pipe-tax-exporter"),
        ("RecommendationEngine", "pipe-feature-hydrator"),
        ("RecommendationEngine", "pipe-profile-sync"),
        ("SearchDiscoveryAPI", "pipe-core-stream-etl"),
        ("StagingAnalyticsSvc", "pipe-click-ingest-v1"),
        ("StagingLoadRunner", "pipe-perf-replay"),
        ("DevModelTrainer", "pipe-ml-feature-gen"),
        ("SandboxReplayWorker", "pipe-perf-replay"),
        ("SandboxReplayWorker", "pipe-click-ingest-v1"),
    ]

    for s_id, p_id in service_to_pipeline_deps:
        graph.query(
            f"MATCH (s:Service {{id: '{s_id}'}}), (p:Pipeline {{id: '{p_id}'}}) "
            f"CREATE (s)-[:DEPENDS_ON {{hop_type: 'SERVICE_TO_PIPELINE'}}]->(p)"
        )

    service_to_service_deps = [
        ("OrderService", "BillingService"),
        ("OrderService", "PaymentLedgerSvc"),
        ("AuthGateway", "FraudDetectionEngine"),
        ("PaymentLedgerSvc", "TaxComplianceSvc"),
        ("CheckoutAPI", "PaymentLedgerSvc"),
        ("CheckoutAPI", "OrderService"),
        ("CheckoutAPI", "AuthGateway"),
        ("InvoiceGenerator", "BillingService"),
        ("SearchDiscoveryAPI", "RecommendationEngine"),
    ]

    for upstream_s, downstream_s in service_to_service_deps:
        graph.query(
            f"MATCH (s1:Service {{id: '{upstream_s}'}}), (s2:Service {{id: '{downstream_s}'}}) "
            f"CREATE (s1)-[:DEPENDS_ON {{hop_type: 'SERVICE_TO_SERVICE'}}]->(s2)"
        )

    # Wire Pipeline [:READS_FROM] and [:WRITES_TO] Bucket edges + Team [:OWNS] / [:OWNED_BY]
    for b in buckets_data:
        graph.query(
            f"MATCH (b:Bucket {{id: '{escape_cypher(b['id'])}'}}), (t:Team {{id: '{escape_cypher(b['team_id'])}'}}) "
            f"CREATE (t)-[:OWNS]->(b), (b)-[:OWNED_BY]->(t)"
        )
        for reader_pipe in b["readers"]:
            graph.query(
                f"MATCH (p:Pipeline {{id: '{escape_cypher(reader_pipe)}'}}), (b:Bucket {{id: '{escape_cypher(b['id'])}'}}) "
                f"CREATE (p)-[:READS_FROM]->(b)"
            )
        for writer_pipe in b["writers"]:
            graph.query(
                f"MATCH (p:Pipeline {{id: '{escape_cypher(writer_pipe)}'}}), (b:Bucket {{id: '{escape_cypher(b['id'])}'}}) "
                f"CREATE (p)-[:WRITES_TO]->(b)"
            )

    for sv in services_data:
        graph.query(
            f"MATCH (s:Service {{id: '{escape_cypher(sv['id'])}'}}), (t:Team {{id: '{escape_cypher(sv['team_id'])}'}}) "
            f"CREATE (t)-[:OWNS]->(s), (s)-[:OWNED_BY]->(t)"
        )

    for pl in pipelines_data:
        graph.query(
            f"MATCH (p:Pipeline {{id: '{escape_cypher(pl['id'])}'}}), (t:Team {{id: '{escape_cypher(pl['team_id'])}'}}) "
            f"CREATE (t)-[:OWNS]->(p), (p)-[:OWNED_BY]->(t)"
        )

    logger.info(f"[{tenant}] Established all [:DEPENDS_ON], [:READS_FROM], [:WRITES_TO], [:OWNED_BY], and [:OWNS] relationships.")

    # Step 7: Create Autonomous Agents (:Agent), Episodic Memories (:Memory), and Rules (:ProceduralRule)
    graph.query(
        f"CREATE "
        f"(a1:Agent {{id: 'ReconAgent', name: 'Recon (Scout)', role: 'Idle Storage & Carbon Scout', status: 'ONLINE', owner: '{ARCHITECT_HANDLE}'}}), "
        f"(a2:Agent {{id: 'SherlockAgent', name: 'Sherlock (Reasoner)', role: '1..3 Hop Blast Radius Reasoner', status: 'ONLINE', owner: '{ARCHITECT_HANDLE}'}}), "
        f"(a3:Agent {{id: 'GuardianAgent', name: 'Guardian (Governor)', role: 'Episodic Memory & Compliance Governor', status: 'ONLINE', owner: '{ARCHITECT_HANDLE}'}}), "
        f"(a1)-[:HANDOFF_TO {{protocol: 'MCP_GRAPH_TELEMETRY'}}]->(a2), "
        f"(a2)-[:HANDOFF_TO {{protocol: 'BLAST_RADIUS_LINEAGE'}}]->(a3)"
    )

    rules_data = [
        {
            "id": f"rule-{p}-01",
            "code": "RULE_PROD_DEPENDENCY_LOCK",
            "title": "Zero-Outage Transitive Production Lock",
            "rule_text": "Never delete storage buckets connected within 1..3 hops to live PRODUCTION services, even when inactive > 90 days.",
        },
        {
            "id": f"rule-{p}-02",
            "code": "RULE_PII_GOVERNANCE_HOLD",
            "title": "PII / HIPAA / PCI Statutory Retention Lock",
            "rule_text": "Any storage bucket tagged PII_LOCKED requires explicit security override from Lead Architect @prateek.",
        },
        {
            "id": f"rule-{p}-03",
            "code": "RULE_SAFE_ORPHAN_CLEANUP",
            "title": "Autonomous Orphaned Data Reclamation",
            "rule_text": "Buckets inactive > 90 days with 0 production hops and non-PII classification are approved for autonomous cleanup.",
        },
    ]

    for r in rules_data:
        graph.query(
            f"MATCH (g:Agent {{id: 'GuardianAgent'}}) "
            f"CREATE (pr:ProceduralRule {{"
            f"id: '{escape_cypher(r['id'])}', "
            f"code: '{escape_cypher(r['code'])}', "
            f"title: '{escape_cypher(r['title'])}', "
            f"rule_text: '{escape_cypher(r['rule_text'])}', "
            f"owner: '{ARCHITECT_HANDLE}', "
            f"created_at: '{now_iso}'"
            f"}}) "
            f"CREATE (g)-[:ENFORCES_RULE]->(pr)"
        )

    memories_data = [
        {
            "id": f"mem-{p}-101",
            "session_id": "Session #101",
            "bucket_id": f"bkt-{p}-q3-aggregates-archive",
            "verdict": "[BLOCKED: LIVE PROD DEPENDENCY]",
            "summary": f"SherlockAgent traced a 2-hop link from BillingService & OrderService to bkt-{p}-q3-aggregates-archive. Automatic cleanup was blocked.",
            "rule": "Procedural Rule: Never delete storage buckets connected to active billing or order pipelines.",
        },
        {
            "id": f"mem-{p}-102",
            "session_id": "Session #102",
            "bucket_id": f"bkt-{p}-customer-kyc-raw-dumps",
            "verdict": "[COMPLIANCE HOLD: PII LOCKED]",
            "summary": f"GuardianAgent locked bkt-{p}-customer-kyc-raw-dumps under @prateek's security policy because it holds regulated KYC records.",
            "rule": "Procedural Rule: Any bucket tagged PII_LOCKED requires manual override from @prateek.",
        },
        {
            "id": f"mem-{p}-103",
            "session_id": "Session #103",
            "bucket_id": f"bkt-{p}-legacy-clickstream-2023",
            "verdict": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "summary": f"ReconAgent & SherlockAgent verified 0 live production links on bkt-{p}-legacy-clickstream-2023 ($2,268/mo savings ready).",
            "rule": "Procedural Rule: Public buckets idle >180 days with zero production hops are cleared for automatic cleanup.",
        },
    ]

    for m in memories_data:
        graph.query(
            f"MATCH (b:Bucket {{id: '{escape_cypher(m['bucket_id'])}'}}), (g:Agent {{id: 'GuardianAgent'}}) "
            f"CREATE (s:Session {{id: '{escape_cypher(m['session_id'])}', operator: '{ARCHITECT_HANDLE}', started_at: '{now_iso}'}}) "
            f"CREATE (mem:Memory {{"
            f"id: '{escape_cypher(m['id'])}', "
            f"session: '{escape_cypher(m['session_id'])}', "
            f"bucket: '{escape_cypher(m['bucket_id'])}', "
            f"verdict: '{escape_cypher(m['verdict'])}', "
            f"summary: '{escape_cypher(m['summary'])}', "
            f"rule: '{escape_cypher(m['rule'])}', "
            f"owner: '{ARCHITECT_HANDLE}', "
            f"created_at: '{now_iso}'"
            f"}}) "
            f"CREATE (s)-[:RECORDED_MEMORY]->(mem)-[:ABOUT_BUCKET]->(b), (g)-[:COMMITTED_MEMORY]->(mem)"
        )

    logger.info(f"[{tenant}] Created 3 Agent nodes, 3 ProceduralRule nodes, and 3 Episodic Memory nodes.")


def seed_database(client: FalkorDB) -> None:
    """Preflight all tenant graphs, then seed without accidental data loss."""
    if not RESET_EXISTING_GRAPH:
        populated = []
        for tenant_name in TENANT_GRAPHS:
            graph = client.select_graph(tenant_name)
            result = graph.query("MATCH (n) RETURN count(n) AS cnt")
            count = int(result.result_set[0][0]) if result and result.result_set else 0
            if count:
                populated.append(f"{tenant_name} ({count} nodes)")
        if populated:
            raise RuntimeError(
                "Refusing to seed because these tenant graphs already contain data: "
                + ", ".join(populated)
                + ". Use --reset only if you intentionally want to delete and rebuild all three."
            )
    for tenant_name in TENANT_GRAPHS:
        seed_tenant_graph(client, tenant_name)


# ==============================================================================
# MODULE 3: GRAPH VERIFICATION & ANALYSIS FUNCTIONS (`verify(graph, tenant)`)
# ==============================================================================
def verify(graph: Any, tenant: str) -> Dict[str, Any]:
    """
    Executes operational Cypher verification checks against a seeded tenant graph:
      1. Total Node & Relationship Count Verification
      2. Dark Data Identification (b.idle_days > 90 with zero inbound reads/writes)
      3. Dependency Trap Detection (idle > 90d buckets connected to active pipelines/services)
      4. Multi-Hop Chain Proof (1..3 hop transitive path from PRODUCTION Services to Buckets)
    """
    logger.info("====================================================================")
    logger.info(f"VERIFYING GRAPH TELEMETRY FOR TENANT: '{tenant}'")
    logger.info("====================================================================")

    # Check 1: Total Node & Edge Counts
    node_res = graph.query("MATCH (n) RETURN count(n) AS total_nodes")
    edge_res = graph.query("MATCH ()-[r]->() RETURN count(r) AS total_edges")
    total_nodes = int(node_res.result_set[0][0]) if node_res.result_set else 0
    total_edges = int(edge_res.result_set[0][0]) if edge_res.result_set else 0
    logger.info(f"[{tenant}] Topology Totals -> Nodes: {total_nodes} | Relationships: {total_edges}")

    # Check 2: Pure Unreferenced Dark Data Identification (idle_days > 90 & 0 inbound reads/writes)
    cypher_pure_orphans = """
    MATCH (b:Bucket)
    WHERE b.idle_days > 90 AND NOT ()-[:READS_FROM|WRITES_TO]->(b)
    RETURN b.id AS bucket_id, b.idle_days AS idle_days, b.mass_tb AS mass_tb, b.cost AS monthly_cost, b.owner AS owner
    ORDER BY b.cost DESC
    """
    orphan_res = graph.query(cypher_pure_orphans)
    pure_orphans = []
    for row in orphan_res.result_set:
        pure_orphans.append({
            "bucket_id": row[0],
            "idle_days": row[1],
            "mass_tb": row[2],
            "monthly_cost": row[3],
            "owner": row[4],
        })
    logger.info(f"[{tenant}] Check 1 (Disconnected Dark Orphans >90d): Found {len(pure_orphans)} buckets:")
    for item in pure_orphans:
        logger.info(
            f"   -> SAFE ORPHAN: {item['bucket_id']} | Idle: {item['idle_days']}d | "
            f"Mass: {item['mass_tb']} TB | Cost: ${item['monthly_cost']}/mo | Owner: {item['owner']}"
        )

    # Check 3: Dependency Trap Detection (idle_days > 90 but connected to active pipelines)
    cypher_traps = """
    MATCH (p:Pipeline)-[:READS_FROM|WRITES_TO]->(b:Bucket)
    WHERE b.idle_days > 90
    RETURN b.id AS bucket_id, b.idle_days AS idle_days, b.sensitivity AS sensitivity, collect(distinct p.id) AS pipelines
    ORDER BY b.idle_days DESC
    """
    trap_res = graph.query(cypher_traps)
    detected_traps = []
    for row in trap_res.result_set:
        detected_traps.append({
            "bucket_id": row[0],
            "idle_days": row[1],
            "sensitivity": row[2],
            "pipelines": row[3],
        })
    logger.info(f"[{tenant}] Check 2 (Pipeline-Connected Idle Traps >90d): Found {len(detected_traps)} buckets:")
    for trap in detected_traps:
        logger.info(
            f"   -> TRAP CANDIDATE: {trap['bucket_id']} ({trap['idle_days']}d idle, {trap['sensitivity']}) "
            f"<-- Pipelines: {trap['pipelines']}"
        )

    # Check 4: Multi-Hop Chain Proof (1..3 Hop Transitive Blast Radius from PRODUCTION Services)
    cypher_multihop_proof = """
    MATCH path = (s:Service {env: 'PRODUCTION'})-[:DEPENDS_ON*1..3]->(p:Pipeline)-[:READS_FROM]->(b:Bucket)
    WHERE b.idle_days > 90
    RETURN b.id AS bucket_id,
           b.verdict_label AS verdict,
           collect(distinct s.id) AS impacted_prod_services,
           collect(distinct p.id) AS via_pipelines,
           max(length(path)) AS max_hop_depth
    ORDER BY max_hop_depth DESC
    """
    hop_res = graph.query(cypher_multihop_proof)
    multihop_proofs = []
    for row in hop_res.result_set:
        multihop_proofs.append({
            "bucket_id": row[0],
            "verdict": row[1],
            "impacted_prod_services": row[2],
            "via_pipelines": row[3],
            "max_hop_depth": row[4],
        })
    logger.info(
        f"[{tenant}] Check 3 (1..3 Hop Transitive Production Blast Radius Proof): "
        f"Verified {len(multihop_proofs)} production-locked dark buckets:"
    )
    for proof in multihop_proofs:
        logger.info(
            f"   -> [BLAST PROOF] Bucket: {proof['bucket_id']} | Max Hops: {proof['max_hop_depth']} | "
            f"Prod Services: {proof['impacted_prod_services']} | Via: {proof['via_pipelines']} | "
            f"Verdict: {proof['verdict']}"
        )

    return {
        "tenant": tenant,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "pure_orphans_count": len(pure_orphans),
        "pipeline_traps_count": len(detected_traps),
        "production_locked_count": len(multihop_proofs),
    }


# ==============================================================================
# MODULE 4: EXECUTION BLOCK
# ==============================================================================
if __name__ == "__main__":
    start_time = time.perf_counter()
    print("\n================================================================================")
    print(" AURA-GRAPH // DARKDATA-GRAPHOPS — FALKORDB CLOUD MULTIGRAPH SEEDER & VERIFIER")
    print(f" Lead Architect & Solo Owner : {ARCHITECT_NAME} ({ARCHITECT_HANDLE})")
    print(f" Target Cloud Instance       : {FALKORDB_HOST or '[not configured]'}:{FALKORDB_PORT}")
    print(f" Destructive reset enabled   : {RESET_EXISTING_GRAPH}")
    print("================================================================================\n")

    try:
        falkor_client = connect_falkordb_cloud()
        seed_database(falkor_client)

        verification_summaries = []
        for tenant_name in TENANT_GRAPHS:
            tenant_graph = falkor_client.select_graph(tenant_name)
            summary = verify(tenant_graph, tenant_name)
            verification_summaries.append(summary)

        elapsed_sec = round(time.perf_counter() - start_time, 2)
        print("\n================================================================================")
        print(f" SUCCESS: All 3 Multi-Tenant FalkorDB Graphs Seeded & Verified in {elapsed_sec}s!")
        for s in verification_summaries:
            print(
                f"   * {s['tenant']:<24} -> {s['total_nodes']} Nodes | {s['total_edges']} Edges | "
                f"{s['production_locked_count']} Prod Locks Verified"
            )
        print("================================================================================\n")
    except Exception as fatal_err:
        logger.error(f"Fatal error during FalkorDB Cloud seeding: {fatal_err}")
        sys.exit(1)