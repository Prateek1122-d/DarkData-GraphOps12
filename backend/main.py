#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
AURA-GRAPH // DarkData-GraphOps Engine (v2.6.0)
Multi-Tenant Cloud Security, GraphRAG & Autonomous Remediation Platform
================================================================================
Lead Systems Architect & Solo Owner : Prateek Gupta (@prateek)
Powered By                          : FalkorDB Cloud, FastAPI, Pydantic, Uvicorn
================================================================================
"""

# ==============================================================================
# MODULE 1: FASTAPI & APP CONFIGURATION
# ==============================================================================
import asyncio
import hashlib
import logging
import math
import os
import secrets
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from fastapi import Depends, FastAPI, Header, HTTPException, Path as FastAPIPath, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

try:
    from falkordb import FalkorDB
except ImportError:
    FalkorDB = None


# Structured ISO-8601 Logging Handler (`darkdata.api` & `FalkorDB`)
class ISOTimestampFormatter(logging.Formatter):
    def formatTime(self, record: logging.LogRecord, datefmt: Optional[str] = None) -> str:
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(
    ISOTimestampFormatter(
        fmt="%(asctime)s | %(levelname)-8s | [%(name)s] %(message)s"
    )
)

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.handlers = [stream_handler]

api_logger = logging.getLogger("darkdata.api")
db_logger = logging.getLogger("FalkorDB")
agent_logger = logging.getLogger("darkdata.agents")
graphrag_logger = logging.getLogger("darkdata.graphrag")

# Solo Architect Identity Constants (Exclusive Ownership: Prateek Gupta / @prateek)
ARCHITECT_NAME: str = "Prateek Gupta"
ARCHITECT_HANDLE: str = "@prateek"
ARCHITECT_TITLE: str = "Principal Enterprise Systems Architect & Solo Owner"

# FinOps & ESG Conversion Multipliers
IDLE_THRESHOLD_DAYS: int = 90
MONTHLY_COST_PER_GB_USD: float = 0.12
CARBON_KG_PER_GB_MONTHLY: float = 0.028


def current_utc_iso() -> str:
    """Returns current UTC timestamp in strict ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_cypher(value: Any) -> str:
    """Escapes strings safely for Cypher query interpolation."""
    text = str(value if value is not None else "")
    return text.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')


# ==============================================================================
# MODULE 2: FALKORDB MULTI-TENANT CLOUD CONNECTOR & SESSION ROUTING
# ==============================================================================
# All database credentials are supplied through environment variables. Never commit secrets.
FALKORDB_HOST: str = os.getenv("FALKORDB_HOST", "").strip()
FALKORDB_PORT: int = int(os.getenv("FALKORDB_PORT", "6379"))
FALKORDB_USER: str = os.getenv("FALKORDB_USER", "").strip()
FALKORDB_PASSWORD: str = os.getenv("FALKORDB_PASSWORD", "")
FALKORDB_SSL: bool = os.getenv("FALKORDB_SSL", "true").strip().lower() in {"1", "true", "yes", "on"}
AURA_ADMIN_API_KEY: str = os.getenv("AURA_ADMIN_API_KEY", "").strip()

DEFAULT_TENANT: str = "darkdata_graphops"
SUPPORTED_TENANTS: List[str] = [
    "darkdata_graphops",
    "fincorp_sec_graph",
    "healthcare_hipaa_graph",
]

TENANT_CONFIGS: Dict[str, Dict[str, str]] = {
    "darkdata_graphops": {
        "prefix": "ops",
        "label": "OPS PRODUCTION (darkdata_graphops)",
        "compliance_standard": "SOC2-TYPE-II / ISO-27001",
        "owner": ARCHITECT_HANDLE,
    },
    "fincorp_sec_graph": {
        "prefix": "fin",
        "label": "CORE FINANCE (fincorp_sec_graph)",
        "compliance_standard": "PCI-DSS-v4.0 / SOX-404",
        "owner": ARCHITECT_HANDLE,
    },
    "healthcare_hipaa_graph": {
        "prefix": "hlth",
        "label": "HEALTHCARE HIPAA (healthcare_hipaa_graph)",
        "compliance_standard": "HIPAA-HITECH / PII-SHIELD",
        "owner": ARCHITECT_HANDLE,
    },
}


def resolve_active_tenant(
    tenant: Optional[str] = Query(default=None, description="Tenant graph space name"),
    x_tenant: Optional[str] = Header(default=None, alias="X-Tenant"),
    x_tenant_graph: Optional[str] = Header(default=None, alias="X-Tenant-Graph"),
) -> str:
    """
    FastAPI Dependency Handler for Multi-Tenant Session Routing.
    Supports `?tenant=...`, `X-Tenant: ...`, and `X-Tenant-Graph: ...`.
    """
    for candidate in (tenant, x_tenant, x_tenant_graph):
        if candidate and candidate.strip() in SUPPORTED_TENANTS:
            return candidate.strip()
    return DEFAULT_TENANT


# ==============================================================================
# MODULE 4: GRAPHRAG & SEMANTIC VECTOR SEARCH LAYER
# ==============================================================================
class GraphRAGSemanticEngine:
    """
    Generates deterministic 16-dimensional L2-normalized vector embeddings and
    executes Cosine Similarity semantic search over (:Bucket), (:Memory),
    (:ProceduralRule), and (:TraceLog) graph entities.
    """

    VECTOR_DIM: int = 16

    DOMAIN_ANCHORS: Dict[str, int] = {
        "production": 0, "prod": 0, "billing": 0, "order": 0, "checkout": 0, "live": 0, "outage": 0,
        "pii": 1, "hipaa": 1, "pci": 1, "soc2": 1, "kyc": 1, "compliance": 1, "locked": 1, "hold": 1,
        "safe": 2, "orphan": 2, "orphaned": 2, "clean": 2, "cleanup": 2, "prune": 2, "reclaim": 2,
        "chaos": 3, "rogue": 3, "shadow": 3, "trap": 3, "anomaly": 3, "sandbox": 3,
        "carbon": 4, "co2": 4, "co2e": 4, "esg": 4, "green": 4, "footprint": 4, "offset": 4,
        "cost": 5, "opex": 5, "money": 5, "savings": 5, "finops": 5, "usd": 5, "monthly": 5,
        "prateek": 6, "@prateek": 6, "architect": 6, "owner": 6, "governor": 6, "solo": 6,
        "pipeline": 7, "etl": 7, "spark": 7, "flink": 7, "kafka": 7, "hydration": 7, "recon": 7,
    }

    @classmethod
    def compute_embedding(cls, text: str) -> List[float]:
        raw = (text or "").lower().strip()
        vec = [0.0] * cls.VECTOR_DIM
        if not raw:
            return vec

        tokens = [
            tok.strip(".,:;!?()[]{}'\"<>/-_")
            for tok in raw.split()
            if tok.strip()
        ]
        if not tokens:
            return vec

        for token in tokens:
            if token in cls.DOMAIN_ANCHORS:
                idx = cls.DOMAIN_ANCHORS[token]
                vec[idx] += 2.8
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            for d in range(cls.VECTOR_DIM):
                vec[d] += ((digest[d] / 255.0) - 0.5) * 0.55

        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 1e-9:
            vec = [round(v / norm, 4) for v in vec]
        return vec

    @classmethod
    def cosine_similarity(cls, vec1: List[float], vec2: List[float]) -> float:
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0
        dot = sum(a * b for a, b in zip(vec1, vec2))
        n1 = math.sqrt(sum(a * a for a in vec1))
        n2 = math.sqrt(sum(b * b for b in vec2))
        if n1 < 1e-9 or n2 < 1e-9:
            return 0.0
        return round(max(0.0, min(1.0, dot / (n1 * n2))), 4)

    @classmethod
    def semantic_search(
        cls,
        state: Dict[str, Any],
        query: str,
        top_k: int = 5,
    ) -> Dict[str, Any]:
        q_vec = cls.compute_embedding(query)

        # 1. Rank Episodic Memories (:Memory)
        ranked_memories: List[Dict[str, Any]] = []
        for mem in state["memories"]:
            corpus = f"{mem['bucket']} {mem['verdict']} {mem['summary']} {mem['rule']}"
            m_vec = mem.get("embedding") or cls.compute_embedding(corpus)
            score = cls.cosine_similarity(q_vec, m_vec)
            ranked_memories.append({**mem, "similarity_score": score})
        ranked_memories.sort(key=lambda x: x["similarity_score"], reverse=True)

        # 2. Rank Storage Buckets (:Bucket)
        ranked_buckets: List[Dict[str, Any]] = []
        for bkt in state["buckets"]:
            corpus = (
                f"{bkt['id']} {bkt['sensitivity']} {bkt['verdict_label']} "
                f"{bkt['explanation']} {' '.join(bkt['readers'])}"
            )
            b_vec = cls.compute_embedding(corpus)
            score = cls.cosine_similarity(q_vec, b_vec)
            ranked_buckets.append({
                "id": bkt["id"],
                "idle_days": bkt["idle_days"],
                "size_gb": bkt["size_gb"],
                "monthly_cost_usd": bkt["monthly_cost_usd"],
                "sensitivity": bkt["sensitivity"],
                "verdict_label": bkt["verdict_label"],
                "owner": ARCHITECT_HANDLE,
                "similarity_score": score,
            })
        ranked_buckets.sort(key=lambda x: x["similarity_score"], reverse=True)

        # 3. Rank Unstructured Trace Logs (:TraceLog)
        ranked_traces: List[Dict[str, Any]] = []
        for tr in state["unstructured_traces"]:
            t_vec = tr.get("embedding") or cls.compute_embedding(tr["raw_text"])
            score = cls.cosine_similarity(q_vec, t_vec)
            ranked_traces.append({**tr, "similarity_score": score})
        ranked_traces.sort(key=lambda x: x["similarity_score"], reverse=True)

        return {
            "query": query,
            "query_vector_sample": q_vec[:8],
            "matched_memories": ranked_memories[:top_k],
            "matched_buckets": ranked_buckets[:top_k],
            "matched_traces": ranked_traces[:top_k],
            "procedural_rules": state["procedural_rules"],
        }


# ==============================================================================
# BASELINE 45-NODE / 81-EDGE MULTI-TENANT TOPOLOGY BUILDER
# ==============================================================================
def generate_tenant_baseline(tenant: str) -> Dict[str, Any]:
    cfg = TENANT_CONFIGS.get(tenant, TENANT_CONFIGS[DEFAULT_TENANT])
    p = cfg["prefix"]
    now_iso = current_utc_iso()

    # 8 Solo Architect Command Teams (All owned by @prateek)
    teams: List[Dict[str, Any]] = [
        {"id": "Arch:@prateek-Core", "name": "Core Cloud Architecture (@prateek)", "lead": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-SecOps", "name": "Security & PII Governance (@prateek)", "lead": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-CloudOps", "name": "Production Reliability SRE (@prateek)", "lead": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-AI", "name": "Autonomous AI & GraphRAG (@prateek)", "lead": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-Data", "name": "Data Engineering & ETL (@prateek)", "lead": ARCHITECT_HANDLE, "tier": "TIER_1"},
        {"id": "Arch:@prateek-QA", "name": "Staging & Load Validation (@prateek)", "lead": ARCHITECT_HANDLE, "tier": "TIER_2"},
        {"id": "Arch:@prateek-Audit", "name": "Statutory Compliance & Audit (@prateek)", "lead": ARCHITECT_HANDLE, "tier": "TIER_0"},
        {"id": "Arch:@prateek-FinOps", "name": "Cloud FinOps & Carbon ESG (@prateek)", "lead": ARCHITECT_HANDLE, "tier": "TIER_1"},
    ]

    # 14 Cloud Services (10 Production, 4 Staging)
    services: List[Dict[str, Any]] = [
        {"id": "BillingService", "name": "BillingService", "env": "PRODUCTION", "criticality": "CRITICAL", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Core", "pipes": ["pipe-quarterly-recon", "pipe-edi-clearinghouse"], "deps": []},
        {"id": "OrderService", "name": "OrderService", "env": "PRODUCTION", "criticality": "CRITICAL", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-CloudOps", "pipes": ["pipe-core-stream-etl"], "deps": ["BillingService", "PaymentLedgerSvc"]},
        {"id": "FraudDetectionEngine", "name": "FraudDetectionEngine", "env": "PRODUCTION", "criticality": "CRITICAL", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-SecOps", "pipes": ["pipe-kyc-verifier", "pipe-audit-archiver"], "deps": []},
        {"id": "AuthGateway", "name": "AuthGateway", "env": "PRODUCTION", "criticality": "CRITICAL", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-SecOps", "pipes": ["pipe-profile-sync"], "deps": ["FraudDetectionEngine"]},
        {"id": "PaymentLedgerSvc", "name": "PaymentLedgerSvc", "env": "PRODUCTION", "criticality": "CRITICAL", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Core", "pipes": ["pipe-edi-clearinghouse"], "deps": ["TaxComplianceSvc"]},
        {"id": "CheckoutAPI", "name": "CheckoutAPI", "env": "PRODUCTION", "criticality": "CRITICAL", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-CloudOps", "pipes": ["pipe-core-stream-etl"], "deps": ["PaymentLedgerSvc", "OrderService", "AuthGateway"]},
        {"id": "TaxComplianceSvc", "name": "TaxComplianceSvc", "env": "PRODUCTION", "criticality": "CRITICAL", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Audit", "pipes": ["pipe-tax-exporter", "pipe-quarterly-recon"], "deps": []},
        {"id": "InvoiceGenerator", "name": "InvoiceGenerator", "env": "PRODUCTION", "criticality": "HIGH", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Core", "pipes": ["pipe-tax-exporter"], "deps": ["BillingService"]},
        {"id": "RecommendationEngine", "name": "RecommendationEngine", "env": "PRODUCTION", "criticality": "HIGH", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-AI", "pipes": ["pipe-feature-hydrator", "pipe-profile-sync"], "deps": []},
        {"id": "SearchDiscoveryAPI", "name": "SearchDiscoveryAPI", "env": "PRODUCTION", "criticality": "HIGH", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-AI", "pipes": ["pipe-core-stream-etl"], "deps": ["RecommendationEngine"]},
        {"id": "StagingAnalyticsSvc", "name": "StagingAnalyticsSvc", "env": "STAGING", "criticality": "LOW", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-QA", "pipes": ["pipe-click-ingest-v1"], "deps": []},
        {"id": "StagingLoadRunner", "name": "StagingLoadRunner", "env": "STAGING", "criticality": "LOW", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-QA", "pipes": ["pipe-perf-replay"], "deps": []},
        {"id": "DevModelTrainer", "name": "DevModelTrainer", "env": "STAGING", "criticality": "LOW", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-AI", "pipes": ["pipe-ml-feature-gen"], "deps": []},
        {"id": "SandboxReplayWorker", "name": "SandboxReplayWorker", "env": "STAGING", "criticality": "LOW", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-QA", "pipes": ["pipe-perf-replay", "pipe-click-ingest-v1"], "deps": []},
    ]

    # 11 Data & AI Pipelines
    pipelines: List[Dict[str, Any]] = [
        {"id": "pipe-quarterly-recon", "name": "pipe-quarterly-recon", "engine": "Spark-3.5", "status": "ACTIVE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Data"},
        {"id": "pipe-click-ingest-v1", "name": "pipe-click-ingest-v1", "engine": "Airflow-Legacy", "status": "DEPRECATED", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Data"},
        {"id": "pipe-kyc-verifier", "name": "pipe-kyc-verifier", "engine": "Flink-Streaming", "status": "ACTIVE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-SecOps"},
        {"id": "pipe-edi-clearinghouse", "name": "pipe-edi-clearinghouse", "engine": "Spark-Batch", "status": "ACTIVE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Core"},
        {"id": "pipe-perf-replay", "name": "pipe-perf-replay", "engine": "Locust-Replay", "status": "IDLE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-QA"},
        {"id": "pipe-tax-exporter", "name": "pipe-tax-exporter", "engine": "Spark-SQL", "status": "ACTIVE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Audit"},
        {"id": "pipe-feature-hydrator", "name": "pipe-feature-hydrator", "engine": "Ray-FeatureStore", "status": "ACTIVE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-AI"},
        {"id": "pipe-core-stream-etl", "name": "pipe-core-stream-etl", "engine": "Kafka-Flink", "status": "ACTIVE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-CloudOps"},
        {"id": "pipe-profile-sync", "name": "pipe-profile-sync", "engine": "Debezium-CDC", "status": "ACTIVE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Core"},
        {"id": "pipe-ml-feature-gen", "name": "pipe-ml-feature-gen", "engine": "PyTorch-Loader", "status": "IDLE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-AI"},
        {"id": "pipe-audit-archiver", "name": "pipe-audit-archiver", "engine": "Compliance-Sync", "status": "ACTIVE", "owner": ARCHITECT_HANDLE, "team_id": "Arch:@prateek-Audit"},
    ]

    # 12 Storage Buckets (10 Dark Storage Candidates >90d idle + 2 Active Core Buckets)
    buckets: List[Dict[str, Any]] = [
        {
            "id": f"bkt-{p}-legacy-clickstream-2023",
            "name": f"bkt-{p}-legacy-clickstream-2023",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 312,
            "size_gb": 18900,
            "mass_tb": 18.9,
            "monthly_cost_usd": 2268,
            "carbon_kg": 529.2,
            "sensitivity": "PUBLIC",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-Data",
            "readers": ["pipe-click-ingest-v1"],
            "writers": [],
            "verdict_code": "SAFE",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "explanation": "Zero live production services use this bucket. It is an old 2023 clickstream archive that can be safely cleaned up to save $2,268/mo.",
        },
        {
            "id": f"bkt-{p}-q3-aggregates-archive",
            "name": f"bkt-{p}-q3-aggregates-archive",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 147,
            "size_gb": 12400,
            "mass_tb": 12.4,
            "monthly_cost_usd": 1488,
            "carbon_kg": 347.2,
            "sensitivity": "INTERNAL",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-Core",
            "readers": ["pipe-quarterly-recon"],
            "writers": [],
            "verdict_code": "BLOCKED_PROD",
            "verdict_label": "[BLOCKED: LIVE PROD DEPENDENCY]",
            "explanation": "Even though this bucket has been inactive for 147 days, live production services (BillingService and OrderService) still read from it during quarterly financial close.",
        },
        {
            "id": f"bkt-{p}-staging-loadtest-artifacts",
            "name": f"bkt-{p}-staging-loadtest-artifacts",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 189,
            "size_gb": 11200,
            "mass_tb": 11.2,
            "monthly_cost_usd": 1344,
            "carbon_kg": 313.6,
            "sensitivity": "PUBLIC",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-QA",
            "readers": ["pipe-perf-replay"],
            "writers": [],
            "verdict_code": "SAFE",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "explanation": "Only linked to a non-production staging test tool. Zero risk to live customer traffic.",
        },
        {
            "id": f"bkt-{p}-dev-sandbox-ml-checkpoints",
            "name": f"bkt-{p}-dev-sandbox-ml-checkpoints",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 204,
            "size_gb": 9400,
            "mass_tb": 9.4,
            "monthly_cost_usd": 1128,
            "carbon_kg": 263.2,
            "sensitivity": "INTERNAL",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-AI",
            "readers": [],
            "writers": [],
            "verdict_code": "SAFE",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "explanation": "Unused AI training checkpoints from an old test sandbox. No pipelines or production services are connected.",
        },
        {
            "id": f"bkt-{p}-customer-kyc-raw-dumps",
            "name": f"bkt-{p}-customer-kyc-raw-dumps",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 118,
            "size_gb": 6800,
            "mass_tb": 6.8,
            "monthly_cost_usd": 952,
            "carbon_kg": 190.4,
            "sensitivity": "PII_LOCKED",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-SecOps",
            "readers": ["pipe-kyc-verifier", "pipe-audit-archiver"],
            "writers": [],
            "verdict_code": "PII_HOLD",
            "verdict_label": "[COMPLIANCE HOLD: PII LOCKED]",
            "explanation": "Protected customer identity records (PII) under legal hold, actively connected to FraudDetectionEngine and AuthGateway.",
        },
        {
            "id": f"bkt-{p}-ab-test-orphaned-logs",
            "name": f"bkt-{p}-ab-test-orphaned-logs",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 275,
            "size_gb": 7600,
            "mass_tb": 7.6,
            "monthly_cost_usd": 912,
            "carbon_kg": 212.8,
            "sensitivity": "INTERNAL",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-FinOps",
            "readers": [],
            "writers": [],
            "verdict_code": "SAFE",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "explanation": "Completely disconnected A/B testing logs from 9 months ago. Safe for immediate cleanup.",
        },
        {
            "id": f"bkt-{p}-realtime-feature-store-cold",
            "name": f"bkt-{p}-realtime-feature-store-cold",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 103,
            "size_gb": 5800,
            "mass_tb": 5.8,
            "monthly_cost_usd": 754,
            "carbon_kg": 162.4,
            "sensitivity": "INTERNAL",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-AI",
            "readers": ["pipe-feature-hydrator"],
            "writers": [],
            "verdict_code": "BLOCKED_PROD",
            "verdict_label": "[BLOCKED: LIVE PROD DEPENDENCY]",
            "explanation": "Acts as a backup data store for RecommendationEngine and SearchDiscoveryAPI in production.",
        },
        {
            "id": f"bkt-{p}-partner-edi-settlements",
            "name": f"bkt-{p}-partner-edi-settlements",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 96,
            "size_gb": 5200,
            "mass_tb": 5.2,
            "monthly_cost_usd": 676,
            "carbon_kg": 145.6,
            "sensitivity": "PII_LOCKED",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-Audit",
            "readers": ["pipe-edi-clearinghouse"],
            "writers": [],
            "verdict_code": "PII_HOLD",
            "verdict_label": "[COMPLIANCE HOLD: PII LOCKED]",
            "explanation": "Contains regulated partner payment records required by PaymentLedgerSvc and CheckoutAPI.",
        },
        {
            "id": f"bkt-{p}-tax-audit-vault-2024",
            "name": f"bkt-{p}-tax-audit-vault-2024",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 164,
            "size_gb": 4300,
            "mass_tb": 4.3,
            "monthly_cost_usd": 559,
            "carbon_kg": 120.4,
            "sensitivity": "PII_LOCKED",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-Audit",
            "readers": ["pipe-tax-exporter"],
            "writers": [],
            "verdict_code": "PII_HOLD",
            "verdict_label": "[COMPLIANCE HOLD: PII LOCKED]",
            "explanation": "Locked tax audit vault required by TaxComplianceSvc and InvoiceGenerator.",
        },
        {
            "id": f"bkt-{p}-deprecated-cdn-access-logs",
            "name": f"bkt-{p}-deprecated-cdn-access-logs",
            "is_dark": True,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 340,
            "size_gb": 3000,
            "mass_tb": 3.0,
            "monthly_cost_usd": 360,
            "carbon_kg": 84.0,
            "sensitivity": "PUBLIC",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-FinOps",
            "readers": [],
            "writers": [],
            "verdict_code": "SAFE",
            "verdict_label": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "explanation": "Old CDN logs idle for nearly a year with zero connected services.",
        },
        {
            "id": f"bkt-{p}-prod-events-live",
            "name": f"bkt-{p}-prod-events-live",
            "is_dark": False,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 0,
            "size_gb": 16000,
            "mass_tb": 16.0,
            "monthly_cost_usd": 1920,
            "carbon_kg": 448.0,
            "sensitivity": "INTERNAL",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-CloudOps",
            "readers": ["pipe-core-stream-etl"],
            "writers": ["pipe-core-stream-etl"],
            "verdict_code": "ACTIVE",
            "verdict_label": "[ACTIVE PRODUCTION STREAM]",
            "explanation": "Live customer event stream serving OrderService and CheckoutAPI.",
        },
        {
            "id": f"bkt-{p}-prod-user-vault",
            "name": f"bkt-{p}-prod-user-vault",
            "is_dark": False,
            "pruned": False,
            "is_chaos": False,
            "idle_days": 0,
            "size_gb": 14000,
            "mass_tb": 14.0,
            "monthly_cost_usd": 1680,
            "carbon_kg": 392.0,
            "sensitivity": "PII_LOCKED",
            "owner": ARCHITECT_HANDLE,
            "team_id": "Arch:@prateek-SecOps",
            "readers": ["pipe-profile-sync"],
            "writers": ["pipe-profile-sync"],
            "verdict_code": "ACTIVE",
            "verdict_label": "[ACTIVE PRODUCTION VAULT]",
            "explanation": "Live customer authentication vault managed by @prateek.",
        },
    ]

    procedural_rules: List[Dict[str, Any]] = [
        {
            "id": f"rule-{p}-01",
            "code": "RULE_PROD_DEPENDENCY_LOCK",
            "title": "Zero-Outage Transitive Production Lock",
            "rule_text": "Never delete storage buckets connected within 1..3 hops to live PRODUCTION services, even when inactive > 90 days.",
            "enforced_by": "GuardianAgent",
            "owner": ARCHITECT_HANDLE,
            "created_at": now_iso,
        },
        {
            "id": f"rule-{p}-02",
            "code": "RULE_PII_GOVERNANCE_HOLD",
            "title": "PII / HIPAA / PCI Statutory Retention Lock",
            "rule_text": "Any storage bucket tagged PII_LOCKED requires explicit security override from Lead Architect @prateek.",
            "enforced_by": "GuardianAgent",
            "owner": ARCHITECT_HANDLE,
            "created_at": now_iso,
        },
        {
            "id": f"rule-{p}-03",
            "code": "RULE_SAFE_ORPHAN_CLEANUP",
            "title": "Autonomous Orphaned Data Reclamation",
            "rule_text": "Buckets inactive > 90 days with 0 production hops and non-PII classification are approved for autonomous cleanup.",
            "enforced_by": "ReconAgent + SherlockAgent",
            "owner": ARCHITECT_HANDLE,
            "created_at": now_iso,
        },
    ]

    memories: List[Dict[str, Any]] = [
        {
            "id": f"mem-{p}-101",
            "session": "Session #101",
            "session_id": "Session #101",
            "bucket": f"bkt-{p}-q3-aggregates-archive",
            "bucket_name": f"bkt-{p}-q3-aggregates-archive",
            "memory_type": "EPISODIC_BLOCK",
            "verdict": "[BLOCKED: LIVE PROD DEPENDENCY]",
            "summary": (
                f"SherlockAgent traced a 2-hop link from BillingService & OrderService to "
                f"bkt-{p}-q3-aggregates-archive. Automatic cleanup was blocked to protect production."
            ),
            "rule": "Procedural Rule: Never delete storage buckets connected to active billing or order pipelines.",
            "rule_learned": "Procedural Rule: Never delete storage buckets connected to active billing or order pipelines.",
            "owner": ARCHITECT_HANDLE,
            "timestamp": "Session #101 • Verified",
            "created_at": now_iso,
        },
        {
            "id": f"mem-{p}-102",
            "session": "Session #102",
            "session_id": "Session #102",
            "bucket": f"bkt-{p}-customer-kyc-raw-dumps",
            "bucket_name": f"bkt-{p}-customer-kyc-raw-dumps",
            "memory_type": "PROCEDURAL_COMPLIANCE",
            "verdict": "[COMPLIANCE HOLD: PII LOCKED]",
            "summary": (
                f"GuardianAgent locked bkt-{p}-customer-kyc-raw-dumps under @prateek's security policy "
                f"because it holds regulated customer KYC records."
            ),
            "rule": "Procedural Rule: Any bucket tagged PII_LOCKED requires manual override from @prateek.",
            "rule_learned": "Procedural Rule: Any bucket tagged PII_LOCKED requires manual override from @prateek.",
            "owner": ARCHITECT_HANDLE,
            "timestamp": "Session #102 • Verified",
            "created_at": now_iso,
        },
        {
            "id": f"mem-{p}-103",
            "session": "Session #103",
            "session_id": "Session #103",
            "bucket": f"bkt-{p}-legacy-clickstream-2023",
            "bucket_name": f"bkt-{p}-legacy-clickstream-2023",
            "memory_type": "EPISODIC_AUDIT",
            "verdict": "[SAFE TO CLEAN UP: ORPHANED DATA]",
            "summary": (
                f"ReconAgent & SherlockAgent verified 0 live production links on "
                f"bkt-{p}-legacy-clickstream-2023 ($2,268/mo savings ready)."
            ),
            "rule": "Procedural Rule: Public buckets idle >180 days with zero production hops are cleared for automatic cleanup.",
            "rule_learned": "Procedural Rule: Public buckets idle >180 days with zero production hops are cleared for automatic cleanup.",
            "owner": ARCHITECT_HANDLE,
            "timestamp": "Session #103 • Verified",
            "created_at": now_iso,
        },
    ]

    for mem in memories:
        mem["embedding"] = GraphRAGSemanticEngine.compute_embedding(
            f"{mem['bucket']} {mem['verdict']} {mem['summary']} {mem['rule']}"
        )

    unstructured_traces: List[Dict[str, Any]] = [
        {
            "trace_id": f"trace-{p}-001",
            "bucket_id": f"bkt-{p}-q3-aggregates-archive",
            "agent": "SherlockAgent",
            "severity": "WARNING",
            "raw_text": (
                f"Spark job nightly-recon-close on pipe-quarterly-recon holds active read lock on "
                f"bkt-{p}-q3-aggregates-archive for upstream BillingService and OrderService."
            ),
            "owner": ARCHITECT_HANDLE,
            "created_at": now_iso,
        },
        {
            "trace_id": f"trace-{p}-002",
            "bucket_id": f"bkt-{p}-customer-kyc-raw-dumps",
            "agent": "GuardianAgent",
            "severity": "CRITICAL",
            "raw_text": (
                f"PII_LOCKED compliance barrier triggered on bkt-{p}-customer-kyc-raw-dumps. "
                f"Contains unmasked KYC identity blobs queried by FraudDetectionEngine."
            ),
            "owner": ARCHITECT_HANDLE,
            "created_at": now_iso,
        },
    ]
    for tr in unstructured_traces:
        tr["embedding"] = GraphRAGSemanticEngine.compute_embedding(tr["raw_text"])

    return {
        "tenant": tenant,
        "config": cfg,
        "teams": teams,
        "services": services,
        "pipelines": pipelines,
        "buckets": buckets,
        "procedural_rules": procedural_rules,
        "memories": memories,
        "unstructured_traces": unstructured_traces,
        "baseline_reclaimed_gb": 14200,
        "baseline_saved_usd": 1840,
        "baseline_carbon_kg": 412.8,
    }


class FalkorCloudConnectorPool:
    """
    Manages the FalkorDB connection using environment-provided credentials.
    Provides multi-tenant graph selection and an explicit in-memory demo fallback.
    """

    def __init__(self) -> None:
        self.client: Optional[Any] = None
        self.cloud_connected: bool = False
        self.last_latency_ms: float = 1.25
        self.seeded_tenants: Set[str] = set()
        self.store: Dict[str, Dict[str, Any]] = {
            t: generate_tenant_baseline(t) for t in SUPPORTED_TENANTS
        }

    def initialize_cloud_client(self) -> Optional[Any]:
        if FalkorDB is None:
            self.cloud_connected = False
            db_logger.warning("falkordb package is unavailable; using the in-memory demo graph.")
            return None
        if not FALKORDB_HOST or not FALKORDB_USER or not FALKORDB_PASSWORD:
            self.cloud_connected = False
            db_logger.warning("FalkorDB credentials are not configured; using the in-memory demo graph.")
            return None

        try:
            if self.client is None:
                db_logger.info(
                    f"Connecting to FalkorDB Cloud -> {FALKORDB_HOST}:{FALKORDB_PORT} (user='{FALKORDB_USER}')"
                )
                self.client = FalkorDB(
                    host=FALKORDB_HOST,
                    port=FALKORDB_PORT,
                    username=FALKORDB_USER,
                    password=FALKORDB_PASSWORD,
                    ssl=FALKORDB_SSL,
                )
            return self.client
        except Exception as exc:
            self.cloud_connected = False
            self.client = None
            db_logger.warning(f"FalkorDB Cloud initialization fallback active: {exc}")
            return None

    def get_tenant_graph(self, tenant: str) -> Tuple[Optional[Any], float]:
        t0 = time.perf_counter()
        client = self.initialize_cloud_client()
        if client is None:
            return None, self.last_latency_ms

        try:
            graph = client.select_graph(tenant)
            res = graph.query("MATCH (n) RETURN count(n) AS cnt")
            latency = round((time.perf_counter() - t0) * 1000, 2)
            self.last_latency_ms = latency
            self.cloud_connected = True

            cnt = int(res.result_set[0][0]) if res and res.result_set else 0
            if cnt == 0 and tenant not in self.seeded_tenants:
                self._seed_cloud_graph(graph, tenant)
                self.seeded_tenants.add(tenant)

            return graph, latency
        except Exception as exc:
            self.cloud_connected = False
            db_logger.warning(f"FalkorDB Cloud query fallback for tenant '{tenant}': {exc}")
            return None, 1.25

    def run_cypher(self, tenant: str, query: str) -> Tuple[Optional[Any], float]:
        graph, latency = self.get_tenant_graph(tenant)
        if graph is None:
            return None, latency
        t0 = time.perf_counter()
        try:
            result = graph.query(query)
            exec_ms = round((time.perf_counter() - t0) * 1000, 2)
            return result, exec_ms
        except Exception as exc:
            db_logger.warning(f"Cypher execution warning on '{tenant}': {exc}")
            return None, latency

    def _seed_cloud_graph(self, graph: Any, tenant: str) -> None:
        state = self.store[tenant]
        try:
            for t in state["teams"]:
                graph.query(
                    f"MERGE (:Team {{id: '{sanitize_cypher(t['id'])}', name: '{sanitize_cypher(t['name'])}', "
                    f"lead: '{ARCHITECT_HANDLE}', tier: '{sanitize_cypher(t['tier'])}'}}) "
                )
            for pl in state["pipelines"]:
                graph.query(
                    f"MERGE (:Pipeline {{id: '{sanitize_cypher(pl['id'])}', name: '{sanitize_cypher(pl['name'])}', "
                    f"engine: '{sanitize_cypher(pl['engine'])}', status: '{sanitize_cypher(pl['status'])}', "
                    f"owner: '{ARCHITECT_HANDLE}'}}) "
                )
            for sv in state["services"]:
                graph.query(
                    f"MERGE (:Service {{id: '{sanitize_cypher(sv['id'])}', name: '{sanitize_cypher(sv['name'])}', "
                    f"env: '{sanitize_cypher(sv['env'])}', criticality: '{sanitize_cypher(sv['criticality'])}', "
                    f"owner: '{ARCHITECT_HANDLE}'}}) "
                )
                for p_id in sv["pipes"]:
                    graph.query(
                        f"MATCH (s:Service {{id: '{sanitize_cypher(sv['id'])}'}}), "
                        f"(p:Pipeline {{id: '{sanitize_cypher(p_id)}'}}) "
                        f"MERGE (s)-[:DEPENDS_ON]->(p)"
                    )
                for d_id in sv["deps"]:
                    graph.query(
                        f"MATCH (s1:Service {{id: '{sanitize_cypher(sv['id'])}'}}), "
                        f"(s2:Service {{id: '{sanitize_cypher(d_id)}'}}) "
                        f"MERGE (s1)-[:DEPENDS_ON]->(s2)"
                    )
            for b in state["buckets"]:
                graph.query(
                    f"MERGE (:Bucket {{id: '{sanitize_cypher(b['id'])}', name: '{sanitize_cypher(b['name'])}', "
                    f"is_dark: {'true' if b['is_dark'] else 'false'}, pruned: {'true' if b['pruned'] else 'false'}, "
                    f"idle_days: {int(b['idle_days'])}, size_gb: {int(b['size_gb'])}, "
                    f"monthly_cost_usd: {int(b['monthly_cost_usd'])}, carbon_kg: {float(b['carbon_kg'])}, "
                    f"sensitivity: '{sanitize_cypher(b['sensitivity'])}', owner: '{ARCHITECT_HANDLE}'}}) "
                )
                for r_pipe in b["readers"]:
                    graph.query(
                        f"MATCH (p:Pipeline {{id: '{sanitize_cypher(r_pipe)}'}}), "
                        f"(bk:Bucket {{id: '{sanitize_cypher(b['id'])}'}}) "
                        f"MERGE (p)-[:READS_FROM]->(bk)"
                    )
            for rule in state["procedural_rules"]:
                graph.query(
                    f"MERGE (:ProceduralRule {{id: '{sanitize_cypher(rule['id'])}', code: '{sanitize_cypher(rule['code'])}', "
                    f"title: '{sanitize_cypher(rule['title'])}', rule_text: '{sanitize_cypher(rule['rule_text'])}', "
                    f"owner: '{ARCHITECT_HANDLE}'}}) "
                )
            for mem in state["memories"]:
                graph.query(
                    f"MATCH (bk:Bucket {{id: '{sanitize_cypher(mem['bucket'])}'}}) "
                    f"MERGE (m:Memory {{id: '{sanitize_cypher(mem['id'])}', bucket: '{sanitize_cypher(mem['bucket'])}', "
                    f"session: '{sanitize_cypher(mem.get('session', 'Demo Session'))}', "
                    f"verdict: '{sanitize_cypher(mem['verdict'])}', summary: '{sanitize_cypher(mem['summary'])}', "
                    f"rule: '{sanitize_cypher(mem['rule'])}', owner: '{ARCHITECT_HANDLE}'}}) "
                    f"MERGE (m)-[:ABOUT_BUCKET]->(bk)"
                )
            db_logger.info(f"Seeded FalkorDB Cloud tenant graph '{tenant}' successfully.")
        except Exception as exc:
            db_logger.warning(f"Seed warning on tenant '{tenant}': {exc}")


cloud_pool = FalkorCloudConnectorPool()


# ==============================================================================
# MODULE 3: MULTI-AGENT AUTONOMOUS COORDINATION PIPELINE
# ==============================================================================
class ReconScoutAgent:
    """
    1. Recon Agent (Scout):
    Scans storage buckets for inactivity thresholds (>90 days), calculating
    storage mass in TB, monthly OPEX cost ($/mo), and carbon footprints (kg CO2e).
    """

    NAME = "Recon (Scout)"

    @classmethod
    def analyze_bucket_telemetry(cls, bucket: Dict[str, Any]) -> Dict[str, Any]:
        size_gb = int(bucket.get("size_gb", 0))
        mass_tb = round(size_gb / 1000.0, 2)
        idle_days = int(bucket.get("idle_days", 0))
        monthly_cost_usd = int(bucket.get("monthly_cost_usd") or round(size_gb * MONTHLY_COST_PER_GB_USD))
        carbon_kg = float(bucket.get("carbon_kg") or round(size_gb * CARBON_KG_PER_GB_MONTHLY, 1))

        return {
            "agent": cls.NAME,
            "bucket_id": bucket["id"],
            "owner": ARCHITECT_HANDLE,
            "idle_days": idle_days,
            "is_idle_trap": idle_days > IDLE_THRESHOLD_DAYS,
            "size_gb": size_gb,
            "mass_tb": mass_tb,
            "monthly_cost_usd": monthly_cost_usd,
            "annual_cost_usd": monthly_cost_usd * 12,
            "carbon_kg": carbon_kg,
            "sensitivity": bucket.get("sensitivity", "INTERNAL"),
            "thought_log": (
                f"[ReconAgent]: Scanned '{bucket['id']}' ({idle_days}d idle > {IDLE_THRESHOLD_DAYS}d threshold). "
                f"Mass={mass_tb} TB, Cost=${monthly_cost_usd}/mo, Carbon={carbon_kg} kg CO2e."
            ),
        }


class SherlockReasonerAgent:
    """
    2. Sherlock Agent (Reasoner):
    Executes 1..3 hop Cypher traversals across the active tenant graph to evaluate
    transitive production dependencies and safety verdicts:
      - Case A: Safe Orphan ([SAFE TO CLEAN UP: ORPHANED DATA])
      - Case B: Hidden Prod Dependency Trap ([BLOCKED: LIVE PROD DEPENDENCY])
      - Case C: Compliance / PII Hold ([COMPLIANCE HOLD: PII LOCKED])
    """

    NAME = "Sherlock (Reasoner)"

    @classmethod
    def trace_blast_radius(
        cls,
        tenant: str,
        state: Dict[str, Any],
        bucket: Dict[str, Any],
    ) -> Dict[str, Any]:
        cypher_query = (
            f"MATCH (b:Bucket {{id: '{sanitize_cypher(bucket['id'])}'}})\n"
            f"WHERE b.owner = '{ARCHITECT_HANDLE}'\n"
            f"OPTIONAL MATCH path = (s:Service {{env: 'PRODUCTION'}})-[:DEPENDS_ON*1..3]->"
            f"(p:Pipeline)-[:READS_FROM]->(b)\n"
            f"RETURN b.id AS bucket_id, collect(distinct s.id) AS prod_services, "
            f"collect(distinct p.id) AS pipelines, coalesce(max(length(path)), 0) AS hop_depth;"
        )
        graph_result, exec_ms = cloud_pool.run_cypher(tenant, cypher_query)
        rows = getattr(graph_result, "result_set", []) or [] if graph_result is not None else []
        graph_reasoning_used = graph_result is not None and bool(rows)

        if graph_reasoning_used:
            row = rows[0] if rows else []
            prod_services = list(row[1] or []) if len(row) > 1 else []
            connected_pipes = list(row[2] or []) if len(row) > 2 else []
            max_hops = int(row[3] or 0) if len(row) > 3 and row[3] is not None else 0
            staging_services = []
        else:
            # Deterministic fallback for local/demo mode when FalkorDB is unavailable.
            connected_pipes = list(dict.fromkeys(bucket.get("readers", []) + bucket.get("writers", [])))
            hop2_services = [
                svc for svc in state["services"]
                if any(pipe in svc["pipes"] for pipe in connected_pipes)
            ]
            hop2_ids = {svc["id"] for svc in hop2_services}
            hop3_services = [
                svc for svc in state["services"]
                if svc["id"] not in hop2_ids and any(dep in hop2_ids for dep in svc["deps"])
            ]
            all_services = hop2_services + hop3_services
            prod_services = [svc["id"] for svc in all_services if svc["env"] == "PRODUCTION"]
            staging_services = [svc["id"] for svc in all_services if svc["env"] != "PRODUCTION"]
            max_hops = 3 if hop3_services else 2 if hop2_services else 1 if connected_pipes else 0

        sens = bucket.get("sensitivity", "INTERNAL").upper()
        is_pii = "PII" in sens or "HIPAA" in sens or "PCI" in sens

        if is_pii:
            case_type = "CASE_C"
            verdict_code = "PII_HOLD"
            verdict_label = "[COMPLIANCE HOLD: PII LOCKED]"
            safe_to_prune = False
            risk_score = 97
            confidence = 0.99
            centrality = round(min(0.98, 0.68 + len(prod_services) * 0.11), 2)
        elif len(prod_services) > 0:
            case_type = "CASE_B"
            verdict_code = "BLOCKED_PROD"
            verdict_label = "[BLOCKED: LIVE PROD DEPENDENCY]"
            safe_to_prune = False
            risk_score = min(94, 75 + len(prod_services) * 9)
            confidence = 0.98
            centrality = round(min(0.95, 0.52 + len(prod_services) * 0.15), 2)
        else:
            case_type = "CASE_A"
            verdict_code = "SAFE"
            verdict_label = "[SAFE TO CLEAN UP: ORPHANED DATA]"
            safe_to_prune = True
            risk_score = 8 if staging_services else 3
            confidence = 0.99
            centrality = round(0.08 if staging_services else 0.03, 2)

        highlighted_node_ids = list(
            dict.fromkeys(
                [bucket["id"], bucket["team_id"]]
                + connected_pipes
                + prod_services
                + staging_services
            )
        )

        return {
            "agent": cls.NAME,
            "case_type": case_type,
            "verdict_code": verdict_code,
            "verdict_label": verdict_label,
            "safe_to_prune": safe_to_prune,
            "risk_score": risk_score,
            "confidence_score": confidence,
            "degree_centrality": centrality,
            "max_hops": max_hops,
            "connected_pipes": connected_pipes,
            "prod_services": prod_services,
            "staging_services": staging_services,
            "highlighted_node_ids": highlighted_node_ids,
            "raw_cypher_query": cypher_query,
            "cypher_latency_ms": exec_ms,
            "reasoning_source": "falkordb_cypher" if graph_reasoning_used else "in_memory_demo_fallback",
            "thought_log": (
                f"[SherlockAgent]: {'FalkorDB Cypher' if graph_reasoning_used else 'In-memory fallback'} "
                f"evaluated the 1..3 hop dependency path ({max_hops} hops). "
                f"Verdict={verdict_label} ({case_type}). Prod Services={', '.join(prod_services) or 'None'}."
            ),
        }


class GuardianGovernorAgent:
    """
    3. Guardian Agent (Governor):
    Enforces compliance locks and automatically commits episodic memory nodes
    (:Memory) and procedural rules (:ProceduralRule) back into FalkorDB.
    """

    NAME = "Guardian (Governor)"

    @classmethod
    def record_episodic_verdict(
        cls,
        tenant: str,
        state: Dict[str, Any],
        bucket: Dict[str, Any],
        sherlock_res: Dict[str, Any],
        memory_type: str = "EPISODIC_ANALYSIS",
    ) -> Dict[str, Any]:
        mem_id = f"mem-{uuid.uuid4().hex[:6]}"
        now_iso = current_utc_iso()
        session_tag = f"Session #{len(state['memories']) + 101}"
        verdict_label = sherlock_res["verdict_label"]
        prod_svcs = sherlock_res["prod_services"]

        if sherlock_res["case_type"] == "CASE_C":
            rule_text = f"Procedural Rule: Any bucket tagged {bucket['sensitivity']} requires manual override from {ARCHITECT_HANDLE}."
            summary_text = (
                f"GuardianAgent enforced PII Compliance Hold on {bucket['id']} ({bucket['mass_tb']} TB) "
                f"owned by {ARCHITECT_HANDLE}."
            )
        elif sherlock_res["case_type"] == "CASE_B":
            rule_text = "Procedural Rule: Never delete storage buckets connected to active production services."
            summary_text = (
                f"GuardianAgent blocked cleanup of {bucket['id']} because live production services "
                f"({', '.join(prod_svcs)}) depend on it."
            )
        else:
            rule_text = "Procedural Rule: Orphaned buckets idle >90d with 0 production hops are cleared for automatic cleanup."
            summary_text = (
                f"GuardianAgent verified {bucket['id']} safe to clean up. Reclaiming {bucket['size_gb']} GB "
                f"saves ${bucket['monthly_cost_usd']}/mo and {bucket['carbon_kg']} kg CO2e."
            )

        new_mem: Dict[str, Any] = {
            "id": mem_id,
            "session": session_tag,
            "session_id": session_tag,
            "bucket": bucket["id"],
            "bucket_name": bucket["id"],
            "memory_type": memory_type,
            "verdict": verdict_label,
            "summary": summary_text,
            "rule": rule_text,
            "rule_learned": rule_text,
            "owner": ARCHITECT_HANDLE,
            "timestamp": f"{session_tag} • Verified",
            "created_at": now_iso,
            "embedding": GraphRAGSemanticEngine.compute_embedding(
                f"{bucket['id']} {verdict_label} {summary_text} {rule_text}"
            ),
        }
        state["memories"].insert(0, new_mem)

        cypher_commit = (
            f"MATCH (b:Bucket {{id: '{sanitize_cypher(bucket['id'])}'}}) "
            f"CREATE (m:Memory {{id: '{mem_id}', bucket: '{sanitize_cypher(bucket['id'])}', "
            f"session: '{sanitize_cypher(session_tag)}', memory_type: '{memory_type}', "
            f"verdict: '{sanitize_cypher(verdict_label)}', summary: '{sanitize_cypher(summary_text)}', "
            f"rule: '{sanitize_cypher(rule_text)}', owner: '{ARCHITECT_HANDLE}', created_at: '{now_iso}'}}) "
            f"CREATE (m)-[:ABOUT_BUCKET]->(b)"
        )
        graph_write, _ = cloud_pool.run_cypher(tenant, cypher_commit)
        new_mem["persistence_mode"] = "falkordb_cloud" if graph_write is not None else "in_memory_demo"

        return new_mem


# ==============================================================================
# MODULE 6: ESG, CARBON FOOTPRINT, & FINOPS METRICS AGGREGATION
# ==============================================================================
def aggregate_finops_esg_metrics(tenant: str) -> Dict[str, Any]:
    state = cloud_pool.store[tenant]
    buckets = state["buckets"]

    active_dark = [b for b in buckets if b["is_dark"] and not b["pruned"]]
    pruned_list = [b for b in buckets if b["pruned"]]

    protected_locks = 0
    safe_orphans = 0
    for b in active_dark:
        trace = SherlockReasonerAgent.trace_blast_radius(tenant, state, b)
        if trace["safe_to_prune"]:
            safe_orphans += 1
        else:
            protected_locks += 1

    reclaimed_gb = int(state["baseline_reclaimed_gb"]) + sum(int(b["size_gb"]) for b in pruned_list)
    monthly_saved_usd = int(state["baseline_saved_usd"]) + sum(int(b["monthly_cost_usd"]) for b in pruned_list)
    carbon_offset_kg = round(
        float(state["baseline_carbon_kg"]) + sum(float(b["carbon_kg"]) for b in pruned_list),
        1,
    )

    total_nodes = (
        len(state["teams"])
        + len(state["services"])
        + len(state["pipelines"])
        + len([b for b in buckets if not b["pruned"]])
    )
    total_edges = max(
        1,
        81 - (len(pruned_list) * 2) + (len([b for b in active_dark if b.get("is_chaos")]) * 3),
    )

    return {
        "tenant": tenant,
        "owner": ARCHITECT_HANDLE,
        "lead_architect": ARCHITECT_NAME,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "total_buckets": len(buckets),
        "idle_data_traps_count": len(active_dark),
        "dark_buckets_count": len(active_dark),
        "protected_production_locks": protected_locks,
        "protected_locks_count": protected_locks,
        "safe_orphans_count": safe_orphans,
        "pruned_buckets_count": len(pruned_list),
        "storage_reclaimed_gb": reclaimed_gb,
        "realized_storage_reclaimed_gb": reclaimed_gb,
        "monthly_money_saved_usd": monthly_saved_usd,
        "realized_monthly_savings_usd": monthly_saved_usd,
        "annual_money_saved_usd": monthly_saved_usd * 12,
        "realized_annual_savings_usd": monthly_saved_usd * 12,
        "carbon_footprint_offset_kg": carbon_offset_kg,
        "realized_carbon_saved_kg": carbon_offset_kg,
        "episodic_memories_count": len(state["memories"]),
        "procedural_rules_count": len(state["procedural_rules"]),
    }


# ==============================================================================
# PYDANTIC VALIDATION MODELS
# ==============================================================================
class AnalyzePruneRequestModel(BaseModel):
    bucket_id: Optional[str] = Field(default=None, description="Target storage bucket ID")
    bucket_name: Optional[str] = Field(default=None, description="Alias for bucket_id")
    tenant: Optional[str] = Field(default=None, description="Optional tenant override")
    operator: Optional[str] = Field(default=ARCHITECT_HANDLE, description="Lead Architect handle")

    def get_bucket_id(self) -> str:
        val = (self.bucket_id or self.bucket_name or "").strip()
        if not val:
            raise HTTPException(status_code=422, detail="Provide 'bucket_id' or 'bucket_name'.")
        return val


class ExecutePruneRequestModel(BaseModel):
    bucket_id: Optional[str] = Field(default=None, description="Target storage bucket ID")
    bucket_name: Optional[str] = Field(default=None, description="Alias for bucket_id")
    tenant: Optional[str] = Field(default=None, description="Optional tenant override")
    force_override: Optional[bool] = Field(default=False, description="Authorize security lock override")
    force: Optional[bool] = Field(default=False, description="Alias for force_override")
    operator: Optional[str] = Field(default=ARCHITECT_HANDLE, description="Lead Architect handle")

    def get_bucket_id(self) -> str:
        val = (self.bucket_id or self.bucket_name or "").strip()
        if not val:
            raise HTTPException(status_code=422, detail="Provide 'bucket_id' or 'bucket_name'.")
        return val

    def is_forced(self) -> bool:
        return bool(self.force_override or self.force)


class ChaosInjectRequestModel(BaseModel):
    tenant: Optional[str] = Field(default=None, description="Optional tenant override")
    custom_bucket_name: Optional[str] = Field(default=None, description="Optional custom rogue bucket ID")
    operator: Optional[str] = Field(default=ARCHITECT_HANDLE, description="Lead Architect handle")


class ChaosResetRequestModel(BaseModel):
    tenant: Optional[str] = Field(default=None, description="Optional tenant override")
    restore_all_pruned: Optional[bool] = Field(default=True, description="Restore baseline 45-node state")
    operator: Optional[str] = Field(default=ARCHITECT_HANDLE, description="Lead Architect handle")


class GraphRAGSearchRequestModel(BaseModel):
    query: str = Field(..., min_length=2, description="Natural language or keyword search query")
    tenant: Optional[str] = Field(default=None, description="Optional tenant override")
    top_k: int = Field(default=5, ge=1, le=20, description="Max results per category")


class GraphRAGIngestTraceRequestModel(BaseModel):
    bucket_id: str = Field(..., description="Associated bucket ID")
    raw_text: str = Field(..., min_length=5, max_length=5000, description="Unstructured agent log or error trace text")
    agent: Optional[str] = Field(default="ReconAgent", description="Originating agent")
    severity: Optional[str] = Field(default="INFO", description="Trace severity")
    tenant: Optional[str] = Field(default=None, description="Optional tenant override")


# ==============================================================================
# FASTAPI LIFESPAN & APP INITIALIZATION
# ==============================================================================
@asynccontextmanager
async def app_lifespan(app_instance: FastAPI):
    api_logger.info("====================================================================")
    api_logger.info(" AURA-GRAPH // DarkData-GraphOps Engine v2.6.0 Starting...")
    api_logger.info(f" Lead Architect : {ARCHITECT_NAME} ({ARCHITECT_HANDLE})")
    api_logger.info(f" FalkorDB Cloud : {FALKORDB_HOST}:{FALKORDB_PORT}")
    api_logger.info("====================================================================")
    cloud_pool.get_tenant_graph(DEFAULT_TENANT)
    yield
    api_logger.info("AURA-GRAPH // DarkData-GraphOps Engine shutdown complete.")


app = FastAPI(
    title="AURA-GRAPH // DarkData-GraphOps Engine",
    version="2.6.0",
    description=(
        "Multi-Tenant Cloud Governance Demo with GraphRAG-style retrieval and "
        "3-Agent Graph-Assisted Remediation Prototype powered by FalkorDB. "
        "Solo Architect: Prateek Gupta (@prateek)."
    ),
    lifespan=app_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv(
        "CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000"
    ).split(",") if origin.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Tenant", "X-Tenant-Graph", "X-Admin-Key"],
)


# ==============================================================================
# MODULE 7: COMPLETE FASTAPI ROUTE MANIFEST
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. GET / & GET /api/health
# ------------------------------------------------------------------------------
@app.get("/")
async def serve_war_room_dashboard(
    active_tenant: str = Depends(resolve_active_tenant),
    accept: Optional[str] = Header(default=""),
):
    """Serves `backend/index.html` to browsers or health JSON to API callers."""
    html_file = Path(__file__).resolve().parent / "index.html"
    wants_json = "application/json" in (accept or "").lower() and "text/html" not in (accept or "").lower()
    if html_file.exists() and not wants_json:
        return FileResponse(html_file)
    return await get_health_status(active_tenant=active_tenant)


@app.get("/api/health")
async def get_health_status(active_tenant: str = Depends(resolve_active_tenant)):
    graph, latency_ms = cloud_pool.get_tenant_graph(active_tenant)
    return {
        "status": "ONLINE" if graph is not None else "DEGRADED",
        "service": "ONLINE",
        "graph_mode": "falkordb_cloud" if graph is not None else "in_memory_demo",
        "title": "AURA-GRAPH // DarkData-GraphOps Engine",
        "version": "2.6.0",
        "owner": ARCHITECT_HANDLE,
        "lead_architect": ARCHITECT_NAME,
        "falkordb_cloud": {
            "connected": graph is not None,
            "host": FALKORDB_HOST,
            "port": FALKORDB_PORT,
            "latency_ms": latency_ms,
        },
        "active_tenant": active_tenant,
        "supported_tenants": SUPPORTED_TENANTS,
        "agents": ["Recon (Scout)", "Sherlock (Reasoner)", "Guardian (Governor)"],
        "timestamp": current_utc_iso(),
    }


# ------------------------------------------------------------------------------
# 2. GET /api/graph/stats
# ------------------------------------------------------------------------------
@app.get("/api/graph/stats")
async def get_graph_stats(active_tenant: str = Depends(resolve_active_tenant)):
    latency_ms = hydrate_tenant_state_from_graph(active_tenant)
    stats = aggregate_finops_esg_metrics(active_tenant)
    return {
        **stats,
        "falkordb_latency_ms": latency_ms,
        "timestamp": current_utc_iso(),
    }


# ------------------------------------------------------------------------------
# 3. GET /api/graph/topology
# ------------------------------------------------------------------------------
@app.get("/api/graph/topology")
async def get_graph_topology(active_tenant: str = Depends(resolve_active_tenant)):
    latency_ms = hydrate_tenant_state_from_graph(active_tenant)
    state = cloud_pool.store[active_tenant]
    prefix = TENANT_CONFIGS[active_tenant]["prefix"]

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for b in state["buckets"]:
        if b["pruned"]:
            continue
        trace = SherlockReasonerAgent.trace_blast_radius(active_tenant, state, b)
        nodes.append({
            "id": b["id"],
            "label": b["id"].replace(f"bkt-{prefix}-", ""),
            "category": "Idle Storage Bucket",
            "shape": "box",
            "owner": ARCHITECT_HANDLE,
            "safe_to_prune": trace["safe_to_prune"],
            "idle_days": b["idle_days"],
            "size_gb": b["size_gb"],
            "monthly_cost_usd": b["monthly_cost_usd"],
            "carbon_kg": b["carbon_kg"],
            "sensitivity": b["sensitivity"],
            "verdict_label": trace["verdict_label"],
            "title": (
                f"Bucket: {b['id']}\nOwner: {ARCHITECT_HANDLE}\n"
                f"Idle: {b['idle_days']}d | Cost: ${b['monthly_cost_usd']}/mo\n"
                f"Verdict: {trace['verdict_label']}"
            ),
        })
        edges.append({"from": b["team_id"], "to": b["id"], "label": "OWNS"})
        for r_pipe in b["readers"]:
            edges.append({"from": r_pipe, "to": b["id"], "label": "READS"})
        for w_pipe in b["writers"]:
            edges.append({"from": w_pipe, "to": b["id"], "label": "WRITES"})

    for pl in state["pipelines"]:
        nodes.append({
            "id": pl["id"],
            "label": pl["id"],
            "category": "Data Pipeline",
            "shape": "diamond",
            "owner": ARCHITECT_HANDLE,
            "title": f"Data Pipeline: {pl['id']}\nOwner: {ARCHITECT_HANDLE}",
        })
        edges.append({"from": pl["team_id"], "to": pl["id"], "label": "OWNS"})

    for sv in state["services"]:
        is_prod = sv["env"] == "PRODUCTION"
        nodes.append({
            "id": sv["id"],
            "label": f"{sv['id']}\n[{'PROD' if is_prod else 'STAGE'}]",
            "category": "Production Service",
            "shape": "dot",
            "env": sv["env"],
            "owner": ARCHITECT_HANDLE,
            "title": f"Cloud Service: {sv['id']} ({sv['env']})\nOwner: {ARCHITECT_HANDLE}",
        })
        edges.append({"from": sv["team_id"], "to": sv["id"], "label": "OWNS"})
        for p_id in sv["pipes"]:
            edges.append({"from": sv["id"], "to": p_id, "label": "USES"})
        for d_id in sv["deps"]:
            edges.append({"from": sv["id"], "to": d_id, "label": "CALLS"})

    for t in state["teams"]:
        nodes.append({
            "id": t["id"],
            "label": t["id"].replace("Arch:", ""),
            "category": "Team",
            "shape": "dot",
            "owner": ARCHITECT_HANDLE,
            "title": f"Command Unit: {t['id']}\nLead Architect: {ARCHITECT_NAME} ({ARCHITECT_HANDLE})",
        })

    return {
        "tenant": active_tenant,
        "owner": ARCHITECT_HANDLE,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "falkordb_latency_ms": latency_ms,
        "nodes": nodes,
        "edges": edges,
    }


# ------------------------------------------------------------------------------
# 4. GET /api/buckets/dark
# ------------------------------------------------------------------------------
@app.get("/api/buckets/dark")
async def get_dark_storage_buckets(active_tenant: str = Depends(resolve_active_tenant)):
    hydrate_tenant_state_from_graph(active_tenant)
    state = cloud_pool.store[active_tenant]
    results: List[Dict[str, Any]] = []

    for b in state["buckets"]:
        if not b["is_dark"]:
            continue
        scout = ReconScoutAgent.analyze_bucket_telemetry(b)
        reasoner = SherlockReasonerAgent.trace_blast_radius(active_tenant, state, b)

        results.append({
            **b,
            "owner": ARCHITECT_HANDLE,
            "mass_tb": scout["mass_tb"],
            "case_type": reasoner["case_type"],
            "verdict_code": reasoner["verdict_code"],
            "verdict_label": "[CLEANED UP ✓]" if b["pruned"] else reasoner["verdict_label"],
            "safe_to_prune": reasoner["safe_to_prune"],
            "risk_score": reasoner["risk_score"],
            "confidence_score": reasoner["confidence_score"],
            "degree_centrality": reasoner["degree_centrality"],
            "connected_pipes": reasoner["connected_pipes"],
            "connected_services": [f"{s} (PROD)" for s in reasoner["prod_services"]],
        })

    return {
        "tenant": active_tenant,
        "owner": ARCHITECT_HANDLE,
        "count": len(results),
        "buckets": results,
    }


# ------------------------------------------------------------------------------
# 5. POST /api/agent/analyze-prune
# ------------------------------------------------------------------------------
@app.post("/api/agent/analyze-prune")
async def post_agent_analyze_prune(
    payload: AnalyzePruneRequestModel,
    active_tenant: str = Depends(resolve_active_tenant),
):
    tenant = payload.tenant if payload.tenant in SUPPORTED_TENANTS else active_tenant
    target_id = payload.get_bucket_id()
    hydrate_tenant_state_from_graph(tenant)
    state = cloud_pool.store[tenant]

    bucket = next(
        (b for b in state["buckets"] if b["id"] == target_id or b["name"] == target_id),
        None,
    )
    if bucket is None:
        raise HTTPException(status_code=404, detail=f"Bucket '{target_id}' not found in tenant '{tenant}'.")

    scout_res = ReconScoutAgent.analyze_bucket_telemetry(bucket)
    sherlock_res = SherlockReasonerAgent.trace_blast_radius(tenant, state, bucket)
    memory_node = GuardianGovernorAgent.record_episodic_verdict(
        tenant=tenant,
        state=state,
        bucket=bucket,
        sherlock_res=sherlock_res,
        memory_type="EPISODIC_ANALYSIS",
    )

    return {
        "tenant": tenant,
        "owner": ARCHITECT_HANDLE,
        "bucket_id": bucket["id"],
        "case_type": sherlock_res["case_type"],
        "verdict_code": sherlock_res["verdict_code"],
        "verdict_label": sherlock_res["verdict_label"],
        "safe_to_prune": sherlock_res["safe_to_prune"],
        "risk_score": sherlock_res["risk_score"],
        "confidence_score": sherlock_res["confidence_score"],
        "degree_centrality": sherlock_res["degree_centrality"],
        "explanation": bucket["explanation"],
        "telemetry": scout_res,
        "impacted_production_services": sherlock_res["prod_services"],
        "connected_pipelines": sherlock_res["connected_pipes"],
        "highlighted_node_ids": sherlock_res["highlighted_node_ids"],
        "raw_cypher_query": sherlock_res["raw_cypher_query"],
        "reasoning_source": sherlock_res["reasoning_source"],
        "cypher_latency_ms": sherlock_res["cypher_latency_ms"],
        "thought_stream": [
            scout_res["thought_log"],
            sherlock_res["thought_log"],
            f"[GuardianAgent]: Recorded episodic memory ({memory_node['id']}) via {memory_node.get('persistence_mode', 'in_memory_demo')}.",
        ],
        "recorded_memory": memory_node,
    }


# ------------------------------------------------------------------------------
# 6. POST /api/agent/execute-prune
# ------------------------------------------------------------------------------
@app.post("/api/agent/execute-prune")
async def post_agent_execute_prune(
    payload: ExecutePruneRequestModel,
    active_tenant: str = Depends(resolve_active_tenant),
    admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    tenant = payload.tenant if payload.tenant in SUPPORTED_TENANTS else active_tenant
    target_id = payload.get_bucket_id()
    force_flag = payload.is_forced()
    if force_flag:
        if not AURA_ADMIN_API_KEY:
            raise HTTPException(
                status_code=503,
                detail="Security override is disabled. Configure AURA_ADMIN_API_KEY on the server before enabling forced cleanup.",
            )
        if not admin_key or not secrets.compare_digest(admin_key, AURA_ADMIN_API_KEY):
            raise HTTPException(status_code=403, detail="Invalid or missing admin override key.")
    hydrate_tenant_state_from_graph(tenant)
    state = cloud_pool.store[tenant]

    bucket = next(
        (b for b in state["buckets"] if b["id"] == target_id or b["name"] == target_id),
        None,
    )
    if bucket is None:
        raise HTTPException(status_code=404, detail=f"Bucket '{target_id}' not found in tenant '{tenant}'.")
    if bucket.get("pruned"):
        raise HTTPException(status_code=409, detail=f"Bucket '{target_id}' is already marked as pruned.")

    sherlock_res = SherlockReasonerAgent.trace_blast_radius(tenant, state, bucket)
    if not sherlock_res["safe_to_prune"] and not force_flag:
        raise HTTPException(
            status_code=400,
            detail=(
                f"GuardianAgent blocked cleanup on '{bucket['id']}': {sherlock_res['verdict_label']}. "
                f"Override authorization from {ARCHITECT_HANDLE} required."
            ),
        )

    bucket["pruned"] = True
    now_iso = current_utc_iso()
    mem_id = f"mem-clean-{uuid.uuid4().hex[:6]}"
    verdict_tag = "[OVERRIDE METADATA PRUNE]" if force_flag and not sherlock_res["safe_to_prune"] else "[SAFE METADATA PRUNE]"
    summary_text = (
        f"Marked {bucket['id']} ({bucket['mass_tb']} TB) as pruned in graph metadata. "
        f"Estimated impact: ${bucket['monthly_cost_usd']}/mo and {bucket['carbon_kg']} kg CO2e. "
        "No external cloud storage object was deleted."
    )

    prune_mem: Dict[str, Any] = {
        "id": mem_id,
        "session": f"Session #{len(state['memories']) + 101}",
        "session_id": f"Session #{len(state['memories']) + 101}",
        "bucket": bucket["id"],
        "bucket_name": bucket["id"],
        "memory_type": "EPISODIC_PRUNE_SIGN_OFF",
        "verdict": verdict_tag,
        "summary": summary_text,
        "rule": "Demo action: bucket metadata marked pruned in the graph; no external cloud object was deleted.",
        "rule_learned": "Demo action: bucket metadata marked pruned in the graph; no external cloud object was deleted.",
        "owner": ARCHITECT_HANDLE,
        "timestamp": now_iso,
        "created_at": now_iso,
        "persistence_mode": "falkordb_cloud" if cloud_pool.cloud_connected else "in_memory_demo",
        "embedding": GraphRAGSemanticEngine.compute_embedding(f"{bucket['id']} {verdict_tag} {summary_text}"),
    }
    state["memories"].insert(0, prune_mem)

    cloud_pool.run_cypher(
        tenant,
        f"MATCH (b:Bucket {{id: '{sanitize_cypher(bucket['id'])}'}}) SET b.pruned = true",
    )

    return {
        "status": "PRUNED",
        "tenant": tenant,
        "owner": ARCHITECT_HANDLE,
        "bucket_id": bucket["id"],
        "force_override_used": force_flag,
        "reclaimed_gb": bucket["size_gb"],
        "saved_monthly_usd": bucket["monthly_cost_usd"],
        "saved_carbon_kg": bucket["carbon_kg"],
        "recorded_memory": prune_mem,
        "updated_stats": aggregate_finops_esg_metrics(tenant),
        "execution_mode": "graph_metadata_only",
        "notice": "This demo marks graph metadata as pruned; it does not delete objects from AWS, GCP, Azure, or any external storage provider.",
    }


# ------------------------------------------------------------------------------
# 7. POST /api/chaos/inject
# ------------------------------------------------------------------------------
@app.post("/api/chaos/inject")
async def post_chaos_inject(
    payload: Optional[ChaosInjectRequestModel] = None,
    active_tenant: str = Depends(resolve_active_tenant),
):
    body = payload or ChaosInjectRequestModel()
    tenant = body.tenant if body.tenant in SUPPORTED_TENANTS else active_tenant
    hydrate_tenant_state_from_graph(tenant)
    state = cloud_pool.store[tenant]

    short_id = uuid.uuid4().hex[:4]
    rogue_id = (body.custom_bucket_name or f"bkt-rogue-shadow-trap-{short_id}").strip()
    if not rogue_id or len(rogue_id) > 80 or any(not (ch.isalnum() or ch in "-_:." ) for ch in rogue_id):
        raise HTTPException(status_code=422, detail="custom_bucket_name may contain only letters, numbers, dot, colon, underscore and hyphen (max 80 chars).")
    now_iso = current_utc_iso()

    rogue_bucket: Dict[str, Any] = {
        "id": rogue_id,
        "name": rogue_id,
        "is_dark": True,
        "pruned": False,
        "is_chaos": True,
        "idle_days": 176,
        "size_gb": 16800,
        "mass_tb": 16.8,
        "monthly_cost_usd": 2016,
        "carbon_kg": 470.4,
        "sensitivity": "PII_LOCKED",
        "owner": ARCHITECT_HANDLE,
        "team_id": "Arch:@prateek-SecOps",
        "readers": ["pipe-quarterly-recon", "pipe-kyc-verifier"],
        "writers": [],
        "verdict_code": "BLOCKED_PROD",
        "verdict_label": "[BLOCKED: LIVE PROD DEPENDENCY]",
        "explanation": (
            "CHAOS SANDBOX TRAP: Hidden shadow bucket with 3-hop links to BillingService, "
            "FraudDetectionEngine, and CheckoutAPI!"
        ),
    }
    state["buckets"].insert(0, rogue_bucket)

    chaos_mem_id = f"mem-chaos-{short_id}"
    chaos_summary = (
        f"Chaos Sandbox injected {rogue_id} (16.8 TB). SherlockAgent & GuardianAgent immediately "
        f"detected 3 live production services and locked deletion."
    )
    chaos_mem: Dict[str, Any] = {
        "id": chaos_mem_id,
        "session": "Chaos Sandbox",
        "session_id": "Chaos Sandbox",
        "bucket": rogue_id,
        "bucket_name": rogue_id,
        "memory_type": "CHAOS_SANDBOX_TRAP",
        "verdict": "[BLOCKED: LIVE PROD DEPENDENCY]",
        "summary": chaos_summary,
        "rule": "Procedural Rule: Automatically quarantine unindexed shadow buckets with hidden production links.",
        "rule_learned": "Procedural Rule: Automatically quarantine unindexed shadow buckets with hidden production links.",
        "owner": ARCHITECT_HANDLE,
        "timestamp": "Chaos Test • Verified",
        "created_at": now_iso,
        "is_chaos": True,
        "embedding": GraphRAGSemanticEngine.compute_embedding(f"{rogue_id} {chaos_summary}"),
    }
    state["memories"].insert(0, chaos_mem)

    cloud_pool.run_cypher(
        tenant,
        f"MATCH (p1:Pipeline {{id: 'pipe-quarterly-recon'}}), (p2:Pipeline {{id: 'pipe-kyc-verifier'}}), "
        f"(t:Team {{id: 'Arch:@prateek-SecOps'}}) "
        f"CREATE (b:Bucket {{id: '{sanitize_cypher(rogue_id)}', name: '{sanitize_cypher(rogue_id)}', "
        f"is_dark: true, pruned: false, is_chaos: true, idle_days: 176, size_gb: 16800, "
        f"monthly_cost_usd: 2016, carbon_kg: 470.4, sensitivity: 'PII_LOCKED', owner: '{ARCHITECT_HANDLE}'}}) "
        f"CREATE (t)-[:OWNS]->(b), (p1)-[:READS_FROM]->(b), (p2)-[:READS_FROM]->(b)",
    )

    return {
        "status": "CHAOS_INJECTED",
        "tenant": tenant,
        "owner": ARCHITECT_HANDLE,
        "injected_bucket": rogue_bucket,
        "recorded_memory": chaos_mem,
        "updated_stats": aggregate_finops_esg_metrics(tenant),
    }


# ------------------------------------------------------------------------------
# 8. POST /api/chaos/reset
# ------------------------------------------------------------------------------
@app.post("/api/chaos/reset")
async def post_chaos_reset(
    payload: Optional[ChaosResetRequestModel] = None,
    active_tenant: str = Depends(resolve_active_tenant),
):
    body = payload or ChaosResetRequestModel()
    tenant = body.tenant if body.tenant in SUPPORTED_TENANTS else active_tenant
    hydrate_tenant_state_from_graph(tenant)

    if body.restore_all_pruned:
        cloud_pool.store[tenant] = generate_tenant_baseline(tenant)
    else:
        state = cloud_pool.store[tenant]
        state["buckets"] = [b for b in state["buckets"] if not b.get("is_chaos", False)]
        state["memories"] = [m for m in state["memories"] if not m.get("is_chaos", False)]

    cloud_pool.run_cypher(tenant, "MATCH (b:Bucket {is_chaos: true}) DETACH DELETE b")

    return {
        "status": "CHAOS_RESET_COMPLETE",
        "tenant": tenant,
        "owner": ARCHITECT_HANDLE,
        "updated_stats": aggregate_finops_esg_metrics(tenant),
    }


# ------------------------------------------------------------------------------
# 9. GET /api/memory/vault (PLUS /api/agent/memories ALIAS)
# ------------------------------------------------------------------------------
def hydrate_tenant_state_from_graph(tenant: str) -> float:
    """Refresh durable bucket, memory, rule and trace state from FalkorDB when available."""
    graph, latency_ms = cloud_pool.get_tenant_graph(tenant)
    if graph is None:
        return latency_ms
    state = cloud_pool.store[tenant]
    try:
        bucket_result = graph.query(
            "MATCH (b:Bucket) RETURN b.id, b.pruned, b.idle_days, b.size_gb, "
            "b.monthly_cost_usd, b.carbon_kg, b.sensitivity"
        )
        by_id = {b["id"]: b for b in state["buckets"]}
        for row in getattr(bucket_result, "result_set", []) or []:
            if not row or row[0] not in by_id:
                continue
            bucket = by_id[row[0]]
            if len(row) > 1 and row[1] is not None: bucket["pruned"] = bool(row[1])
            if len(row) > 2 and row[2] is not None: bucket["idle_days"] = int(row[2])
            if len(row) > 3 and row[3] is not None: bucket["size_gb"] = int(row[3])
            if len(row) > 4 and row[4] is not None: bucket["monthly_cost_usd"] = float(row[4])
            if len(row) > 5 and row[5] is not None: bucket["carbon_kg"] = float(row[5])
            if len(row) > 6 and row[6] is not None: bucket["sensitivity"] = str(row[6])

        memory_result = graph.query(
            "MATCH (m:Memory) OPTIONAL MATCH (m)-[:ABOUT_BUCKET]->(b:Bucket) "
            "RETURN m.id, m.session, coalesce(m.bucket, b.id), m.memory_type, "
            "m.verdict, m.summary, m.rule, m.owner, m.created_at "
            "ORDER BY m.created_at DESC LIMIT 100"
        )
        graph_memories = []
        for row in getattr(memory_result, "result_set", []) or []:
            if not row: continue
            graph_memories.append({
                "id": row[0] or f"memory-{uuid.uuid4().hex[:8]}",
                "session": row[1] or "Persistent Graph Session",
                "session_id": row[1] or "Persistent Graph Session",
                "bucket": row[2] or "Unknown bucket",
                "bucket_name": row[2] or "Unknown bucket",
                "memory_type": row[3] or "EPISODIC_MEMORY",
                "verdict": row[4] or "RECORDED",
                "summary": row[5] or "",
                "rule": row[6] or "",
                "owner": row[7] or ARCHITECT_HANDLE,
                "timestamp": row[8] or "Stored in FalkorDB",
                "created_at": row[8] or "",
                "persistence_mode": "falkordb_cloud",
            })
        if graph_memories:
            state["memories"] = graph_memories

        rule_result = graph.query(
            "MATCH (r:ProceduralRule) RETURN r.id, r.code, r.title, r.rule_text, r.owner, r.created_at LIMIT 100"
        )
        graph_rules = []
        for row in getattr(rule_result, "result_set", []) or []:
            if not row: continue
            graph_rules.append({
                "id": row[0] or "graph-rule",
                "code": row[1] or "GRAPH_RULE",
                "title": row[2] or "Graph governance rule",
                "rule_text": row[3] or "",
                "owner": row[4] or ARCHITECT_HANDLE,
                "created_at": row[5] or "",
            })
        if graph_rules:
            state["procedural_rules"] = graph_rules

        trace_result = graph.query(
            "MATCH (t:TraceLog) OPTIONAL MATCH (t)-[:TRACED_ON]->(b:Bucket) "
            "RETURN t.id, coalesce(t.bucket_id, b.id), t.agent, t.severity, t.raw_text, t.owner, t.created_at "
            "ORDER BY t.created_at DESC LIMIT 100"
        )
        graph_traces = []
        for row in getattr(trace_result, "result_set", []) or []:
            if not row: continue
            raw_text = row[4] or ""
            graph_traces.append({
                "trace_id": row[0] or f"trace-{uuid.uuid4().hex[:8]}",
                "bucket_id": row[1] or "Unknown bucket",
                "agent": row[2] or "UnknownAgent",
                "severity": row[3] or "INFO",
                "raw_text": raw_text,
                "owner": row[5] or ARCHITECT_HANDLE,
                "created_at": row[6] or "",
                "embedding": GraphRAGSemanticEngine.compute_embedding(raw_text),
            })
        if graph_traces:
            state["unstructured_traces"] = graph_traces
    except Exception as exc:
        db_logger.warning("Could not hydrate persistent tenant state for '%s': %s", tenant, exc)
    return latency_ms


@app.get("/api/memory/vault")
@app.get("/api/agent/memories")
async def get_episodic_memory_vault(active_tenant: str = Depends(resolve_active_tenant)):
    latency_ms = hydrate_tenant_state_from_graph(active_tenant)
    state = cloud_pool.store[active_tenant]
    return {
        "tenant": active_tenant,
        "owner": ARCHITECT_HANDLE,
        "lead_architect": ARCHITECT_NAME,
        "persistence_mode": "falkordb_cloud" if cloud_pool.cloud_connected else "in_memory_demo",
        "memories_count": len(state["memories"]),
        "procedural_rules_count": len(state["procedural_rules"]),
        "falkordb_latency_ms": latency_ms,
        "memories": state["memories"],
        "procedural_rules": state["procedural_rules"],
        "unstructured_traces_count": len(state["unstructured_traces"]),
    }


# ------------------------------------------------------------------------------
# 10. GRAPHRAG ROUTES:
#   - POST /api/graphrag/search (and POST /api/memory/search alias)
#   - POST /api/graphrag/ingest-trace
#   - GET  /api/graphrag/context/{bucket_id}
# ------------------------------------------------------------------------------
@app.post("/api/graphrag/search")
@app.post("/api/memory/search")
async def post_graphrag_semantic_search(
    payload: GraphRAGSearchRequestModel,
    active_tenant: str = Depends(resolve_active_tenant),
):
    tenant = payload.tenant if payload.tenant in SUPPORTED_TENANTS else active_tenant
    hydrate_tenant_state_from_graph(tenant)
    state = cloud_pool.store[tenant]
    search_results = GraphRAGSemanticEngine.semantic_search(
        state=state,
        query=payload.query,
        top_k=payload.top_k,
    )
    graphrag_logger.info(f"GraphRAG semantic search on '{tenant}' for query='{payload.query}'")
    return {
        "tenant": tenant,
        "owner": ARCHITECT_HANDLE,
        **search_results,
    }


@app.post("/api/graphrag/ingest-trace")
async def post_graphrag_ingest_trace(
    payload: GraphRAGIngestTraceRequestModel,
    active_tenant: str = Depends(resolve_active_tenant),
):
    tenant = payload.tenant if payload.tenant in SUPPORTED_TENANTS else active_tenant
    hydrate_tenant_state_from_graph(tenant)
    state = cloud_pool.store[tenant]
    if not any(b["id"] == payload.bucket_id for b in state["buckets"]):
        raise HTTPException(status_code=404, detail=f"Bucket '{payload.bucket_id}' not found in tenant '{tenant}'.")
    now_iso = current_utc_iso()
    trace_id = f"trace-{uuid.uuid4().hex[:6]}"
    emb = GraphRAGSemanticEngine.compute_embedding(f"{payload.bucket_id} {payload.raw_text}")

    trace_node: Dict[str, Any] = {
        "trace_id": trace_id,
        "bucket_id": payload.bucket_id,
        "agent": payload.agent or "ReconAgent",
        "severity": payload.severity or "INFO",
        "raw_text": payload.raw_text,
        "owner": ARCHITECT_HANDLE,
        "created_at": now_iso,
        "embedding": emb,
    }
    state["unstructured_traces"].insert(0, trace_node)

    cloud_pool.run_cypher(
        tenant,
        f"MATCH (b:Bucket {{id: '{sanitize_cypher(payload.bucket_id)}'}}) "
        f"CREATE (tr:TraceLog {{id: '{trace_id}', bucket_id: '{sanitize_cypher(payload.bucket_id)}', "
        f"agent: '{sanitize_cypher(trace_node['agent'])}', severity: '{sanitize_cypher(trace_node['severity'])}', "
        f"raw_text: '{sanitize_cypher(payload.raw_text)}', "
        f"owner: '{ARCHITECT_HANDLE}', created_at: '{now_iso}'}}) "
        f"CREATE (tr)-[:TRACED_ON]->(b)",
    )

    graphrag_logger.info(f"Ingested unstructured trace '{trace_id}' for bucket '{payload.bucket_id}'")
    return {
        "status": "TRACE_INGESTED",
        "tenant": tenant,
        "owner": ARCHITECT_HANDLE,
        "trace": trace_node,
    }


@app.get("/api/graphrag/context/{bucket_id}")
async def get_graphrag_bucket_context(
    bucket_id: str = FastAPIPath(..., description="Target storage bucket ID"),
    active_tenant: str = Depends(resolve_active_tenant),
):
    hydrate_tenant_state_from_graph(active_tenant)
    state = cloud_pool.store[active_tenant]
    bucket = next(
        (b for b in state["buckets"] if b["id"] == bucket_id or b["name"] == bucket_id),
        None,
    )
    if bucket is None:
        raise HTTPException(status_code=404, detail=f"Bucket '{bucket_id}' not found in tenant '{active_tenant}'.")

    scout = ReconScoutAgent.analyze_bucket_telemetry(bucket)
    sherlock = SherlockReasonerAgent.trace_blast_radius(active_tenant, state, bucket)
    linked_memories = [m for m in state["memories"] if m["bucket"] == bucket["id"]]
    linked_traces = [t for t in state["unstructured_traces"] if t["bucket_id"] == bucket["id"]]
    semantic_neighbors = GraphRAGSemanticEngine.semantic_search(
        state=state,
        query=f"{bucket['id']} {bucket['sensitivity']} {sherlock['verdict_label']}",
        top_k=3,
    )

    return {
        "tenant": active_tenant,
        "owner": ARCHITECT_HANDLE,
        "lead_architect": ARCHITECT_NAME,
        "bucket": bucket,
        "scout_telemetry": scout,
        "sherlock_blast_radius": sherlock,
        "linked_episodic_memories": linked_memories,
        "linked_unstructured_traces": linked_traces,
        "procedural_rules": state["procedural_rules"],
        "semantic_neighbors": semantic_neighbors["matched_buckets"],
    }


# ==============================================================================
# GLOBAL EXCEPTION HANDLER
# ==============================================================================
@app.exception_handler(Exception)
async def global_api_exception_handler(request: Request, exc: Exception):
    api_logger.error(f"Unhandled error on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "status": "ERROR",
            "title": "AURA-GRAPH // DarkData-GraphOps Engine",
            "owner": ARCHITECT_HANDLE,
            "path": str(request.url.path),
            "detail": str(exc),
            "timestamp": current_utc_iso(),
        },
    )


# ==============================================================================
# MODULE 8: SERVER EXECUTION BLOCK
# ==============================================================================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)