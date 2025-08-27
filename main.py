from fastapi import FastAPI, Request, Depends, Header, APIRouter, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, AnyUrl, constr
from datetime import datetime
import os
import time
import requests
from ldap3 import Server, Connection, ALL, SUBTREE
import logging
import json
import hmac
import hashlib
from uuid import uuid4
from pathlib import Path
from typing import List, Optional, Dict, Literal, Any, Set, Tuple

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except Exception:
    boto3 = None

from database import SessionLocal, engine, Base
from models import Application, ApplicationUserAccess, Vulnerability

DATABASE_PATH = "/app/data/app.db"  # must match your Helm mountPath

# ----------------- WAVES ROUTER (Jenkins orchestration) -----------------
waves_router = APIRouter(prefix="/waves", tags=["waves"])

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# With your ingress rewrite (/pipeline/api -> /), no root_path is needed.
app = FastAPI()

Base.metadata.create_all(bind=engine)

# Jenkins configuration
JENKINS_URL = "https://horizonrelevance.com/jenkins"
JENKINS_USER = os.getenv("JENKINS_USER")
JENKINS_TOKEN = os.getenv("JENKINS_TOKEN")

# In-memory store for demo
WAVES: Dict[str, dict] = {}  # wave_id -> wave doc
EXECUTIONS: Dict[str, dict] = {}

# GitHub webhook secret
GITHUB_WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]

# LDAP configuration
LDAP_SERVER = "ldaps://ldap.jumpcloud.com:636"
LDAP_USER = "uid=ankur.kashyap,ou=Users,o=6817d9a0d50cd4b1b5b81ba7,dc=jumpcloud,dc=com"
LDAP_PASSWORD = os.getenv("LDAP_MANAGER_PASSWORD")
LDAP_BASE_DN = "ou=Users,o=6817d9a0d50cd4b1b5b81ba7,dc=jumpcloud,dc=com"
SEARCH_FILTER = "(objectClass=person)"

# CORS setup for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://horizonrelevance.com",
        "https://www.horizonrelevance.com",
        # "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Serve JSON/UI schemas so the frontend can fetch them
Path("schemas").mkdir(parents=True, exist_ok=True)
app.mount("/schemas", StaticFiles(directory="schemas"), name="schemas")

@app.get("/healthz")
def healthz():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

# ----------------- TENANT REGISTRY -----------------
TENANTS: Dict[str, dict] = {}  # tenant_id -> { accounts, role arn, external id, tf state info, ... }

class PipelineRequest(BaseModel):
    project_name: str
    app_type: str
    repo_url: str
    branch: str
    ENABLE_SONARQUBE: bool
    ENABLE_OPA: bool
    ENABLE_TRIVY: bool
    requestedBy: str

class TriggerRequest(BaseModel):
    project_name: str

class VulnerabilityModel(BaseModel):
    target: str
    package_name: str
    installed_version: str
    vulnerability_id: str
    severity: str
    fixed_version: Optional[str] = None
    risk_score: float = 0.0
    description: Optional[str] = None
    source: Optional[str] = "Trivy"
    timestamp: Optional[str] = None
    line: Optional[int] = None
    rule: Optional[str] = None
    status: Optional[str] = None
    predictedSeverity: Optional[str] = None
    jenkins_job: str
    build_number: int
    jenkins_url: Optional[str] = None

class VulnerabilityUpload(BaseModel):
    vulnerabilities: List[VulnerabilityModel]

class OPARiskModel(BaseModel):
    target: str
    violation: str
    severity: str
    risk_score: float
    package_name: Optional[str] = "OPA Policy"
    installed_version: Optional[str] = "N/A"
    source: Optional[str] = "OPA"
    description: Optional[str] = ""
    remediation: Optional[str] = ""
    jenkins_job: Optional[str] = None
    build_number: Optional[int] = None
    jenkins_url: Optional[str] = None

class OPARiskUpload(BaseModel):
    application: str
    risks: List[OPARiskModel]

class UploadPayload(BaseModel):
    application: str
    requestedBy: str
    repo_url: str
    jenkins_url: str
    jenkins_job: str
    build_number: int
    vulnerabilities: List[VulnerabilityModel]

class RegisterAppRequest(BaseModel):
    name: str
    description: Optional[str] = None
    owner_email: str
    repo_url: str
    branch: str = "main"

class GrantAccessRequest(BaseModel):
    user_email: str
    application: str

class TenantUpsert(BaseModel):
    id: str
    # NEW (simple) shape: accounts[account_ref] = {"role_arn": "...", "external_id": "...", ...}
    accounts: Optional[Dict[str, Dict[str, str]]] = None

    # Legacy single-account fields (still supported)
    account_id: Optional[str] = None
    provisioner_role_arn: Optional[str] = None
    external_id: Optional[str] = None
    state_bucket: Optional[str] = None
    lock_table: Optional[str] = None
    regions: List[str] = ["us-east-1"]

# ---------- Models for EC2 Lift-and-Shift (AWS) ----------
class SmokeTest(BaseModel):
    type: Literal["http"] = "http"
    url: AnyUrl
    expect: Literal[200, 204] = 200

# ---------- Cloud Migration: multi-placement models ----------
Provider = Literal["aws", "azure", "gcp", "oci"]

class AwsPlacementParams(BaseModel):
    region: constr(regex=r"^[a-z]{2}-[a-z]+-\d$")
    vpc_id: constr(regex=r"^vpc-([0-9a-f]{8}|[0-9a-f]{17})$")
    private_subnet_ids: List[constr(regex=r"^subnet-([0-9a-f]{8}|[0-9a-f]{17})$")] = Field(..., min_items=2)
    security_group_ids: List[constr(regex=r"^sg-([0-9a-f]{8}|[0-9a-f]{17})$")] = Field(..., min_items=1)
    instance_type_map: Dict[
        constr(regex=r"^[A-Za-z0-9._-]{1,128}$"),
        constr(regex=r"^[a-z0-9-]+\.(nano|micro|small|medium|large|xlarge|[2-9]xlarge|[1-9][0-9]xlarge)$")
    ]
    tg_health_check_path: constr(regex=r"^/.*$") = "/healthz"
    attach_backup: bool = True
    kms_key_alias: constr(regex=r"^alias/[A-Za-z0-9/_-]{1,256}$") = "alias/tenant-data"
    blue_green: bool = True
    smoke_tests: List[SmokeTest] = Field(default_factory=list)
    tags: Dict[constr(regex=r"^[A-Za-z0-9._:/+=@-]{1,128}$"), constr(max_length=256)] = {}
    maintenance_window: Optional[constr(max_length=128)] = None
    copy_to_region: Optional[constr(regex=r"^[a-z]{2}-[a-z]+-\d$")] = None
    account_ref: constr(min_length=1)

class Placement(BaseModel):
    id: constr(min_length=1) = Field(default_factory=lambda: f"p-{uuid4().hex[:8]}")
    provider: Provider
    params: Dict[str, Any]

    @classmethod
    def aws(cls, **kwargs):
        p = AwsPlacementParams(**kwargs)
        return cls(provider="aws", params=p.dict())

class WaveCreate(BaseModel):
    tenant_id: str
    name: constr(min_length=1)
    blueprint_key: Literal["ec2-liftshift"]
    targets: List[constr(regex=r"^[A-Za-z0-9._-]{1,128}$")] = Field(..., min_items=1)
    placements: List[Placement]

@app.post("/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        return JSONResponse(status_code=400, content={"error": "Username and password required"})
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        search_conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)
        search_conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=f"(uid={username})",
            search_scope=SUBTREE,
            attributes=["displayName", "mail", "uid"]
        )
        if not search_conn.entries:
            return JSONResponse(status_code=401, content={"error": "User not found"})

        user_entry = search_conn.entries[0]
        user_dn = str(user_entry.entry_dn)
        display_name = str(user_entry.displayName)
        email = str(user_entry.mail)
        search_conn.unbind()

        auth_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        auth_conn.unbind()

        return {"username": username, "fullName": display_name, "email": email}

    except Exception:
        return JSONResponse(status_code=401, content={"error": "Invalid credentials or server error"})

@app.get("/get_ldap_users")
def get_ldap_users():
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=SEARCH_FILTER,
            search_scope=SUBTREE,
            attributes=["uid", "displayName", "mail"]
        )
        users = []
        seen = set()
        for entry in conn.entries:
            uid = str(entry.uid)
            display_name = str(entry.displayName)
            email = str(entry.mail)
            if uid not in seen:
                users.append({"username": uid, "fullName": display_name, "email": email})
                seen.add(uid)
        conn.unbind()
        return JSONResponse(content=users)
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Failed to fetch LDAP users"})

@app.get("/my_applications")
def get_user_applications(email: str, db: Session = Depends(get_db)):
    try:
        if email in ["ankur.kashyap@horizonrelevance.com"]:
            apps = db.query(Application.name).all()
            return [a.name for a in apps]

        apps = db.query(Application.name).join(ApplicationUserAccess).filter(
            ApplicationUserAccess.user_email == email
        ).all()
        return [a.name for a in apps]

    except Exception:
        return JSONResponse(status_code=500, content={"error": "Failed to call backend"})

@app.post("/pipeline")
def create_pipeline(request: PipelineRequest):
    job_config = f"""
<flow-definition plugin="workflow-job">
  <description>Dynamic Jenkins Pipeline for {request.project_name}</description>
  <properties>
    <hudson.model.ParametersDefinitionProperty>
      <parameterDefinitions>
        <hudson.model.StringParameterDefinition>
          <name>APP_TYPE</name>
          <defaultValue>{request.app_type}</defaultValue>
          <description>Application Type</description>
        </hudson.model.StringParameterDefinition>
        <hudson.model.StringParameterDefinition>
          <name>REPO_URL</name>
          <defaultValue>{request.repo_url}</defaultValue>
          <description>Git Repository URL</description>
        </hudson.model.StringParameterDefinition>
        <hudson.model.StringParameterDefinition>
          <name>BRANCH</name>
          <defaultValue>{request.branch}</defaultValue>
          <description>Git Branch</description>
        </hudson.model.StringParameterDefinition>
        <hudson.model.StringParameterDefinition>
          <name>CREDENTIALS_ID</name>
          <defaultValue>github-token</defaultValue>
          <description>Jenkins GitHub Credential ID</description>
        </hudson.model.StringParameterDefinition>
        <hudson.model.BooleanParameterDefinition>
          <name>ENABLE_SONARQUBE</name>
          <defaultValue>{str(request.ENABLE_SONARQUBE).lower()}</defaultValue>
          <description>Enable SonarQube Scan</description>
        </hudson.model.BooleanParameterDefinition>
        <hudson.model.BooleanParameterDefinition>
          <name>ENABLE_OPA</name>
          <defaultValue>{str(request.ENABLE_OPA).lower()}</defaultValue>
          <description>Enable OPA Scan</description>
        </hudson.model.BooleanParameterDefinition>
        <hudson.model.BooleanParameterDefinition>
          <name>ENABLE_TRIVY</name>
          <defaultValue>{str(request.ENABLE_TRIVY).lower()}</defaultValue>
          <description>Enable Trivy Scan</description>
        </hudson.model.BooleanParameterDefinition>
      </parameterDefinitions>
    </hudson.model.ParametersDefinitionProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
    <script>
@Library('jenkins-shared-library@main') _
main_template([
  APP_TYPE: "${{APP_TYPE}}",
  REPO_URL: "${{REPO_URL}}",
  BRANCH: "${{BRANCH}}",
  CREDENTIALS_ID: "${{CREDENTIALS_ID}}",
  ENABLE_SONARQUBE: "${{ENABLE_SONARQUBE}}",
  ENABLE_OPA: "${{ENABLE_OPA}}",
  ENABLE_TRIVY: "${{ENABLE_TRIVY}}"
])
    </script>
    <sandbox>true</sandbox>
  </definition>
</flow-definition>
"""
    create_response = requests.post(
        f"{JENKINS_URL}/createItem?name={request.project_name}",
        headers={"Content-Type": "application/xml"},
        auth=(JENKINS_USER, JENKINS_TOKEN),
        data=job_config,
        verify=False
    )

    build_response = requests.post(
        f"{JENKINS_URL}/job/{request.project_name}/buildWithParameters",
        auth=(JENKINS_USER, JENKINS_TOKEN),
        params={
            "APP_TYPE": request.app_type,
            "REPO_URL": request.repo_url,
            "BRANCH": request.branch,
            "CREDENTIALS_ID": "github-token",
            "ENABLE_SONARQUBE": str(request.ENABLE_SONARQUBE).lower(),
            "ENABLE_OPA": str(request.ENABLE_OPA).lower(),
            "ENABLE_TRIVY": str(request.ENABLE_TRIVY).lower()
        },
        verify=False
    )

    return {
        "status": "Pipeline created and triggered",
        "create_response_code": create_response.status_code,
        "build_response_code": build_response.status_code
    }

@app.post("/pipeline/trigger")
def trigger_existing_pipeline(request: TriggerRequest):
    job_url = f"{JENKINS_URL}/job/{request.project_name}/api/json"
    job_check = requests.get(job_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    if job_check.status_code != 200:
        return {"status": "Job not found", "message": f"Pipeline '{request.project_name}' does not exist."}
    build_url = f"{JENKINS_URL}/job/{request.project_name}/build"
    build_trigger = requests.post(build_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    return {"status": "Build triggered", "project_name": request.project_name, "code": build_trigger.status_code}

@app.get("/pipeline/logs/{job_name}/{build_number}")
def get_console_logs(job_name: str, build_number: int):
    log_url = f"{JENKINS_URL}/job/{job_name}/{build_number}/logText/progressiveText"
    response = requests.get(log_url, auth=(JENKINS_USER, JENKINS_TOKEN), verify=False)
    return {"build_number": build_number, "job_name": job_name, "logs": response.text}

# ----------------- Vulns (RBAC-filtered) -----------------
@app.get("/vulnerabilities")
def get_vulnerabilities(
    email: str,
    application: Optional[str] = None,
    source: Optional[str] = None,
    db: Session = Depends(get_db)
):
    if email == "ankur.kashyap@horizonrelevance.com":
        query = db.query(Vulnerability)
    else:
        app_ids = db.query(ApplicationUserAccess.application_id).filter_by(user_email=email).all()
        allowed_ids = [a.application_id for a in app_ids]
        query = db.query(Vulnerability).filter(Vulnerability.application_id.in_(allowed_ids))

    if application:
        app_entry = db.query(Application).filter_by(name=application).first()
        if app_entry:
            query = query.filter(Vulnerability.application_id == app_entry.id)

    if source:
        query = query.filter_by(source=source)

    results = query.order_by(Vulnerability.timestamp.desc()).all()

    return [
        {
            "target": v.target,
            "package_name": v.package_name,
            "installed_version": v.installed_version,
            "vulnerability_id": v.vulnerability_id,
            "severity": v.severity,
            "fixed_version": v.fixed_version,
            "risk_score": v.risk_score,
            "description": v.description,
            "source": v.source,
            "timestamp": v.timestamp,
            "line": v.line,
            "rule": v.rule,
            "status": v.status,
            "predictedSeverity": v.predicted_severity,
            "jenkins_job": v.jenkins_job,
            "build_number": v.build_number,
            "jenkins_url": v.jenkins_url
        }
        for v in results
    ]

@app.delete("/vulnerabilities/clear")
def clear_vulnerabilities(db: Session = Depends(get_db)):
    deleted = db.query(Vulnerability).delete()
    db.commit()
    return {"status": "cleared", "deleted_records": deleted}

@app.post("/opa/risks/")
async def upload_opa_risks(payload: OPARiskUpload, db: Session = Depends(get_db)):
    try:
        app_name = payload.application.strip()
        if not app_name:
            return JSONResponse(status_code=400, content={"error": "Application name is required"})

        app_entry = db.query(Application).filter_by(name=app_name).first()
        if not app_entry:
            app_entry = Application(
                name=app_name,
                description="Auto-created",
                owner_email="ankur.kashyap@horizonrelevance.com"
            )
            db.add(app_entry)
            db.commit()
            db.refresh(app_entry)

        count = 0
        for risk in payload.risks:
            if not risk.violation:
                continue

            vuln = Vulnerability(
                application_id=app_entry.id,
                target=risk.target,
                package_name=risk.package_name or "OPA Policy",
                installed_version=risk.installed_version or "N/A",
                vulnerability_id=risk.violation.strip(),
                severity=risk.severity.strip().upper(),
                fixed_version=risk.remediation or "Review policy",
                risk_score=risk.risk_score,
                description=risk.description or risk.violation,
                source=risk.source or "OPA",
                jenkins_job=risk.jenkins_job,
                build_number=risk.build_number,
                jenkins_url=risk.jenkins_url,
                timestamp=datetime.utcnow()
            )
            db.add(vuln)
            count += 1

        db.commit()
        return {"status": "success", "received_count": count}
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Server error while processing OPA risks"})

@app.post("/register_application")
def register_application(request: RegisterAppRequest, db: Session = Depends(get_db)):
    app_entry = db.query(Application).filter_by(name=request.name).first()
    if app_entry:
        return JSONResponse(status_code=400, content={"error": "Application already exists"})
    app_entry = Application(
        name=request.name,
        description=request.description,
        owner_email=request.owner_email,
        repo_url=request.repo_url,
        branch=request.branch
    )
    db.add(app_entry)
    db.commit()
    db.refresh(app_entry)
    return {"status": "registered", "application_id": app_entry.id}

@app.post("/grant_access")
def grant_access(request: GrantAccessRequest, db: Session = Depends(get_db)):
    app_entry = db.query(Application).filter_by(name=request.application).first()
    if not app_entry:
        return JSONResponse(status_code=404, content={"error": "Application not found"})
    access = ApplicationUserAccess(user_email=request.user_email, application_id=app_entry.id)
    db.add(access)
    db.commit()
    return {"status": "access granted"}

@app.post("/upload_vulnerabilities")
def upload_vulnerabilities(payload: UploadPayload, db: Session = Depends(get_db)):
    try:
        app_entry = db.query(Application).filter_by(name=payload.application).first()
        if not app_entry:
            app_entry = Application(
                name=payload.application,
                description="Auto-created",
                owner_email=payload.requestedBy or "unknown@horizonrelevance.com",
                repo_url=payload.repo_url or "N/A"
            )
            db.add(app_entry)
            db.commit()
            db.refresh(app_entry)

        count = 0
        for v in payload.vulnerabilities:
            vuln = Vulnerability(
                application_id=app_entry.id,
                target=v.target,
                package_name=v.package_name,
                installed_version=v.installed_version,
                vulnerability_id=v.vulnerability_id,
                severity=v.severity,
                fixed_version=v.fixed_version,
                risk_score=v.risk_score,
                description=v.description,
                source=v.source,
                timestamp=datetime.utcnow(),
                line=v.line,
                rule=v.rule,
                status=v.status,
                predicted_severity=v.predictedSeverity,
                jenkins_job=payload.jenkins_job,
                build_number=payload.build_number,
                jenkins_url=payload.jenkins_url
            )
            db.add(vuln)
            count += 1

        db.commit()
        return {"status": "uploaded", "count": count}
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Failed to upload vulnerabilities"})

def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    expected_signature = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(), msg=payload_body, digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    try:
        body = await request.body()
        if not x_hub_signature_256:
            return JSONResponse(status_code=401, content={"error": "Missing signature"})

        expected_signature = "sha256=" + hmac.new(
            GITHUB_WEBHOOK_SECRET.encode(), msg=body, digestmod=hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_signature, x_hub_signature_256):
            return JSONResponse(status_code=401, content={"error": "Invalid signature"})

        payload = json.loads(body)
        repo_url = payload.get("repository", {}).get("clone_url")
        branch_ref = payload.get("ref", "")
        branch = branch_ref.split("/")[-1] if branch_ref.startswith("refs/heads/") else "main"

        app_match = db.query(Application).filter(
            Application.repo_url == repo_url, Application.branch == branch
        ).first()
        if not app_match:
            app_match = db.query(Application).filter_by(repo_url=repo_url).first()
            if not app_match:
                return JSONResponse(status_code=404, content={"error": "No matching pipeline found for repo"})

        job_name = app_match.name
        jenkins_url = f"{JENKINS_URL}/job/{job_name}/buildWithParameters"
        params = {
            "REPO_URL": repo_url,
            "BRANCH": branch,
            "APP_TYPE": getattr(app_match, "app_type", None) or "unknown",
            "CREDENTIALS_ID": "github-token",
            "ENABLE_SONARQUBE": "true",
            "ENABLE_OPA": "true",
            "ENABLE_TRIVY": "true"
        }
        response = requests.post(jenkins_url, auth=(JENKINS_USER, JENKINS_TOKEN), params=params, verify=False)
        return {"status": "Triggered Jenkins job", "job": job_name, "jenkins_code": response.status_code}
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Failed to process webhook"})

@app.post("/tenants")
def register_tenant(t: TenantUpsert):
    TENANTS[t.id] = t.dict()
    return {"status": "ok", "tenant_id": t.id}

@app.get("/tenants/{tenant_id}")
def get_tenant(tenant_id: str):
    t = TENANTS.get(tenant_id)
    if not t:
        return JSONResponse(status_code=404, content={"error": "tenant not found"})
    return t

# ----------------- Cloud metadata helpers (AWS) -----------------
_META_CACHE = {"regions": {}, "instance_types": {}}  # simple in-memory TTL cache
_CACHE_TTL = 900  # seconds

def _cache_get(bucket: dict, key: str):
    rec = bucket.get(key)
    if not rec:
        return None
    value, expires = rec
    if time.time() > expires:
        bucket.pop(key, None)
        return None
    return value

def _cache_put(bucket: dict, key: str, value, ttl: int = _CACHE_TTL):
    bucket[key] = (value, time.time() + ttl)

def _lookup_account_conf(tenant_id: str, account_ref: str | None) -> dict:
    """
    Supports:
      - NEW shape:  TENANTS[tenant]['accounts'][account_ref] -> {role_arn, ...}
      - Compat:     TENANTS[tenant]['accounts'][provider][account_ref] -> {...}
      - Legacy:     fields at tenant root (provisioner_role_arn, external_id, regions, ...)
    """
    t = TENANTS.get(tenant_id) or {}
    accs = t.get("accounts") or {}

    # New simple shape
    if account_ref and account_ref in accs and isinstance(accs[account_ref], dict):
        return accs[account_ref]

    # Back-compat: provider -> account_ref
    for _provider, envmap in accs.items():
        if isinstance(envmap, dict) and account_ref in envmap:
            maybe = envmap[account_ref]
            if isinstance(maybe, dict) and "role_arn" in maybe:
                return maybe

    # Legacy single-account fields
    legacy = {
        "role_arn": t.get("provisioner_role_arn"),
        "external_id": t.get("external_id"),
        "default_region": (t.get("regions") or ["us-east-1"])[0] if t.get("regions") else "us-east-1",
        "state_bucket": t.get("state_bucket"),
        "lock_table": t.get("lock_table"),
    }
    if not legacy["role_arn"]:
        raise ValueError("No account configuration found for tenant; register /tenants first.")
    return legacy

def _aws_session_via_role(role_arn: str, external_id: str | None):
    if not boto3:
        raise RuntimeError("boto3 not installed in backend image.")
    sts = boto3.client("sts")
    params = {"RoleArn": role_arn, "RoleSessionName": f"hrl-{int(time.time())}"}
    if external_id:
        params["ExternalId"] = external_id
    creds = sts.assume_role(**params)["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

def _aws_client(service: str, region: str, tenant_id: str, account_ref: str | None):
    conf = _lookup_account_conf(tenant_id, account_ref)
    sess = _aws_session_via_role(conf["role_arn"], conf.get("external_id"))
    return sess.client(service, region_name=region)

# ----------------- Regions -----------------
@app.get("/cloud/aws/regions")
def list_aws_regions(
    tenant_id: Optional[str] = None,
    account_ref: Optional[str] = None,
    include_opt_in: bool = True
):
    """
    Returns list of region codes.
      - If tenant_id omitted: return curated static list (UI-friendly default).
      - If tenant_id provided: try live AWS via STS+EC2, else fall back to static.
    """
    if not tenant_id:
        fallback = [
            "us-east-1","us-east-2","us-west-1","us-west-2",
            "eu-west-1","eu-west-2","eu-central-1",
            "ap-south-1","ap-southeast-1","ap-southeast-2","ap-northeast-1"
        ]
        return {"regions": fallback, "source": "static"}

    cache_key = f"{tenant_id or '_'}:{account_ref or '_'}:{'optin' if include_opt_in else 'noopt'}"
    cached = _cache_get(_META_CACHE["regions"], cache_key)
    if cached:
        return {"regions": cached, "source": "cache"}

    try:
        ec2 = _aws_client("ec2", "us-east-1", tenant_id, account_ref)
        resp = ec2.describe_regions(AllRegions=True)
        regions = [
            r["RegionName"]
            for r in resp["Regions"]
            if include_opt_in or r.get("OptInStatus") in (None, "opt-in-not-required", "opted-in")
        ]
        regions.sort()
        _cache_put(_META_CACHE["regions"], cache_key, regions)
        return {"regions": regions, "source": "aws"}
    except Exception as e:
        fallback = [
            "us-east-1","us-east-2","us-west-1","us-west-2",
            "eu-west-1","eu-west-2","eu-central-1",
            "ap-south-1","ap-southeast-1","ap-southeast-2","ap-northeast-1"
        ]
        _cache_put(_META_CACHE["regions"], cache_key, fallback)
        return {"regions": fallback, "source": "static", "warning": str(e)}

# ----------------- Instance Types -----------------
@app.get("/cloud/aws/instance-types")
def list_instance_types(
    region: str,
    tenant_id: Optional[str] = None,
    account_ref: Optional[str] = None,
    family_prefix: Optional[str] = None  # e.g. "t3", "m6i", "c7g"
):
    """
    Returns available instance types in a region.
    If tenant/account cannot be used, returns a curated static list so the UI still works.
    """
    cache_key = f"{tenant_id or '_'}:{account_ref or '_'}:{region}:{family_prefix or '*'}"
    cached = _cache_get(_META_CACHE["instance_types"], cache_key)
    if cached:
        return {"instance_types": cached, "source": "cache"}

    # Try dynamic
    try:
        types: Set[str] = set()
        if tenant_id:
            ec2 = _aws_client("ec2", region, tenant_id, account_ref)
            kwargs = {
                "LocationType": "region",
                "Filters": [{"Name": "location", "Values": [region]}],
            }
            while True:
                resp = ec2.describe_instance_type_offerings(**kwargs)
                for off in resp.get("InstanceTypeOfferings", []):
                    it = off["InstanceType"]
                    if not family_prefix or it.startswith(family_prefix):
                        types.add(it)
                token = resp.get("NextToken")
                if not token:
                    break
                kwargs["NextToken"] = token

        if types:
            out = sorted(types)
            _cache_put(_META_CACHE["instance_types"], cache_key, out)
            return {"instance_types": out, "source": "aws"}
    except Exception:
        pass

    # Static curated list
    static = [
        "t3.nano","t3.micro","t3.small","t3.medium","t3.large",
        "t3.xlarge","t3.2xlarge","t4g.micro","t4g.small","t4g.medium","t4g.large",
        "m6i.large","m6i.xlarge","m6i.2xlarge","m6i.4xlarge",
        "c7g.large","c7g.xlarge","c7g.2xlarge","c7g.4xlarge"
    ]
    if family_prefix:
        static = [t for t in static if t.startswith(family_prefix)]
    _cache_put(_META_CACHE["instance_types"], cache_key, static)
    return {"instance_types": static, "source": "static"}

# ----------------- Pricing (AWS) -----------------

# AWS Pricing wants region *names*, not codes:
_AWS_REGION_CODE_TO_NAME = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "eu-central-1": "EU (Frankfurt)",
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
}

# quick local fallback (approx OD Linux shared in us-east-1)
_LOCAL_OD_FALLBACK = {
    "t3.nano": 0.0052,
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.0416,
    "m6i.large": 0.096,
    "m6i.xlarge": 0.192,
}

_PRICE_CACHE: Dict[str, Tuple[float, float]] = {}  # key -> (value, expires_at)
_PRICE_TTL = 3600

def _price_cache_get(key: str) -> Optional[float]:
    rec = _PRICE_CACHE.get(key)
    if not rec:
        return None
    val, exp = rec
    if time.time() > exp:
        _PRICE_CACHE.pop(key, None)
        return None
    return val

def _price_cache_put(key: str, value: float):
    _PRICE_CACHE[key] = (value, time.time() + _PRICE_TTL)

def _aws_pricing_client():
    # Pricing API lives in us-east-1 (or ap-south-1); use us-east-1 by default
    if not boto3:
        raise RuntimeError("boto3 not available")
    return boto3.client("pricing", region_name="us-east-1")

def _lookup_ondemand_price_usd(instance_type: str, region_code: str, os: str, tenancy: str) -> Optional[float]:
    """
    Query AWS Pricing for On-Demand hourly USD for a given instance type/region/os/tenancy.
    Returns None on failure (caller uses fallback).
    """
    try:
        location = _AWS_REGION_CODE_TO_NAME.get(region_code)
        if not location:
            return None

        cache_key = f"{instance_type}:{region_code}:{os}:{tenancy}:OnDemand"
        cached = _price_cache_get(cache_key)
        if cached is not None:
            return cached

        pricing = _aws_pricing_client()
        # Pricing API uses string filters; values are case sensitive
        # OS: Linux | Windows | RHEL | SUSE | etc.
        # Tenancy: Shared | Dedicated | Host
        paginator = pricing.get_paginator("get_products")
        pages = paginator.paginate(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": os},
                {"Type": "TERM_MATCH", "Field": "tenancy", "Value": tenancy},
                {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
                {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
                {"Type": "TERM_MATCH", "Field": "licenseModel", "Value": "No License required"},
            ],
            FormatVersion="aws_v1",
        )

        for page in pages:
            for price_str in page.get("PriceList", []):
                try:
                    prod = json.loads(price_str)
                except Exception:
                    continue
                terms = prod.get("terms", {}).get("OnDemand", {})
                for _term_code, term in terms.items():
                    price_dims = term.get("priceDimensions", {})
                    for _dim_code, dim in price_dims.items():
                        usd = dim.get("pricePerUnit", {}).get("USD")
                        if usd is not None:
                            val = float(usd)
                            _price_cache_put(cache_key, val)
                            return val
        return None
    except Exception as e:
        logger.debug(f"Pricing lookup failed for {instance_type}/{region_code}: {e}")
        return None

def _estimate_price_on_demand(region: str, instance_types: List[str], os: str, tenancy: str) -> Dict[str, Any]:
    """
    Returns per-type items and total using AWS Pricing if available, else fallback.
    """
    items = []
    total = 0.0
    for it in instance_types:
        val = _lookup_ondemand_price_usd(it, region, os, tenancy)
        if val is None:
            # fallback (rough): try exact, else map by size suffix
            if it in _LOCAL_OD_FALLBACK:
                val = _LOCAL_OD_FALLBACK[it]
            else:
                size = (it or "").split(".")[-1]
                rough = {
                    "nano": 0.005, "micro": 0.010, "small": 0.020, "medium": 0.040,
                    "large": 0.080, "xlarge": 0.160, "2xlarge": 0.320, "4xlarge": 0.640
                }
                val = rough.get(size, 0.12)
        items.append({"instance_type": it, "hourly_usd": round(val, 6)})
        total += float(val)
    return {"items": items, "hourly_usd": round(total, 6), "monthly_usd": round(total * 730, 2)}

# ----------------- Simple pricing API (updated) -----------------
class PricingReq(BaseModel):
    region: str
    instance_types: List[str]
    os: Literal["Linux", "Windows"] = "Linux"
    tenancy: Literal["Shared", "Dedicated", "Host"] = "Shared"
    purchase_option: Literal["OnDemand", "Reserved"] = "OnDemand"

@app.post("/cloud/aws/pricing/estimate")
def estimate_price(req: PricingReq):
    # Only On-Demand implemented for live pricing; fall back otherwise.
    if req.purchase_option != "OnDemand":
        result = _estimate_price_on_demand(req.region, req.instance_types, req.os, req.tenancy)
        result["note"] = "Reserved pricing not implemented; showing OnDemand approximation"
        return result
    return _estimate_price_on_demand(req.region, req.instance_types, req.os, req.tenancy)

# ---------- Jenkins helper ----------
def _jenkins_build(job: str, params: dict) -> int:
    r = requests.post(
        f"{JENKINS_URL}/job/{job}/buildWithParameters",
        auth=(JENKINS_USER, JENKINS_TOKEN),
        params=params,
        verify=False
    )
    return r.status_code

def _jenkins_last_build_number(job: str) -> Optional[int]:
    try:
        j = requests.get(
            f"{JENKINS_URL}/job/{job}/api/json",
            auth=(JENKINS_USER, JENKINS_TOKEN),
            verify=False
        ).json()
        return (j.get("lastBuild") or {}).get("number")
    except Exception:
        return None

def _resolve_account(tenant_id: str, account_ref: str) -> dict:
    t = TENANTS.get(tenant_id) or {}
    acc = (t.get("accounts") or {}).get(account_ref)
    if not acc:
        raise ValueError(f"unknown account_ref '{account_ref}' for tenant '{tenant_id}'")
    return acc

# ---------- Build TENANT_CONTEXT for Jenkins ----------
def _tenant_context_for_wave(wave: dict) -> dict:
    """
    Shape Jenkins expects:
    {
      "tenant_id": "...",
      "placements": [
        {"id": "p-xxxx", "account": {
            "role_arn": "...",
            "external_id": "...",
            "state_bucket": "...",
            "lock_table": "...",
            "region": "us-east-1"   # optional
        }},
        ...
      ]
    }
    """
    t_id = wave.get("tenant_id")
    tenant = TENANTS.get(t_id) or {}
    placements_ctx = []

    for pl in wave.get("placements", []):
        pl_id = pl.get("id")
        params = pl.get("params") or {}
        acc_ref = params.get("account_ref")

        try:
            acc = _lookup_account_conf(t_id, acc_ref)
        except Exception:
            acc = {}

        placements_ctx.append({
            "id": pl_id,
            "account": {
                "role_arn": acc.get("role_arn") or tenant.get("provisioner_role_arn"),
                "external_id": acc.get("external_id") or tenant.get("external_id"),
                "state_bucket": acc.get("state_bucket") or tenant.get("state_bucket"),
                "lock_table": acc.get("lock_table") or tenant.get("lock_table"),
                "region": acc.get("default_region") or (tenant.get("regions") or [None])[0]
            }
        })

    return {"tenant_id": t_id, "placements": placements_ctx}

# ---------- Waves router (multi-cloud placements) ----------
@waves_router.post("")
def create_wave(req: WaveCreate):
    t = TENANTS.get(req.tenant_id)
    if not t:
        return JSONResponse(status_code=400, content={"error": f"unknown tenant_id {req.tenant_id}"})
    wave_id = f"wave-{uuid4().hex[:10]}"
    WAVES[wave_id] = req.dict()
    return {"id": wave_id, "status": "created"}

@waves_router.post("/{wave_id}/plan")
def plan_wave(wave_id: str, payload: Optional[WaveCreate] = Body(default=None)):
    # Use provided payload if present (stateless), else fall back to memory
    wave = payload.dict() if payload else WAVES.get(wave_id)
    if not wave:
        return JSONResponse(status_code=404, content={"error": "wave not found; include payload or create first"})
    if not TENANTS.get(wave["tenant_id"]):
        return JSONResponse(status_code=400, content={"error": "tenant not registered"})

    # keep an updated copy in memory
    WAVES[wave_id] = wave
    tenant_ctx = _tenant_context_for_wave(wave)

    exec_id = f"exec-{uuid4().hex[:10]}"
    EXECUTIONS[exec_id] = {"wave_id": wave_id, "job": "maas-plan"}
    code = _jenkins_build("maas-plan", {
        "WAVE_ID": wave_id,
        "WAVE_JSON": json.dumps(wave),
        "TENANT_CONTEXT": json.dumps(tenant_ctx)
    })
    return {"status": "queued", "jenkins_code": code, "execution_id": exec_id}

@waves_router.post("/{wave_id}/execute")
def execute_wave(wave_id: str, payload: Optional[WaveCreate] = Body(default=None)):
    wave = payload.dict() if payload else WAVES.get(wave_id)
    if not wave:
        return JSONResponse(status_code=404, content={"error": "wave not found; include payload or create first"})
    if not TENANTS.get(wave["tenant_id"]):
        return JSONResponse(status_code=400, content={"error": "tenant not registered"})

    WAVES[wave_id] = wave
    tenant_ctx = _tenant_context_for_wave(wave)

    exec_id = f"exec-{uuid4().hex[:10]}"
    EXECUTIONS[exec_id] = {"wave_id": wave_id, "job": "maas-execute"}
    code = _jenkins_build("maas-execute", {
        "WAVE_ID": wave_id,
        "WAVE_JSON": json.dumps(wave),
        "TENANT_CONTEXT": json.dumps(tenant_ctx)
    })
    return {"status": "queued", "jenkins_code": code, "execution_id": exec_id}

@waves_router.post("/{wave_id}/cutover")
def cutover_wave(
    wave_id: str,
    mode: Literal["test","prod"] = Query(...),
    payload: Optional[WaveCreate] = Body(default=None)
):
    wave = payload.dict() if payload else WAVES.get(wave_id)
    if not wave:
        return JSONResponse(status_code=404, content={"error": "wave not found; include payload or create first"})
    if not TENANTS.get(wave["tenant_id"]):
        return JSONResponse(status_code=400, content={"error": "tenant not registered"})

    WAVES[wave_id] = wave
    tenant_ctx = _tenant_context_for_wave(wave)

    exec_id = f"exec-{uuid4().hex[:10]}"
    EXECUTIONS[exec_id] = {"wave_id": wave_id, "job": "maas-cutover", "mode": mode}
    code = _jenkins_build("maas-cutover", {
        "WAVE_ID": wave_id,
        "MODE": mode,
        "WAVE_JSON": json.dumps(wave),
        "TENANT_CONTEXT": json.dumps(tenant_ctx)
    })
    return {"status": "queued", "jenkins_code": code, "execution_id": exec_id}

@app.get("/executions/{exec_id}/logs")
def get_execution_logs(exec_id: str):
    ex = EXECUTIONS.get(exec_id)
    if not ex:
        return JSONResponse(status_code=404, content={"error": "execution not found"})
    job = ex["job"]
    num = _jenkins_last_build_number(job)
    if not num:
        return {"status": "queued", "logs": ""}

    log = requests.get(
        f"{JENKINS_URL}/job/{job}/{num}/logText/progressiveText",
        auth=(JENKINS_USER, JENKINS_TOKEN),
        verify=False
    ).text

    jb = requests.get(
        f"{JENKINS_URL}/job/{job}/{num}/api/json",
        auth=(JENKINS_USER, JENKINS_TOKEN),
        verify=False
    ).json()
    state = (jb.get("result") or "RUNNING").lower()
    return {"status": "succeeded" if state == "success" else ("failed" if state == "failure" else "running"),
            "logs": log}

@waves_router.get("/{wave_id}/summary")
def wave_summary(wave_id: str):
    wave = WAVES.get(wave_id)
    if not wave:
        return JSONResponse(status_code=404, content={"error": "wave not found"})

    items = []
    hourly = 0.0

    for pl in wave["placements"]:
        if pl["provider"] == "aws":
            p = AwsPlacementParams(**pl["params"])
            items += [
              f"[{pl['id']}] ALB + listeners",
              f"[{pl['id']}] 2 Target Groups (test/prod)",
              f"[{pl['id']}] ASGs + Launch Templates (x{len(wave['targets'])})",
              f"[{pl['id']}] SGs + SSM instance profile",
              f"[{pl['id']}] AWS MGN replication + converted AMIs"
            ]
            if p.attach_backup:
                items.append(f"[{pl['id']}] AWS Backup plan (tag-based) + vault")
            itypes = [p.instance_type_map.get(t) or next(iter(p.instance_type_map.values())) for t in wave["targets"]]
            # Fast local estimate for summaries
            hourly += _estimate_cost_usd_per_hour_local(itypes)

    return {
        "id": wave_id,
        "name": wave["name"],
        "blueprint": wave["blueprint_key"],
        "targets_count": len(wave["targets"]),
        "resources": items,
        "estimated_cost_per_hour_usd": round(hourly, 4),
        "estimated_cost_per_month_usd": round(hourly * 730, 2)
    }

# --- Super admins (POC) ---
SUPER_ADMINS = {"ankur.kashyap"}  # username from LDAP login (not the email)
def _is_super_admin(username: str | None) -> bool:
    return bool(username and username in SUPER_ADMINS)

@waves_router.post("/{wave_id}/destroy")
def destroy_wave(
    wave_id: str,
    requested_by: str = Query(..., description="username of the caller"),
    payload: Optional[WaveCreate] = Body(default=None),
):
    # RBAC
    if not _is_super_admin(requested_by):
        return JSONResponse(status_code=403, content={"error": "forbidden: super admin only"})

    # Resolve wave content (allow stateless call)
    wave = payload.dict() if payload else WAVES.get(wave_id)
    if not wave:
        return JSONResponse(status_code=404, content={"error": "wave not found; include payload or create first"})
    if not TENANTS.get(wave["tenant_id"]):
        return JSONResponse(status_code=400, content={"error": "tenant not registered"})

    # Save latest and build tenant context
    WAVES[wave_id] = wave
    tenant_ctx = _tenant_context_for_wave(wave)

    # Kick Jenkins "maas-destroy"
    exec_id = f"exec-{uuid4().hex[:10]}"
    EXECUTIONS[exec_id] = {"wave_id": wave_id, "job": "maas-destroy"}
    code = _jenkins_build("maas-destroy", {
        "WAVE_ID": wave_id,
        "WAVE_JSON": json.dumps(wave),
        "TENANT_CONTEXT": json.dumps(tenant_ctx),
        "REQUESTED_BY": requested_by,
    })
    return {"status": "queued", "jenkins_code": code, "execution_id": exec_id}


# ---------- Cost & summary helpers (local-only fast estimate) ----------
def _estimate_cost_usd_per_hour_local(instance_types: List[str]) -> float:
    table = {
        "nano": 0.005, "micro": 0.01, "small": 0.02, "medium": 0.05,
        "large": 0.10, "xlarge": 0.20, "2xlarge": 0.40
    }
    total = 0.0
    for it in instance_types:
        size = (it or "").split(".")[-1]
        total += table.get(size, 0.12)
    return round(total, 4)

def _aws_summary_for_placement(targets: List[str], params: AwsPlacementParams) -> Dict[str, object]:
    default_type = next(iter(params.instance_type_map.values()), None)
    types = [(params.instance_type_map.get(t) or default_type) for t in targets if (params.instance_type_map.get(t) or default_type)]
    hourly = _estimate_cost_usd_per_hour_local(types)
    resources = [
        "ALB + listeners",
        "Target Groups (blue/green if enabled)",
        f"ASG/Launch Templates x{len(targets)}",
        "MGN replication + conversion (per target)",
        "Security groups & SSM role",
    ]
    if params.attach_backup:
        resources.append("AWS Backup plan (tag-based) + vault")
    return {
        "provider": "aws",
        "region": params.region,
        "resources": resources,
        "hourly_estimate_usd": hourly,
        "monthly_estimate_usd": round(hourly * 730, 2)
    }

# Register the router
app.include_router(waves_router)
