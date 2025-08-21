from fastapi import FastAPI, Request, Depends, Header, APIRouter, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, AnyUrl, constr
from typing import List, Optional, Dict, Literal
from datetime import datetime
import os
import requests
from ldap3 import Server, Connection, ALL, SUBTREE
import logging
import json
import hmac
import hashlib
from uuid import uuid4

from database import SessionLocal, engine, Base
from models import Application, ApplicationUserAccess, Vulnerability

DATABASE_PATH = "/app/data/app.db"  # This path must match your Helm `mountPath`

# ----------------- WAVES ROUTER (Jenkins orchestration) -----------------
waves_router = APIRouter(prefix="/waves", tags=["waves"])

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(root_path="/pipeline/api")

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
    allow_origins=["https://horizonrelevance.com/pipeline"],
    allow_credentials=True,
    allow_methods=["*"],
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
app.mount("/schemas", StaticFiles(directory="schemas"), name="schemas")

# ----------------- TENANT REGISTRY -----------------
# In-memory for now. Move to DB when ready.
TENANTS: Dict[str, dict] = {}  # tenant_id -> { account_id, role arn, external id, tf state info, ... }

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
    # New: multi-cloud account map. Example:
    # {
    #   "aws": {
    #     "prod":  {"role_arn":"...", "external_id":"...", "state_bucket":"...", "lock_table":"...", "default_region":"us-east-1"},
    #     "nonprod": {...}
    #   },
    #   "azure": {...},
    #   "gcp":   {...},
    #   "oci":   {...}
    # }
    accounts: Optional[Dict[str, Dict[str, Dict[str, str]]]] = None

    # Backward compat (older single-account AWS style)
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
    smoke_tests: List[SmokeTest] = []
    tags: Dict[constr(regex=r"^[A-Za-z0-9._:/+=@-]{1,128}$"), constr(max_length=256)] = {}
    maintenance_window: Optional[constr(max_length=128)] = None
    # optional cross-region copy for backup
    copy_to_region: Optional[constr(regex=r"^[a-z]{2}-[a-z]+-\d$")] = None
    # account to use for this placement (key in TENANTS[tenant_id].accounts)
    account_ref: constr(min_length=1)

class Placement(BaseModel):
    id: constr(min_length=1) = Field(default_factory=lambda: f"p-{uuid4().hex[:8]}")
    provider: Provider
    # For now, only validate strictly for AWS. Others can be Dict[str, Any] until added.
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
    # NEW: multiple placements (UI sends this)
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

    except Exception as e:
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
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Failed to fetch LDAP users"})
    
@app.get("/my_applications")
def get_user_applications(email: str, db: Session = Depends(get_db)):
    try:
        print(f"[DEBUG] Incoming email: {email}")
        if email in ["ankur.kashyap@horizonrelevance.com"]:
            apps = db.query(Application.name).all()
            print(f"[DEBUG] Admin access - apps: {apps}")
            return [a.name for a in apps]

        apps = db.query(Application.name).join(ApplicationUserAccess).filter(
            ApplicationUserAccess.user_email == email
        ).all()
        print(f"[DEBUG] User apps: {apps}")
        return [a.name for a in apps]

    except Exception as e:
        print(f"[ERROR] in /my_applications: {e}")
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

#vulnerabilities_store = []

# @app.post("/vulnerabilities")
# async def upload_vulnerabilities(payload: VulnerabilityUpload, db: Session = Depends(get_db)):
#     count = 0
#     default_app_name = "webserice-application"

#     # Ensure application exists or create a dummy entry
#     app_entry = db.query(Application).filter_by(name=default_app_name).first()
#     if not app_entry:
#         app_entry = Application(name=default_app_name, description="Auto-created", owner_email="auto@horizonrelevance.com")
#         db.add(app_entry)
#         db.commit()
#         db.refresh(app_entry)

#     for v in payload.vulnerabilities:
#         vuln = Vulnerability(
#             application_id=app_entry.id,
#             target=v.target,
#             package_name=v.package_name,
#             installed_version=v.installed_version,
#             vulnerability_id=v.vulnerability_id,
#             severity=v.severity,
#             fixed_version=v.fixed_version,
#             risk_score=v.risk_score,
#             description=v.description,
#             source=v.source,
#             timestamp=v.timestamp or datetime.utcnow(),
#             line=v.line,
#             rule=v.rule,
#             status=v.status,
#             predicted_severity=v.predictedSeverity,
#             jenkins_job=v.jenkins_job,
#             build_number=v.build_number,
#             jenkins_url=v.jenkins_url
#         )
#         db.add(vuln)
#         count += 1
#     db.commit()
#     return {"status": "uploaded", "count": count}

# GET: return only authorized vulnerabilities
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
        logger.info(f"Received OPA risks for application: {payload.application}")
        logger.debug("Raw payload: %s", payload.dict())

        app_name = payload.application.strip()
        if not app_name:
            return JSONResponse(status_code=400, content={"error": "Application name is required"})

        # Ensure application exists
        app_entry = db.query(Application).filter_by(name=app_name).first()
        if not app_entry:
            logger.info(f"Creating new application entry: {app_name}")
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
                logger.warning(f"Skipping risk without violation: {risk}")
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
        logger.info(f"Successfully stored {count} OPA-Kubernetes risks.")
        return {"status": "success", "received_count": count}

    except Exception as e:
        logger.exception("Failed to upload OPA risks")
        return JSONResponse(status_code=500, content={"error": "Server error while processing OPA risks"})


def get_dynamic_fix(violation: str) -> str:
    violation = violation.lower()
    if "root user" in violation:
        return "Use a non-root USER in Dockerfile"
    elif "ssh port" in violation:
        return "Avoid exposing port 22 unless explicitly needed"
    elif "privileged" in violation:
        return "Set privileged: false in your container configuration"
    elif "capabilities" in violation:
        return "Drop all Linux capabilities and add only required ones"
    elif "no read-only" in violation or "writable" in violation:
        return "Set filesystem to read-only using readOnlyRootFilesystem"
    else:
        return "Review OPA policy and secure container accordingly"
    
@app.post("/register_application")
def register_application(request: RegisterAppRequest, db: Session = Depends(get_db)):
    app_entry = db.query(Application).filter_by(name=request.name).first()
    if app_entry:
        return JSONResponse(status_code=400, content={"error": "Application already exists"})
    app_entry = Application(name=request.name, description=request.description, owner_email=request.owner_email, repo_url=request.repo_url, branch=request.branch)
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
            print(f"[App Created] {payload.application}")

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
        print(f"[Vulnerabilities Uploaded] Count: {count} for app: {payload.application}")
        return {"status": "uploaded", "count": count}

    except Exception as e:
        print(f"[Upload Error] {str(e)}")
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
            GITHUB_WEBHOOK_SECRET.encode(),
            msg=body,
            digestmod=hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, x_hub_signature_256):
            print(f"[Signature Mismatch] Expected: {expected_signature}")
            return JSONResponse(status_code=401, content={"error": "Invalid signature"})

        payload = json.loads(body)
        repo_url = payload.get("repository", {}).get("clone_url")
        branch_ref = payload.get("ref", "")
        branch = branch_ref.split("/")[-1] if branch_ref.startswith("refs/heads/") else "main"

        print(f"[Webhook] Repo: {repo_url}, Branch: {branch}")

        app_match = db.query(Application).filter(Application.repo_url == repo_url, Application.branch == branch).first()
        if not app_match:
            print(f"[Fallback] Trying to match repo only without branch: {repo_url}")
            app_match = db.query(Application).filter_by(repo_url=repo_url).first()
            if not app_match:
                return JSONResponse(status_code=404, content={"error": "No matching pipeline found for repo"})

        job_name = app_match.name
        jenkins_url = f"{JENKINS_URL}/job/{job_name}/buildWithParameters"
        params = {
            "REPO_URL": repo_url,
            "BRANCH": branch,
            "APP_TYPE": app_match.app_type or "unknown",
            "CREDENTIALS_ID": "github-token",
            "ENABLE_SONARQUBE": "true",
            "ENABLE_OPA": "true",
            "ENABLE_TRIVY": "true"
        }

        response = requests.post(jenkins_url, auth=(JENKINS_USER, JENKINS_TOKEN), params=params, verify=False)

        return {
            "status": "Triggered Jenkins job",
            "job": job_name,
            "jenkins_code": response.status_code
        }

    except Exception as e:
        print(f"[Webhook Error] {str(e)}")
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

# ---------- Jenkins helper ----------
def _jenkins_build(job: str, params: dict) -> int:
    r = requests.post(
        f"{JENKINS_URL}/job/{job}/buildWithParameters",
        auth=(JENKINS_USER, JENKINS_TOKEN),
        params=params,
        verify=False
    )
    return r.status_code

# --- helper: resolve account by ref
def _resolve_account(tenant_id: str, account_ref: str) -> dict:
    t = TENANTS.get(tenant_id) or {}
    acc = (t.get("accounts") or {}).get(account_ref)
    if not acc:
        raise ValueError(f"unknown account_ref '{account_ref}' for tenant '{tenant_id}'")
    return acc

# ---------- Waves router (multi-cloud placements) ----------

@waves_router.post("")
def create_wave(req: WaveCreate):
    # validate AWS placements strictly
    for pl in req.placements:
        if pl.provider == "aws":
            # throws if invalid
            AwsPlacementParams(**pl.params)
    wave_id = f"wave-{uuid4().hex[:10]}"
    WAVES[wave_id] = req.dict()
    return {"id": wave_id, "status": "created"}

@waves_router.post("/{wave_id}/plan")
def plan_wave(wave_id: str):
    wave = WAVES.get(wave_id)
    if not wave:
        return JSONResponse(status_code=404, content={"error": "wave not found"})

    # Build TENANT_CONTEXT per-placement so the library can assume roles
    tenant_ctx = {"tenant_id": wave["tenant_id"], "placements": []}
    for pl in wave["placements"]:
        if pl["provider"] == "aws":
            acc = _resolve_account(wave["tenant_id"], pl["params"]["account_ref"])
            tenant_ctx["placements"].append({"id": pl["id"], "provider": "aws", "account": acc})

    code = _jenkins_build("maas-plan", {
        "WAVE_ID": wave_id,
        "WAVE_JSON": json.dumps(wave),
        "TENANT_CONTEXT": json.dumps(tenant_ctx)
    })
    return {"status": "queued", "jenkins_code": code}

@waves_router.post("/{wave_id}/execute")
def execute_wave(wave_id: str):
    wave = WAVES.get(wave_id)
    if not wave:
        return JSONResponse(status_code=404, content={"error": "wave not found"})

    tenant_ctx = {"tenant_id": wave["tenant_id"], "placements": []}
    for pl in wave["placements"]:
        if pl["provider"] == "aws":
            acc = _resolve_account(wave["tenant_id"], pl["params"]["account_ref"])
            tenant_ctx["placements"].append({"id": pl["id"], "provider": "aws", "account": acc})

    code = _jenkins_build("maas-execute", {
        "WAVE_ID": wave_id,
        "WAVE_JSON": json.dumps(wave),
        "TENANT_CONTEXT": json.dumps(tenant_ctx)
    })
    return {"status": "queued", "jenkins_code": code}

@waves_router.post("/{wave_id}/cutover")
def cutover_wave(wave_id: str, mode: Literal["test","prod"] = Query(...)):
    wave = WAVES.get(wave_id)
    if not wave:
        return JSONResponse(status_code=404, content={"error": "wave not found"})

    tenant_ctx = {"tenant_id": wave["tenant_id"], "placements": []}
    for pl in wave["placements"]:
        if pl["provider"] == "aws":
            acc = _resolve_account(wave["tenant_id"], pl["params"]["account_ref"])
            tenant_ctx["placements"].append({"id": pl["id"], "provider": "aws", "account": acc})

    code = _jenkins_build("maas-cutover", {
        "WAVE_ID": wave_id,
        "MODE": mode,
        "WAVE_JSON": json.dumps(wave),
        "TENANT_CONTEXT": json.dumps(tenant_ctx)
    })
    return {"status": "queued", "jenkins_code": code}

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
            # simple “what will be created” for AWS
            items += [
              f"[{pl['id']}] ALB + listeners",
              f"[{pl['id']}] 2 Target Groups (test/prod)",
              f"[{pl['id']}] ASGs + Launch Templates (x{len(wave['targets'])})",
              f"[{pl['id']}] SGs + SSM instance profile",
              f"[{pl['id']}] AWS MGN replication + converted AMIs"
            ]
            if p.attach_backup:
                items.append(f"[{pl['id']}] AWS Backup plan (tag-based) + vault")
            # rough cost
            itypes = [p.instance_type_map.get(t) or next(iter(p.instance_type_map.values())) for t in wave["targets"]]
            hourly += _estimate_cost_usd_per_hour(itypes)

    return {
        "id": wave_id,
        "name": wave["name"],
        "blueprint": wave["blueprint_key"],
        "targets_count": len(wave["targets"]),
        "resources": items,
        "estimated_cost_per_hour_usd": round(hourly, 4),
        "estimated_cost_per_month_usd": round(hourly * 730, 2)
    }

# ---------- Cost & summary helpers ----------

def _estimate_cost_usd_per_hour(instance_types: List[str]) -> float:
    table = {
        "nano": 0.005, "micro": 0.01, "small": 0.02, "medium": 0.05,
        "large": 0.10, "xlarge": 0.20, "2xlarge": 0.40
    }
    total = 0.0
    for it in instance_types:
        size = (it or "").split(".")[-1]
        total += table.get(size, 0.12)
    return round(total, 4)

def _aws_summary_for_placement(targets: List[str], params: AWSPlacementParams) -> Dict[str, object]:
    # pick a type per target (default to first value)
    default_type = next(iter(params.instance_type_map.values()), None)
    types = [(params.instance_type_map.get(t) or default_type) for t in targets if (params.instance_type_map.get(t) or default_type)]
    hourly = _estimate_cost_usd_per_hour(types)
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

# Register the new router
app.include_router(waves_router)
