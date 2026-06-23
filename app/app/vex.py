"""
VEX (Vulnerability Exploitability eXchange) Support
Implements OpenVEX format (v0.2.0) for vulnerability status communication.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.config import get_redis_client
from app.logging_config import get_logger

logger = get_logger(__name__)

VEX_PREFIX = "vex:statement:"
VEX_INDEX = "vex:index"
VEX_CVE_INDEX = "vex:cve_index:"

VALID_STATUSES = ["not_affected", "affected", "fixed", "under_investigation"]
VALID_JUSTIFICATIONS = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]


class VEXManager:
    """Manages VEX statements stored in Redis."""

    def __init__(self):
        self.redis = get_redis_client()

    def create_statement(
        self,
        cve_id: str,
        product: str,
        status: str,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        action_statement: Optional[str] = None,
        supplier: str = "Apex Scanner",
        author: str = "",
    ) -> Dict[str, Any]:
        """Create a new VEX statement."""
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of: {VALID_STATUSES}")

        if status == "not_affected" and justification:
            if justification not in VALID_JUSTIFICATIONS:
                raise ValueError(f"Invalid justification: {justification}. Must be one of: {VALID_JUSTIFICATIONS}")

        statement_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        statement = {
            "id": statement_id,
            "cve_id": cve_id.upper(),
            "product": product,
            "status": status,
            "justification": justification or "",
            "impact_statement": impact_statement or "",
            "action_statement": action_statement or "",
            "supplier": supplier,
            "author": author,
            "created_at": now,
            "updated_at": now,
            "version": 1,
        }

        # Store statement
        self.redis.set(f"{VEX_PREFIX}{statement_id}", json.dumps(statement))
        # Add to index
        self.redis.sadd(VEX_INDEX, statement_id)
        # Add to CVE index for fast lookup
        self.redis.sadd(f"{VEX_CVE_INDEX}{cve_id.upper()}", statement_id)

        logger.info("VEX statement created", statement_id=statement_id, cve_id=cve_id, status=status)
        return statement

    def get_statement(self, statement_id: str) -> Optional[Dict[str, Any]]:
        """Get a VEX statement by ID."""
        data = self.redis.get(f"{VEX_PREFIX}{statement_id}")
        if data:
            return json.loads(data)
        return None

    def update_statement(
        self,
        statement_id: str,
        status: Optional[str] = None,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        action_statement: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update an existing VEX statement."""
        statement = self.get_statement(statement_id)
        if not statement:
            return None

        if status:
            if status not in VALID_STATUSES:
                raise ValueError(f"Invalid status: {status}")
            statement["status"] = status

        if justification is not None:
            if justification and justification not in VALID_JUSTIFICATIONS:
                raise ValueError(f"Invalid justification: {justification}")
            statement["justification"] = justification

        if impact_statement is not None:
            statement["impact_statement"] = impact_statement
        if action_statement is not None:
            statement["action_statement"] = action_statement

        statement["updated_at"] = datetime.now(timezone.utc).isoformat()
        statement["version"] = statement.get("version", 1) + 1

        self.redis.set(f"{VEX_PREFIX}{statement_id}", json.dumps(statement))
        logger.info("VEX statement updated", statement_id=statement_id)
        return statement

    def delete_statement(self, statement_id: str) -> bool:
        """Delete a VEX statement."""
        statement = self.get_statement(statement_id)
        if not statement:
            return False

        cve_id = statement.get("cve_id", "")
        self.redis.delete(f"{VEX_PREFIX}{statement_id}")
        self.redis.srem(VEX_INDEX, statement_id)
        if cve_id:
            self.redis.srem(f"{VEX_CVE_INDEX}{cve_id}", statement_id)

        logger.info("VEX statement deleted", statement_id=statement_id)
        return True

    def list_statements(
        self,
        cve_id: Optional[str] = None,
        status: Optional[str] = None,
        product: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List VEX statements with optional filtering."""
        if cve_id:
            statement_ids = self.redis.smembers(f"{VEX_CVE_INDEX}{cve_id.upper()}")
        else:
            statement_ids = self.redis.smembers(VEX_INDEX)

        statements = []
        for sid in statement_ids:
            stmt = self.get_statement(sid)
            if not stmt:
                continue
            if status and stmt.get("status") != status:
                continue
            if product and product.lower() not in stmt.get("product", "").lower():
                continue
            statements.append(stmt)

        # Sort by updated_at descending
        statements.sort(key=lambda s: s.get("updated_at", ""), reverse=True)

        total = len(statements)
        statements = statements[offset:offset + limit]

        return {
            "total": total,
            "statements": statements,
            "offset": offset,
            "limit": limit,
        }

    def get_statements_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get all VEX statements for a specific CVE."""
        statement_ids = self.redis.smembers(f"{VEX_CVE_INDEX}{cve_id.upper()}")
        statements = []
        for sid in statement_ids:
            stmt = self.get_statement(sid)
            if stmt:
                statements.append(stmt)
        return statements

    def apply_vex_to_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        product_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Apply VEX statements to a list of vulnerabilities.
        Adds vex_status and vex_justification fields.
        Optionally filters out not_affected vulnerabilities.
        """
        enriched = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("id", vuln.get("cve_id", "")).upper()
            if not cve_id:
                enriched.append(vuln)
                continue

            statements = self.get_statements_for_cve(cve_id)

            # Pick the statement to apply: prefer one whose product actually
            # matches the scanned image, else a GENERIC (product-less) statement.
            # NEVER apply a statement scoped to a DIFFERENT product — doing so
            # would let a VEX for image X silently suppress a finding on image Y.
            best_match = None
            generic_match = None
            pf = (product_filter or "").lower()
            for stmt in statements:
                stmt_product = (stmt.get("product") or "").strip().lower()
                if stmt_product:
                    # Product-scoped statement: require a real match (either name
                    # contains the other, since product may be a short name or a
                    # full image ref). Mismatch -> do not apply.
                    if pf and (stmt_product in pf or pf in stmt_product):
                        best_match = stmt
                        break
                    continue
                # Product-less statement -> generic, applies to any image.
                if generic_match is None:
                    generic_match = stmt

            best_match = best_match or generic_match

            if best_match:
                vuln = {**vuln}  # Copy to avoid mutation
                vuln["vex_status"] = best_match["status"]
                vuln["vex_justification"] = best_match.get("justification", "")
                vuln["vex_statement_id"] = best_match["id"]
                vuln["vex_impact"] = best_match.get("impact_statement", "")

            enriched.append(vuln)

        return enriched

    def generate_openvex_document(
        self,
        scan_id: str,
        product: str,
        statements: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate an OpenVEX format document."""
        if statements is None:
            result = self.list_statements(product=product, limit=1000)
            statements = result["statements"]

        now = datetime.now(timezone.utc).isoformat()

        vex_statements = []
        for stmt in statements:
            vex_stmt = {
                "vulnerability": {
                    "@id": f"https://nvd.nist.gov/vuln/detail/{stmt['cve_id']}",
                    "name": stmt["cve_id"],
                },
                "products": [
                    {
                        "@id": f"pkg:docker/{stmt['product']}",
                        "identifiers": {
                            "purl": f"pkg:docker/{stmt['product']}",
                        },
                    }
                ],
                "status": stmt["status"],
            }

            if stmt.get("justification"):
                vex_stmt["justification"] = stmt["justification"]
            if stmt.get("impact_statement"):
                vex_stmt["impact_statement"] = stmt["impact_statement"]
            if stmt.get("action_statement"):
                vex_stmt["action_statement"] = stmt["action_statement"]

            vex_statements.append(vex_stmt)

        return {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"https://apex-scanner.local/vex/{scan_id}",
            "author": "Apex Scanner",
            "role": "Document Creator",
            "timestamp": now,
            "version": 1,
            "tooling": "Apex Scanner v3.0",
            "statements": vex_statements,
        }

    def import_openvex_document(self, document: Dict[str, Any], author: str = "") -> Dict[str, Any]:
        """Import statements from an OpenVEX document."""
        statements = document.get("statements", [])
        imported = 0
        errors = []

        for stmt in statements:
            try:
                vuln = stmt.get("vulnerability", {})
                cve_id = vuln.get("name", "")
                if not cve_id:
                    errors.append("Statement missing vulnerability name")
                    continue

                products = stmt.get("products", [{}])
                product = products[0].get("identifiers", {}).get("purl", "") if products else ""
                status = stmt.get("status", "under_investigation")

                self.create_statement(
                    cve_id=cve_id,
                    product=product,
                    status=status,
                    justification=stmt.get("justification", ""),
                    impact_statement=stmt.get("impact_statement", ""),
                    action_statement=stmt.get("action_statement", ""),
                    supplier=document.get("author", "Imported"),
                    author=author,
                )
                imported += 1
            except Exception as e:
                errors.append(f"Failed to import statement for {cve_id}: {str(e)}")

        return {
            "imported": imported,
            "total": len(statements),
            "errors": errors,
        }


# Singleton
_vex_manager = None


def get_vex_manager() -> VEXManager:
    """Get singleton VEX manager."""
    global _vex_manager
    if _vex_manager is None:
        _vex_manager = VEXManager()
    return _vex_manager
