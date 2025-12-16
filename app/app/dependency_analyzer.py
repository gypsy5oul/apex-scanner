"""
Dependency Graph Analyzer
Analyzes package dependencies and vulnerability paths from SBOM data
"""
import json
import redis
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)

# Redis connection
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=10,
    decode_responses=True
)


def get_redis_client() -> redis.Redis:
    return redis.Redis(connection_pool=redis_pool)


@dataclass
class PackageNode:
    """Represents a package in the dependency graph"""
    id: str
    name: str
    version: str
    type: str  # npm, pip, rpm, deb, etc.
    vulnerabilities: List[Dict[str, Any]]
    vuln_count: int
    critical_count: int
    high_count: int
    has_fix: bool
    dependencies: List[str]  # List of package IDs this depends on
    dependents: List[str]  # List of package IDs that depend on this


@dataclass
class DependencyEdge:
    """Represents a dependency relationship"""
    source: str  # Package ID
    target: str  # Package ID
    relationship: str  # "depends_on", "dev_dependency", etc.


class DependencyAnalyzer:
    """Analyzes package dependencies and creates vulnerability graphs"""

    def __init__(self):
        self.redis = get_redis_client()

    def parse_sbom_dependencies(self, sbom_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse SBOM data to extract dependency relationships

        Args:
            sbom_data: SBOM in CycloneDX or SPDX format

        Returns:
            Dictionary with nodes and edges for the dependency graph
        """
        nodes = {}
        edges = []

        # Handle CycloneDX format
        if "components" in sbom_data:
            components = sbom_data.get("components", [])
            dependencies = sbom_data.get("dependencies", [])

            # Create nodes for each component
            for comp in components:
                pkg_id = self._generate_package_id(comp)
                nodes[pkg_id] = {
                    "id": pkg_id,
                    "name": comp.get("name", "unknown"),
                    "version": comp.get("version", "unknown"),
                    "type": comp.get("type", "library"),
                    "purl": comp.get("purl", ""),
                    "licenses": [lic.get("license", {}).get("id", "")
                                for lic in comp.get("licenses", [])],
                    "vulnerabilities": [],
                    "vuln_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "has_fix": False,
                    "dependencies": [],
                    "dependents": []
                }

            # Create edges from dependencies
            for dep in dependencies:
                source_ref = dep.get("ref", "")
                source_id = self._ref_to_id(source_ref, nodes)

                for depends_on in dep.get("dependsOn", []):
                    target_id = self._ref_to_id(depends_on, nodes)
                    if source_id and target_id and source_id in nodes and target_id in nodes:
                        edges.append({
                            "source": source_id,
                            "target": target_id,
                            "relationship": "depends_on"
                        })
                        nodes[source_id]["dependencies"].append(target_id)
                        nodes[target_id]["dependents"].append(source_id)

        # Handle SPDX format
        elif "packages" in sbom_data:
            packages = sbom_data.get("packages", [])
            relationships = sbom_data.get("relationships", [])

            # Create nodes
            for pkg in packages:
                pkg_id = pkg.get("SPDXID", self._generate_package_id(pkg))
                nodes[pkg_id] = {
                    "id": pkg_id,
                    "name": pkg.get("name", "unknown"),
                    "version": pkg.get("versionInfo", "unknown"),
                    "type": "package",
                    "purl": "",
                    "licenses": [pkg.get("licenseConcluded", "")],
                    "vulnerabilities": [],
                    "vuln_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "has_fix": False,
                    "dependencies": [],
                    "dependents": []
                }

            # Create edges from relationships
            for rel in relationships:
                if rel.get("relationshipType") == "DEPENDS_ON":
                    source_id = rel.get("spdxElementId", "")
                    target_id = rel.get("relatedSpdxElement", "")
                    if source_id in nodes and target_id in nodes:
                        edges.append({
                            "source": source_id,
                            "target": target_id,
                            "relationship": "depends_on"
                        })
                        nodes[source_id]["dependencies"].append(target_id)
                        nodes[target_id]["dependents"].append(source_id)

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges)
        }

    def _generate_package_id(self, component: Dict[str, Any]) -> str:
        """Generate a unique ID for a package"""
        name = component.get("name", "unknown")
        version = component.get("version", "unknown")
        pkg_type = component.get("type", "library")
        return f"{pkg_type}:{name}@{version}"

    def _ref_to_id(self, ref: str, nodes: Dict[str, Any]) -> Optional[str]:
        """Convert a reference to a node ID"""
        # Try direct match first
        if ref in nodes:
            return ref

        # Try to find by matching name pattern
        for node_id, node in nodes.items():
            if ref in node_id or node.get("purl", "") == ref:
                return node_id

        return None

    def enrich_with_vulnerabilities(
        self,
        graph_data: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Enrich the dependency graph with vulnerability information

        Args:
            graph_data: Dependency graph from parse_sbom_dependencies
            vulnerabilities: List of vulnerabilities from scan results

        Returns:
            Enriched graph data with vulnerability information
        """
        # Create a lookup map for packages
        pkg_lookup = {}
        for node in graph_data.get("nodes", []):
            name = node.get("name", "").lower()
            version = node.get("version", "")
            key = f"{name}:{version}"
            pkg_lookup[key] = node
            # Also add by name only for partial matching
            if name not in pkg_lookup:
                pkg_lookup[name] = node

        # Map vulnerabilities to packages
        for vuln in vulnerabilities:
            pkg_name = (vuln.get("package_name") or vuln.get("package", "")).lower()
            pkg_version = vuln.get("package_version") or vuln.get("version", "")

            # Try exact match first
            key = f"{pkg_name}:{pkg_version}"
            node = pkg_lookup.get(key) or pkg_lookup.get(pkg_name)

            if node:
                severity = vuln.get("severity", "").upper()
                # Get fix version from multiple possible fields
                fix_ver = vuln.get("fix_version") or vuln.get("fixed_in", "")
                if not fix_ver:
                    fix_vers_list = vuln.get("fix_versions", [])
                    if isinstance(fix_vers_list, list) and fix_vers_list:
                        fix_ver = fix_vers_list[0]
                # Get CVSS score (handle string format)
                cvss = vuln.get("cvss_score", 0)
                try:
                    cvss_float = float(cvss) if cvss else 0
                except (ValueError, TypeError):
                    cvss_float = 0

                node["vulnerabilities"].append({
                    "id": vuln.get("id", ""),
                    "severity": severity,
                    "description": vuln.get("description", ""),
                    "fix_version": fix_ver,
                    "cvss_score": cvss_float
                })
                node["vuln_count"] += 1
                if severity == "CRITICAL":
                    node["critical_count"] += 1
                elif severity == "HIGH":
                    node["high_count"] += 1
                if fix_ver:
                    node["has_fix"] = True

        # Calculate vulnerability paths
        vuln_paths = self._calculate_vulnerability_paths(graph_data)

        # Calculate statistics
        stats = self._calculate_graph_stats(graph_data)

        return {
            **graph_data,
            "vulnerability_paths": vuln_paths,
            "statistics": stats
        }

    def _calculate_vulnerability_paths(self, graph_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Calculate paths from root packages to vulnerable packages

        Returns list of vulnerability paths showing how vulnerabilities
        are introduced into the dependency tree
        """
        paths = []
        nodes_by_id = {n["id"]: n for n in graph_data.get("nodes", [])}

        # Find vulnerable nodes
        vuln_nodes = [n for n in graph_data.get("nodes", []) if n.get("vuln_count", 0) > 0]

        # Find root nodes (packages with no dependents - top-level deps)
        root_nodes = [n for n in graph_data.get("nodes", []) if not n.get("dependents")]

        for vuln_node in vuln_nodes:
            # BFS to find paths from roots to this vulnerable node
            for root in root_nodes:
                path = self._find_path(root["id"], vuln_node["id"], nodes_by_id)
                if path:
                    paths.append({
                        "vulnerable_package": vuln_node["name"],
                        "vulnerable_version": vuln_node["version"],
                        "vulnerabilities": vuln_node["vulnerabilities"],
                        "path": path,
                        "depth": len(path),
                        "is_direct": len(path) == 1
                    })

        # Sort by severity and depth
        paths.sort(key=lambda p: (
            -max([v.get("cvss_score", 0) for v in p["vulnerabilities"]] or [0]),
            p["depth"]
        ))

        return paths[:50]  # Return top 50 paths

    def _find_path(
        self,
        start_id: str,
        end_id: str,
        nodes_by_id: Dict[str, Any],
        visited: Set[str] = None
    ) -> Optional[List[str]]:
        """Find a path between two nodes using DFS"""
        if visited is None:
            visited = set()

        if start_id == end_id:
            return [start_id]

        if start_id in visited:
            return None

        visited.add(start_id)
        node = nodes_by_id.get(start_id, {})

        for dep_id in node.get("dependencies", []):
            path = self._find_path(dep_id, end_id, nodes_by_id, visited)
            if path:
                return [start_id] + path

        return None

    def _calculate_graph_stats(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate statistics about the dependency graph"""
        nodes = graph_data.get("nodes", [])

        total_packages = len(nodes)
        vulnerable_packages = sum(1 for n in nodes if n.get("vuln_count", 0) > 0)
        total_vulns = sum(n.get("vuln_count", 0) for n in nodes)
        critical_vulns = sum(n.get("critical_count", 0) for n in nodes)
        high_vulns = sum(n.get("high_count", 0) for n in nodes)
        fixable_packages = sum(1 for n in nodes if n.get("has_fix"))

        # Calculate max depth
        max_depth = 0
        for node in nodes:
            depth = len(node.get("dependents", []))
            if depth > max_depth:
                max_depth = depth

        # Find most depended-upon packages
        most_depended = sorted(
            nodes,
            key=lambda n: len(n.get("dependents", [])),
            reverse=True
        )[:10]

        return {
            "total_packages": total_packages,
            "vulnerable_packages": vulnerable_packages,
            "vulnerability_percentage": round(vulnerable_packages / total_packages * 100, 1) if total_packages > 0 else 0,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
            "fixable_packages": fixable_packages,
            "max_dependency_depth": max_depth,
            "most_depended_packages": [
                {"name": n["name"], "version": n["version"], "dependent_count": len(n.get("dependents", []))}
                for n in most_depended
            ]
        }

    def get_dependency_graph(self, scan_id: str) -> Dict[str, Any]:
        """
        Get or generate dependency graph for a scan

        Args:
            scan_id: The scan ID to get graph for

        Returns:
            Dependency graph data
        """
        import os

        # Check cache first
        cache_key = f"dep_graph:{scan_id}"
        cached = self.redis.get(cache_key)
        if cached:
            return json.loads(cached)

        # Try to get SBOM from Redis first
        sbom_key = f"sbom:{scan_id}"
        sbom_data = self.redis.get(sbom_key)

        # If not in Redis, try to read from file
        if not sbom_data:
            # Try CycloneDX format first (better for dependency analysis)
            sbom_paths = [
                f"{settings.SBOMS_DIR}/{scan_id}_cyclonedx_json.json",
                f"{settings.SBOMS_DIR}/{scan_id}_spdx_json.json",
                f"{settings.SBOMS_DIR}/{scan_id}_syft_json.json",
            ]

            for sbom_path in sbom_paths:
                if os.path.exists(sbom_path):
                    try:
                        with open(sbom_path, 'r') as f:
                            sbom_data = f.read()
                        logger.info(f"Loaded SBOM from file: {sbom_path}")
                        break
                    except Exception as e:
                        logger.warning(f"Failed to read SBOM from {sbom_path}: {e}")
                        continue

        if not sbom_data:
            return {"error": "SBOM not found for this scan"}

        sbom = json.loads(sbom_data)

        # Get vulnerability data
        vulns_key = f"vulns:{scan_id}"
        vulns_data = self.redis.get(vulns_key)
        vulnerabilities = json.loads(vulns_data) if vulns_data else []

        # Parse and enrich
        graph = self.parse_sbom_dependencies(sbom)
        enriched_graph = self.enrich_with_vulnerabilities(graph, vulnerabilities)

        # Cache for 1 hour
        self.redis.setex(cache_key, 3600, json.dumps(enriched_graph))

        return enriched_graph

    def get_package_impact(self, scan_id: str, package_name: str) -> Dict[str, Any]:
        """
        Analyze the impact of a specific package

        Shows what depends on this package and what vulnerabilities
        would be resolved by updating/removing it
        """
        graph = self.get_dependency_graph(scan_id)

        if "error" in graph:
            return graph

        # Find the package
        target_node = None
        for node in graph.get("nodes", []):
            if node.get("name", "").lower() == package_name.lower():
                target_node = node
                break

        if not target_node:
            return {"error": f"Package {package_name} not found"}

        # Find all packages that depend on this one (direct and transitive)
        dependents = self._get_all_dependents(target_node["id"], graph)

        return {
            "package": {
                "name": target_node["name"],
                "version": target_node["version"],
                "vulnerabilities": target_node["vulnerabilities"],
                "vuln_count": target_node["vuln_count"]
            },
            "direct_dependents": len(target_node.get("dependents", [])),
            "total_dependents": len(dependents),
            "dependent_packages": [
                {"id": d, "name": graph["nodes"][i]["name"] if i < len(graph["nodes"]) else d}
                for i, d in enumerate(list(dependents)[:20])
            ],
            "impact_summary": f"Updating {package_name} would affect {len(dependents)} packages"
        }

    def _get_all_dependents(self, node_id: str, graph: Dict[str, Any]) -> Set[str]:
        """Get all packages that depend on a node (transitively)"""
        nodes_by_id = {n["id"]: n for n in graph.get("nodes", [])}
        dependents = set()
        queue = [node_id]

        while queue:
            current = queue.pop(0)
            node = nodes_by_id.get(current, {})
            for dep in node.get("dependents", []):
                if dep not in dependents:
                    dependents.add(dep)
                    queue.append(dep)

        return dependents
