#!/usr/bin/env python3

import html
import json
import math
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from io import BytesIO
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
REPORT_TITLE_SUFFIX = "Ports/Protocols/Services Risk Analysis"
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
HARDWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_hardware_json.py"
SOFTWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_software_json.py"
PPSM_SCRIPT_NAME = "get_systempackage_by_systemkey_ppsm_json.py"
DEFAULT_COVER_HARDWARE_LIMIT = 12
DEFAULT_TOP_NODES = 15
DEFAULT_TOP_EDGES = 25
DEFAULT_GRAPH_NODE_LIMIT = 18
REPORT_SECTIONS = [
	{"title": "Ports/Protocols/Services Risk Analysis", "anchor": "pps-risk-analysis", "page_number": "2"},
	{"title": "Top Critical Nodes", "anchor": "top-critical-nodes", "page_number": "3"},
	{"title": "Top Risky Nodes", "anchor": "top-risky-nodes", "page_number": "4"},
]

HOSTNAME_KEYS = [
	"hostname",
	"hostName",
	"host_name",
	"deviceName",
	"devicename",
	"assetName",
	"computerName",
	"machineName",
	"dnsName",
	"netbiosName",
	"name",
]
TARGET_KEYS = [
	"targetAsset",
	"targetHost",
	"targetHostname",
	"targetDeviceName",
	"destinationAsset",
	"destinationHost",
	"destinationHostname",
	"destinationDeviceName",
	"remoteHost",
	"remoteAddress",
	"peerHost",
]
PROTOCOL_KEYS = ["protocol", "transportProtocol", "ipProtocol", "networkProtocol", "proto"]
PORT_KEYS = ["port", "ports", "portNumber", "port_number", "destinationPort", "localPort"]
PORT_LOW_KEYS = ["portLow", "lowPort", "startPort", "fromPort", "beginPort"]
PORT_HIGH_KEYS = ["portHigh", "highPort", "endPort", "toPort"]
SERVICE_KEYS = ["service", "serviceName", "service_name", "application", "applicationName", "processName", "ppsName"]
SOFTWARE_NAME_KEYS = ["software", "softwareName", "name", "application", "applicationName", "product", "productName", "title"]
SOFTWARE_VERSION_KEYS = ["version", "softwareVersion", "productVersion", "release", "patchLevel"]
STANDARD_SERVICE_PORTS = {
	"ftp": {"tcp": {21}},
	"ssh": {"tcp": {22}},
	"telnet": {"tcp": {23}},
	"smtp": {"tcp": {25}},
	"dns": {"tcp": {53}, "udp": {53}},
	"dhcp": {"udp": {67, 68}},
	"http": {"tcp": {80, 8080}},
	"kerberos": {"tcp": {88}, "udp": {88}},
	"pop3": {"tcp": {110}},
	"ntp": {"udp": {123}},
	"imap": {"tcp": {143}},
	"snmp": {"udp": {161, 162}},
	"ldap": {"tcp": {389}, "udp": {389}},
	"https": {"tcp": {443, 8443}},
	"smb": {"tcp": {445}},
	"ldaps": {"tcp": {636}},
	"mssql": {"tcp": {1433}},
	"oracle": {"tcp": {1521}},
	"mysql": {"tcp": {3306}},
	"rdp": {"tcp": {3389}},
	"postgres": {"tcp": {5432}},
	"vnc": {"tcp": {5900}},
}
RISKY_PORTS = {
	20: "FTP data channel",
	21: "FTP clear-text file transfer",
	22: "Remote administration pathway",
	23: "Telnet clear-text remote access",
	25: "SMTP relay exposure",
	53: "DNS infrastructure dependency",
	69: "TFTP unauthenticated file transfer",
	110: "POP3 clear-text mail access",
	111: "RPC service mapper exposure",
	135: "Windows RPC exposure",
	137: "NetBIOS name service exposure",
	138: "NetBIOS datagram exposure",
	139: "NetBIOS session exposure",
	143: "IMAP mail access",
	161: "SNMP management exposure",
	389: "LDAP directory exposure",
	445: "SMB lateral movement pathway",
	512: "rsh remote execution exposure",
	513: "rlogin remote access exposure",
	514: "remote shell/syslog exposure",
	636: "LDAPS directory exposure",
	1433: "Microsoft SQL Server exposure",
	1521: "Oracle database exposure",
	2049: "NFS file share exposure",
	3306: "MySQL database exposure",
	3389: "Remote Desktop exposure",
	5432: "PostgreSQL database exposure",
	5900: "VNC remote console exposure",
	5985: "WinRM HTTP remote management",
	5986: "WinRM HTTPS remote management",
	6379: "Redis datastore exposure",
	8080: "Alternate web service exposure",
	8443: "Alternate HTTPS service exposure",
	9200: "Elasticsearch exposure",
	27017: "MongoDB exposure",
}
REMOTE_ADMIN_TERMS = ["admin", "remote", "rdp", "ssh", "telnet", "winrm", "vnc", "shell", "rpc"]
DATABASE_TERMS = ["database", "db", "sql", "oracle", "postgres", "mysql", "mongo", "redis", "elastic"]


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 network-graph/"
		+ Path(__file__).name
		+ " <rootURL> <applicationKey> <authorizationToken> <systemKey> [KEY=VALUE ...]"
	)


def safe_filename_value(value: str) -> str:
	safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", safe_text(value).strip())
	return safe_value.strip(".-") or "unknown-system"


def safe_text(value) -> str:
	if value is None:
		return ""
	return str(value)


def normalized_value(value) -> str:
	return re.sub(r"\s+", " ", safe_text(value).strip().lower())


def normalize_hostname(value) -> str:
	text = normalized_value(value)
	return text.split(".", 1)[0] if text else ""


def display_value(value, default: str = "Unknown") -> str:
	text = safe_text(value).strip()
	return text if text else default


def call_json_script(script_folder: str, script_name: str, arguments: list[str], error_label: str) -> str:
	source_script = Path(__file__).resolve().parents[1] / script_folder / script_name
	result = subprocess.run([get_project_python_executable(), str(source_script), *arguments], capture_output=True, text=True)
	if result.returncode != 0:
		print(f"ERROR: The {error_label} JSON script failed.")
		if result.stdout.strip():
			print(result.stdout.strip())
		if result.stderr.strip():
			print(result.stderr.strip())
		sys.exit(result.returncode)
	return result.stdout


def call_system_package_json_script(arguments: list[str]) -> str:
	return call_json_script("system-package", SYSTEM_PACKAGE_SCRIPT_NAME, arguments, "system package")


def call_hardware_json_script(arguments: list[str]) -> str:
	return call_json_script("hardware", HARDWARE_SCRIPT_NAME, arguments, "hardware")


def call_software_json_script(arguments: list[str]) -> str:
	return call_json_script("software", SOFTWARE_SCRIPT_NAME, [*arguments, "groupby=false"], "software")


def call_ppsm_json_script(arguments: list[str]) -> str:
	return call_json_script("ports-protocols-services", PPSM_SCRIPT_NAME, [*arguments, "groupby=false"], "PPSM")


def parse_json_value_from_output(output: str):
	decoder = json.JSONDecoder()
	for index, character in enumerate(output):
		if character not in "[{":
			continue
		try:
			parsed, _ = decoder.raw_decode(output[index:])
			return parsed
		except json.JSONDecodeError:
			continue
	print("ERROR: Could not find JSON in the JSON script output.")
	print(output)
	sys.exit(1)


def parse_optional_arguments(arguments: list[str]) -> dict[str, str]:
	parsed = {}
	for argument in arguments:
		if "=" not in argument:
			print(f"ERROR: Optional arguments must use KEY=VALUE format. Invalid value: {argument}")
			sys.exit(1)
		key, value = argument.split("=", 1)
		parsed[key] = value
	return parsed


def optional_value(options: dict[str, str], *keys: str) -> str:
	for key in keys:
		value = options.get(key)
		if value not in (None, ""):
			return value
	return "Unknown"


def optional_int(options: dict[str, str], key: str, default_value: int) -> int:
	try:
		return int(float(options.get(key, default_value)))
	except (TypeError, ValueError):
		return default_value


def first_json_value(data, keys: set[str]) -> str:
	if isinstance(data, dict):
		for key, value in data.items():
			if key in keys and value not in (None, ""):
				return safe_text(value).strip()
		for value in data.values():
			found_value = first_json_value(value, keys)
			if found_value:
				return found_value
	elif isinstance(data, list):
		for item in data:
			found_value = first_json_value(item, keys)
			if found_value:
				return found_value
	return ""


def first_record_value(record: dict, keys: list[str]) -> str:
	for key in keys:
		value = record.get(key)
		if value not in (None, ""):
			return safe_text(value).strip()
	return ""


def iter_dict_records(data):
	if isinstance(data, list):
		for item in data:
			if isinstance(item, dict):
				yield item
			elif isinstance(item, list):
				yield from iter_dict_records(item)
	elif isinstance(data, dict):
		list_values = [value for value in data.values() if isinstance(value, list)]
		if any(key in data for key in HOSTNAME_KEYS + TARGET_KEYS + PROTOCOL_KEYS + PORT_KEYS + SERVICE_KEYS + SOFTWARE_NAME_KEYS):
			yield data
		for value in list_values:
			yield from iter_dict_records(value)


def record_display_name(record: dict) -> str:
	return first_record_value(record, HOSTNAME_KEYS) or first_json_value(record, set(HOSTNAME_KEYS)) or "Unknown"


def build_system_title(system_package: dict, options: dict[str, str]) -> str:
	title = first_json_value(system_package, {"title", "systemTitle", "system_title", "systemName", "name"})
	if title:
		return title
	return optional_value(options, "title", "systemTitle", "system_title", "systemName", "name")


def build_system_description(system_package: dict, options: dict[str, str]) -> str:
	description = first_json_value(
		system_package,
		{"description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription"},
	)
	if description:
		return description
	return optional_value(options, "description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription")


def report_title_for_system(system_title: str) -> str:
	return f"{safe_text(system_title).strip() or 'Unknown'} {REPORT_TITLE_SUFFIX}"


def build_table_of_contents_rows() -> list[dict[str, str]]:
	return [dict(section) for section in REPORT_SECTIONS]


def build_hardware_device_summary(hardware_data, options: dict[str, str]) -> dict[str, object]:
	cover_limit = max(1, optional_int(options, "coverHardwareLimit", DEFAULT_COVER_HARDWARE_LIMIT))
	devices = []
	seen_hosts = set()
	for record in iter_dict_records(hardware_data):
		asset = record_display_name(record)
		asset_key = normalize_hostname(asset)
		if not asset_key or asset_key in seen_hosts:
			continue
		seen_hosts.add(asset_key)
		devices.append({"asset": asset})
	devices.sort(key=lambda row: normalized_value(row["asset"]))
	return {"total_count": len(devices), "display_count": min(len(devices), cover_limit), "devices": devices[:cover_limit]}


def parse_port_numbers(value) -> list[int]:
	if value in (None, ""):
		return []
	if isinstance(value, bool):
		return []
	if isinstance(value, int):
		return [value]
	if isinstance(value, float) and not math.isnan(value):
		return [int(value)]
	ports = []
	for token in re.findall(r"\d+", safe_text(value)):
		try:
			port = int(token)
		except ValueError:
			continue
		if 0 <= port <= 65535:
			ports.append(port)
	return ports


def extract_port_values(record: dict) -> tuple[list[int], bool]:
	ports = []
	for key in PORT_KEYS:
		ports.extend(parse_port_numbers(record.get(key)))
	low_value = first_record_value(record, PORT_LOW_KEYS)
	high_value = first_record_value(record, PORT_HIGH_KEYS)
	low_ports = parse_port_numbers(low_value)
	high_ports = parse_port_numbers(high_value)
	if low_ports and high_ports:
		low_port = low_ports[0]
		high_port = high_ports[0]
		if high_port >= low_port:
			ports.extend([low_port, high_port])
			return sorted(set(ports)), high_port != low_port
	if low_ports:
		ports.extend(low_ports)
	return sorted(set(ports)), False


def normalize_protocol(protocol: str) -> str:
	protocol_value = normalized_value(protocol)
	if "tcp" in protocol_value:
		return "tcp"
	if "udp" in protocol_value:
		return "udp"
	if "icmp" in protocol_value:
		return "icmp"
	return protocol_value or "unknown"


def standard_service_for_port(port: int, protocol: str) -> str:
	protocol_key = normalize_protocol(protocol)
	for service, protocol_ports in STANDARD_SERVICE_PORTS.items():
		if port in protocol_ports.get(protocol_key, set()):
			return service.upper()
	return ""


def service_tokens(service: str) -> set[str]:
	return {token for token in re.split(r"[^a-z0-9]+", normalized_value(service)) if token}


def is_standard_service_port(service: str, protocol: str, port: int) -> bool:
	tokens = service_tokens(service)
	protocol_key = normalize_protocol(protocol)
	for token in tokens:
		if token in STANDARD_SERVICE_PORTS and port in STANDARD_SERVICE_PORTS[token].get(protocol_key, set()):
			return True
	return False


def classify_port_risk(service: str, protocol: str, port: int | None, is_range: bool, target_asset: str) -> tuple[bool, list[str], int]:
	reasons = []
	score = 0
	service_value = normalized_value(service)
	if port is None:
		reasons.append("Missing port prevents standard-service validation")
		score += 1
	else:
		if port in RISKY_PORTS:
			reasons.append(RISKY_PORTS[port])
			score += 3
		if is_range:
			reasons.append("Port range broadens reachable attack surface")
			score += 2
		if port < 1024 and port not in {80, 443}:
			reasons.append("Privileged system port")
			score += 1
		if service_value and not is_standard_service_port(service_value, protocol, port):
			standard_service = standard_service_for_port(port, protocol)
			if standard_service:
				reasons.append(f"Port normally maps to {standard_service}, but service is listed as {service}")
			else:
				reasons.append("Non-standard service/port pairing")
			score += 2
		elif not service_value and port not in {80, 443}:
			reasons.append("Service name is missing for exposed port")
			score += 1
	if any(term in service_value for term in REMOTE_ADMIN_TERMS):
		reasons.append("Remote administration service")
		score += 2
	if any(term in service_value for term in DATABASE_TERMS):
		reasons.append("Database or datastore service")
		score += 2
	if normalize_hostname(target_asset):
		score += 1
	return bool(reasons), sorted(set(reasons)), score


def software_records_by_host(software_data) -> tuple[dict[str, list[str]], int]:
	software_by_host = defaultdict(list)
	record_count = 0
	for record in iter_dict_records(software_data):
		host = normalize_hostname(record_display_name(record))
		name = first_record_value(record, SOFTWARE_NAME_KEYS) or first_json_value(record, set(SOFTWARE_NAME_KEYS))
		version = first_record_value(record, SOFTWARE_VERSION_KEYS)
		if not host or not name:
			continue
		record_count += 1
		display_name = name if not version else f"{name} {version}"
		if display_name not in software_by_host[host]:
			software_by_host[host].append(display_name)
	return dict(software_by_host), record_count


def ppsm_edge_rows(ppsm_data, software_by_host: dict[str, list[str]]) -> tuple[list[dict[str, object]], int, list[str]]:
	edge_rows = []
	skipped_examples = []
	skipped_count = 0
	for record in iter_dict_records(ppsm_data):
		source_asset = first_record_value(record, HOSTNAME_KEYS) or first_json_value(record, set(HOSTNAME_KEYS))
		source_key = normalize_hostname(source_asset)
		protocol = normalize_protocol(first_record_value(record, PROTOCOL_KEYS) or first_json_value(record, set(PROTOCOL_KEYS)))
		service = first_record_value(record, SERVICE_KEYS) or first_json_value(record, set(SERVICE_KEYS))
		target_asset = first_record_value(record, TARGET_KEYS) or first_json_value(record, set(TARGET_KEYS))
		ports, is_range = extract_port_values(record)
		if not source_key:
			skipped_count += 1
			if len(skipped_examples) < 5:
				skipped_examples.append("PPSM record missing source asset/hostname")
			continue
		if not ports:
			ports = [None]
		for port in ports:
			target_display = display_value(target_asset, "")
			if not target_display:
				service_label = service or standard_service_for_port(port, protocol) if port is not None else service or "unknown-service"
				port_label = safe_text(port) if port is not None else "unknown-port"
				target_display = f"{protocol.upper()} {port_label} {service_label}".strip()
			is_risky, reasons, risk_score = classify_port_risk(service, protocol, port, is_range, target_asset)
			edge_rows.append(
				{
					"source_asset": display_value(source_asset),
					"source_key": source_key,
					"target_asset": target_display,
					"target_key": normalize_hostname(target_display) or normalized_value(target_display),
					"target_type": "asset" if normalize_hostname(target_asset) else "service_port",
					"protocol": protocol.upper(),
					"port": "Unknown" if port is None else str(port),
					"service": display_value(service, standard_service_for_port(port, protocol) if port is not None else "Unknown"),
					"software": ", ".join(software_by_host.get(source_key, [])[:3]) or "Unknown",
					"is_risky": is_risky,
					"risk_score": risk_score,
					"risk_reasons": "; ".join(reasons) if reasons else "Standard/known service-port pairing",
				}
			)
	return edge_rows, skipped_count, skipped_examples


def build_graph_analysis(edge_rows: list[dict[str, object]], options: dict[str, str]) -> dict[str, object]:
	try:
		import pandas as pd
	except ImportError:
		print("ERROR: pandas is required for this workflow. Install it with: pip install pandas")
		sys.exit(1)
	try:
		import networkx as nx
	except ImportError:
		print("ERROR: networkx is required for this workflow. Install it with: pip install networkx")
		sys.exit(1)

	edge_df = pd.DataFrame(edge_rows)
	if edge_df.empty:
		return {
			"edge_count": 0,
			"risky_edge_count": 0,
			"node_count": 0,
			"critical_node": "None",
			"centrality_rows": [],
			"risky_edge_rows": [],
			"service_rows": [],
			"graph_image": None,
		}
	graph = nx.from_pandas_edgelist(edge_df, source="source_asset", target="target_asset", edge_attr=True, create_using=nx.Graph())
	degree_centrality = nx.degree_centrality(graph)
	try:
		pagerank = nx.pagerank(graph, weight="risk_score")
	except Exception:
		pagerank = {node: 0 for node in graph.nodes}
	risky_by_node = Counter()
	for row in edge_rows:
		if row.get("is_risky"):
			risky_by_node[safe_text(row.get("source_asset"))] += 1
			risky_by_node[safe_text(row.get("target_asset"))] += 1
	centrality_rows = []
	for node in graph.nodes:
		centrality_rows.append(
			{
				"node": safe_text(node),
				"degree": graph.degree(node),
				"degree_centrality": degree_centrality.get(node, 0.0),
				"pagerank": pagerank.get(node, 0.0),
				"risky_edges": risky_by_node.get(node, 0),
			}
		)
	centrality_rows.sort(key=lambda row: (row["pagerank"], row["degree_centrality"], row["risky_edges"]), reverse=True)
	top_nodes = max(1, optional_int(options, "topNodes", DEFAULT_TOP_NODES))
	top_edges = max(1, optional_int(options, "topEdges", DEFAULT_TOP_EDGES))
	risky_edge_rows = edge_df[edge_df["is_risky"]].sort_values(["risk_score", "source_asset", "port"], ascending=[False, True, True]).head(top_edges).to_dict("records")
	service_rows = (
		edge_df.groupby(["protocol", "port", "service"], dropna=False)
		.agg(edge_count=("source_asset", "count"), risky_count=("is_risky", "sum"), source_count=("source_asset", "nunique"))
		.reset_index()
		.sort_values(["risky_count", "edge_count"], ascending=[False, False])
		.head(12)
		.to_dict("records")
	)
	return {
		"edge_count": len(edge_df),
		"risky_edge_count": int(edge_df["is_risky"].sum()),
		"node_count": graph.number_of_nodes(),
		"critical_node": centrality_rows[0]["node"] if centrality_rows else "None",
		"centrality_rows": centrality_rows[:top_nodes],
		"risky_edge_rows": risky_edge_rows,
		"service_rows": service_rows,
		"graph_image": build_graph_image(graph, centrality_rows, options),
	}


def build_graph_image(graph, centrality_rows: list[dict[str, object]], options: dict[str, str]):
	try:
		import matplotlib
		matplotlib.use("Agg")
		import matplotlib.pyplot as plt
		import networkx as nx
	except ImportError:
		return None
	if graph.number_of_nodes() == 0:
		return None
	node_limit = max(4, optional_int(options, "graphNodeLimit", DEFAULT_GRAPH_NODE_LIMIT))
	top_node_names = {row["node"] for row in centrality_rows[:node_limit]}
	selected_nodes = [node for node in graph.nodes if node in top_node_names]
	if len(selected_nodes) < min(node_limit, graph.number_of_nodes()):
		for node, degree in sorted(graph.degree, key=lambda item: item[1], reverse=True):
			if node not in selected_nodes:
				selected_nodes.append(node)
			if len(selected_nodes) >= node_limit:
				break
	subgraph = graph.subgraph(selected_nodes).copy()
	if subgraph.number_of_edges() == 0:
		return None
	figure, axis = plt.subplots(figsize=(7.2, 4.2))
	position = nx.spring_layout(subgraph, seed=17, k=0.8)
	node_sizes = [450 + 90 * subgraph.degree(node) for node in subgraph.nodes]
	node_colors = ["#F4B183" if any(data.get("is_risky") for _, _, data in subgraph.edges(node, data=True)) else "#BDD7EE" for node in subgraph.nodes]
	nx.draw_networkx_edges(subgraph, position, ax=axis, edge_color="#8C8C8C", width=1.2, alpha=0.75)
	nx.draw_networkx_nodes(subgraph, position, ax=axis, node_color=node_colors, node_size=node_sizes, edgecolors="#1F4E79", linewidths=0.8)
	nx.draw_networkx_labels(subgraph, position, ax=axis, font_size=7)
	axis.set_axis_off()
	axis.set_title("Top Network Pathways by Centrality", fontsize=11)
	buffer = BytesIO()
	figure.tight_layout()
	figure.savefig(buffer, format="png", dpi=160)
	plt.close(figure)
	buffer.seek(0)
	return buffer


def build_network_graph_analysis(software_data, ppsm_data, options: dict[str, str]) -> dict[str, object]:
	software_by_host, software_record_count = software_records_by_host(software_data)
	edge_rows, skipped_count, skipped_examples = ppsm_edge_rows(ppsm_data, software_by_host)
	graph_analysis = build_graph_analysis(edge_rows, options)
	return {
		"software_record_count": software_record_count,
		"ppsm_record_count": len(edge_rows) + skipped_count,
		"software_asset_count": len(software_by_host),
		"skipped_record_count": skipped_count,
		"skipped_record_examples": skipped_examples,
		**graph_analysis,
	}


def build_report_data(system_key: str, options: dict[str, str], system_package: dict, hardware_data, software_data, ppsm_data) -> dict[str, object]:
	system_title = build_system_title(system_package, options)
	return {
		"system_key": system_key,
		"system_title": system_title,
		"report_title": report_title_for_system(system_title),
		"system_description": build_system_description(system_package, options),
		"hardware_device_summary": build_hardware_device_summary(hardware_data, options),
		"table_of_contents_rows": build_table_of_contents_rows(),
		"network_graph_analysis": build_network_graph_analysis(software_data, ppsm_data, options),
		"generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
		"source_script": Path(__file__).name,
	}


def truncated_text(value, max_length: int = 120) -> str:
	text = display_value(safe_text(value))
	if len(text) <= max_length:
		return text
	return text[: max_length - 3].rstrip() + "..."


def pdf_table(rows: list[list[str]], column_widths: list[int], styles, table_style):
	from reportlab.platypus import Paragraph, Table

	table = Table(
		[[Paragraph(html.escape(safe_text(cell)), styles["BodyText"]) for cell in row] for row in rows],
		colWidths=column_widths,
		style=table_style,
		repeatRows=1,
	)
	table.hAlign = "LEFT"
	return table


def build_cover_hardware_section(summary: dict[str, object], styles, table_style):
	from reportlab.platypus import Paragraph, Spacer

	total_count = int(summary.get("total_count", 0) or 0)
	display_count = int(summary.get("display_count", 0) or 0)
	devices = summary.get("devices", [])
	table_rows = [["Hardware Device"]]
	if isinstance(devices, list) and devices:
		for device in devices:
			if isinstance(device, dict):
				table_rows.append([safe_text(device.get("asset", "Unknown"))])
	else:
		table_rows.append(["No hardware devices were found."])
	section = [
		Spacer(1, 12),
		Paragraph("Total Number of Hardware Devices", styles["LeftHeading2"]),
		Spacer(1, 6),
		pdf_table(table_rows, [300], styles, table_style),
	]
	if total_count > display_count:
		section.extend([Spacer(1, 6), Paragraph(f"Showing first {display_count} of {total_count} hardware devices.", styles["Normal"])])
	return section


def build_analysis_summary_lines(analysis: dict[str, object]) -> list[str]:
	return [
		f"Software Records Loaded: {analysis['software_record_count']}",
		f"PPSM Edge Records Loaded: {analysis['ppsm_record_count']}",
		f"Software Assets Matched: {analysis['software_asset_count']}",
		f"Graph Nodes: {analysis['node_count']}",
		f"Graph Edges: {analysis['edge_count']}",
		f"Risky / Non-Standard Edges: {analysis['risky_edge_count']}",
		f"Most Critical Node: {analysis['critical_node']}",
		f"Skipped Records: {analysis['skipped_record_count']}",
	]


def build_fallback_analysis_lines(analysis: dict[str, object]) -> list[str]:
	lines = ["Ports/Protocols/Services Risk Analysis", ""]
	lines.extend(build_analysis_summary_lines(analysis))
	centrality_rows = analysis.get("centrality_rows", [])
	if isinstance(centrality_rows, list) and centrality_rows:
		lines.extend(["", "Top Critical Nodes"])
		for row in centrality_rows[:12]:
			lines.append(truncated_text(f"{row['node']}: PageRank {row['pagerank']:.4f}, degree {row['degree']}, risky edges {row['risky_edges']}", 88))
	risky_edge_rows = analysis.get("risky_edge_rows", [])
	if isinstance(risky_edge_rows, list) and risky_edge_rows:
		lines.extend(["", "Top Risky Nodes"])
		for row in risky_edge_rows[:12]:
			lines.append(truncated_text(f"{row['source_asset']} -> {row['target_asset']} {row['protocol']}/{row['port']}: {row['risk_reasons']}", 88))
	return lines


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, object]) -> bool:
	try:
		from reportlab.lib import colors
		from reportlab.lib.pagesizes import letter
		from reportlab.lib.styles import getSampleStyleSheet
		from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
	except ImportError:
		return False

	styles = getSampleStyleSheet()
	table_header_style = styles["BodyText"].clone("CenteredTableHeader")
	table_header_style.alignment = 1
	table_header_style.fontName = "Helvetica-Bold"
	contents_link_style = styles["BodyText"].clone("ContentsLink")
	contents_link_style.fontSize = 9
	contents_link_style.leading = 11
	contents_link_style.textColor = colors.blue
	left_title_style = styles["Title"].clone("LeftTitle")
	left_title_style.alignment = 0
	left_title_style.leftIndent = 0
	left_title_style.firstLineIndent = 0
	left_heading_style = styles["Heading2"].clone("LeftHeading2")
	left_heading_style.alignment = 0
	left_heading_style.leftIndent = 0
	left_heading_style.firstLineIndent = 0
	styles.add(left_heading_style)
	table_style = TableStyle(
		[
			("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9EAF7")),
			("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1F4E79")),
			("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
			("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
			("VALIGN", (0, 0), (-1, -1), "TOP"),
			("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F6F8FA")]),
		]
	)
	analysis = report_data["network_graph_analysis"]
	if not isinstance(analysis, dict):
		analysis = {}

	def anchored_heading(title: str, anchor: str, style):
		return Paragraph(f'<a name="{html.escape(anchor, quote=True)}"/>{html.escape(title)}', style)

	def contents_link(title: str, anchor: str):
		return Paragraph(f'<a href="#{html.escape(anchor, quote=True)}" color="blue">{html.escape(title)}</a>', contents_link_style)

	def build_contents_table(contents_rows):
		contents_table_rows = [[Paragraph("Page Title", table_header_style), Paragraph("Page Number", table_header_style)]]
		contents_table_rows.extend(
			[
				contents_link(row["title"], row["anchor"]),
				row["page_number"],
			]
			for row in contents_rows
		)
		contents_table = Table(contents_table_rows, hAlign="LEFT", colWidths=[380, 90])
		contents_table.setStyle(
			TableStyle(
				[
					("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
					("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
					("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
					("ALIGN", (1, 1), (1, -1), "RIGHT"),
					("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
				]
			)
		)
		return contents_table

	contents_table = build_contents_table(report_data.get("table_of_contents_rows", build_table_of_contents_rows()))
	document = SimpleDocTemplate(
		str(output_path),
		pagesize=letter,
		leftMargin=36,
		rightMargin=36,
		title=safe_text(report_data["report_title"]),
		author="OpenRMF Professional External API Scripts",
	)
	story = [
		Paragraph(safe_text(report_data["report_title"]), styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['system_description'])}", styles["Normal"]),
		Spacer(1, 18),
		contents_table,
	]
	story.extend([PageBreak(), anchored_heading("Ports/Protocols/Services Risk Analysis", "pps-risk-analysis", left_title_style), Spacer(1, 10)])
	story.extend(
		[
			Paragraph("Summary", left_heading_style),
			Spacer(1, 6),
		]
	)
	summary_rows = [["Metric", "Value"]]
	for line in build_analysis_summary_lines(analysis):
		metric, value = line.split(":", 1)
		summary_rows.append([metric, value.strip()])
	story.append(pdf_table(summary_rows, [235, 250], styles, table_style))
	graph_image = analysis.get("graph_image")
	if graph_image is not None:
		story.extend([Spacer(1, 14), Paragraph("Network Graph", left_heading_style), Spacer(1, 6), Image(graph_image, width=500, height=292)])
	else:
		story.extend([Spacer(1, 10), Paragraph("Network graph visualization unavailable. Install matplotlib to render the graph image; centrality tables are still included.", styles["Normal"])])
	centrality_rows = [["Node", "Number of Connections", "Risky Connections"]]
	for row in analysis.get("centrality_rows", []):
		centrality_rows.append([row["node"], row["degree"], row["risky_edges"]])
	story.extend([PageBreak(), anchored_heading("Top Critical Nodes", "top-critical-nodes", left_heading_style), Spacer(1, 6), pdf_table(centrality_rows, [260, 130, 120], styles, table_style)])
	risky_rows = [["Node", "Port", "Software", "Risk Reason"]]
	for row in analysis.get("risky_edge_rows", []):
		risky_rows.append([row["source_asset"], row["port"], row["software"], row["risk_reasons"]])
	story.extend([PageBreak(), anchored_heading("Top Risky Nodes", "top-risky-nodes", left_heading_style), Spacer(1, 6), pdf_table(risky_rows, [130, 60, 140, 180], styles, table_style)])
	skipped_examples = analysis.get("skipped_record_examples", [])
	if isinstance(skipped_examples, list) and skipped_examples:
		story.extend([Spacer(1, 14), Paragraph("Skipped Record Examples", left_heading_style), Spacer(1, 4)])
		for example in skipped_examples:
			story.append(Paragraph(f"• {html.escape(safe_text(example))}", styles["Normal"]))
	document.build(story)
	return True


def escape_pdf_text(value: str) -> str:
	return safe_text(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_text_page(lines: list[str], font_size: int = 14) -> str:
	stream_lines = ["BT", f"/F1 {font_size} Tf", "72 720 Td"]
	for index, line in enumerate(lines):
		if index:
			stream_lines.append("0 -24 Td")
		stream_lines.append(f"({escape_pdf_text(line)}) Tj")
	stream_lines.append("ET")
	return "\n".join(stream_lines)


def write_minimal_pdf(output_path: Path, report_data: dict[str, object]) -> None:
	analysis = report_data["network_graph_analysis"]
	if not isinstance(analysis, dict):
		analysis = {}
	hardware_summary = report_data.get("hardware_device_summary", {})
	if not isinstance(hardware_summary, dict):
		hardware_summary = {}
	contents_lines = ["", "Page Title                                      Page Number", "--------------------------------------------  -----------"]
	contents_rows = report_data.get("table_of_contents_rows", build_table_of_contents_rows())
	if isinstance(contents_rows, list):
		contents_lines.extend([f"{row['title']:<44}  {row['page_number']:>11}" for row in contents_rows if isinstance(row, dict)])
	analysis_lines = build_fallback_analysis_lines(analysis)
	analysis_page_chunks = [analysis_lines[index:index + 30] for index in range(0, len(analysis_lines), 30)] or [["Ports/Protocols/Services Risk Analysis"]]
	page_streams = [
		make_text_page(
			[
				safe_text(report_data["report_title"]),
				"",
				f"Date Generated: {report_data['generated_at']}",
				f"System Key: {report_data['system_key']}",
				f"System Title: {report_data['system_title']}",
				f"Description: {report_data['system_description']}",
				*contents_lines,
			],
			font_size=14,
		),
	]
	page_streams.extend(make_text_page(chunk, font_size=12) for chunk in analysis_page_chunks)
	objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
	page_object_numbers = []
	for page_stream in page_streams:
		page_object_number = len(objects) + 1
		content_object_number = len(objects) + 2
		page_object_numbers.append(page_object_number)
		objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_number} 0 R >>".encode("latin-1"))
		stream_bytes = page_stream.encode("latin-1", errors="replace")
		objects.append(b"<< /Length " + str(len(stream_bytes)).encode("ascii") + b" >>\nstream\n" + stream_bytes + b"\nendstream")
	kids = " ".join(f"{page_number} 0 R" for page_number in page_object_numbers)
	objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_object_numbers)} >>".encode("latin-1")
	pdf = bytearray(b"%PDF-1.4\n")
	offsets = [0]
	for object_number, object_bytes in enumerate(objects, start=1):
		offsets.append(len(pdf))
		pdf.extend(f"{object_number} 0 obj\n".encode("ascii"))
		pdf.extend(object_bytes)
		pdf.extend(b"\nendobj\n")
	xref_offset = len(pdf)
	pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
	pdf.extend(b"0000000000 65535 f \n")
	for offset in offsets[1:]:
		pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
	pdf.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
	output_path.write_bytes(pdf)


def write_pdf(output_path: Path, report_data: dict[str, object]) -> str:
	if output_path.exists():
		output_path.unlink()
	if write_pdf_with_reportlab(output_path, report_data):
		return "reportlab"
	write_minimal_pdf(output_path, report_data)
	return "fallback"


def main() -> None:
	if len(sys.argv) < REQUIRED_ARGUMENT_COUNT:
		print_usage()
		sys.exit(1)
	system_key = sys.argv[4]
	options = parse_optional_arguments(sys.argv[5:])
	system_package = parse_json_value_from_output(call_system_package_json_script(sys.argv[1:5]))
	hardware_data = parse_json_value_from_output(call_hardware_json_script(sys.argv[1:5]))
	software_data = parse_json_value_from_output(call_software_json_script(sys.argv[1:5]))
	ppsm_data = parse_json_value_from_output(call_ppsm_json_script(sys.argv[1:5]))
	report_data = build_report_data(system_key, options, system_package, hardware_data, software_data, ppsm_data)
	output_filename = f"OpenRMFPro-Network-Graph-PPSM-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
