import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.rule import Rule

console = Console()

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
}

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 123, 135, 137, 138, 139, 143, 161, 389, 443,
    445, 465, 587, 636, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443
]

HIGH_RISK_PORTS = {21, 23, 445, 3389, 5900, 6379}
MEDIUM_RISK_PORTS = {22, 25, 110, 135, 139, 143, 161, 389, 3306, 5432}


def print_banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]CyberScan Smart[/bold cyan]\n"
            "[white]Scanner Inteligente de Portas[/white]\n\n"
            "[green]Alta performance • Análise contextual • Relatórios executivos[/green]\n"
            "[red]Uso autorizado apenas[/red]",
            border_style="cyan",
            padding=(1, 3),
        )
    )


def authorized_use_check() -> None:
    console.print("[bold yellow]Aviso:[/bold yellow] utilize esta ferramenta apenas com autorização.")
    confirm = input("Você confirma que tem autorização? (s/n): ").strip().lower()
    if confirm != "s":
        raise ValueError("Execução cancelada. Autorização não confirmada.")


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Não foi possível resolver o host '{target}'.") from exc


def is_private_or_internal_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private or ip.startswith("127.")
    except ValueError:
        return False


def is_ephemeral_port(port: int) -> bool:
    return port >= 49152


def classify_port(port: int) -> str:
    if port in HIGH_RISK_PORTS:
        return "Alto risco"
    if port in MEDIUM_RISK_PORTS:
        return "Médio risco"
    return "Baixo risco"


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "Serviço não identificado")


def choose_scan_mode() -> tuple[list[int], int, float, bool, str]:
    console.print("\n[bold]Escolha o tipo de escaneamento:[/bold]")
    console.print("[cyan]1[/cyan] - Rápido (recomendado)")
    console.print("[cyan]2[/cyan] - Completo")
    console.print("[cyan]3[/cyan] - Personalizado")

    option = input("Opção: ").strip()

    if option == "1":
        return sorted(set(TOP_PORTS)), 150, 0.30, True, "Rápido"

    if option == "2":
        return list(range(1, 65536)), 200, 0.40, True, "Completo"

    if option == "3":
        return custom_scan_mode()

    raise ValueError("Opção inválida.")


def custom_scan_mode() -> tuple[list[int], int, float, bool, str]:
    console.print("\n[bold]Modo personalizado:[/bold]")
    console.print("[cyan]1[/cyan] - Intervalo de portas")
    console.print("[cyan]2[/cyan] - Lista específica de portas")

    custom_option = input("Opção: ").strip()

    if custom_option == "1":
        start_text = input("Porta inicial: ").strip()
        end_text = input("Porta final: ").strip()

        if not start_text.isdigit() or not end_text.isdigit():
            raise ValueError("As portas devem ser números inteiros.")

        start_port = int(start_text)
        end_port = int(end_text)

        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError("As portas devem estar entre 1 e 65535.")

        if start_port > end_port:
            raise ValueError("A porta inicial não pode ser maior que a final.")

        ports = list(range(start_port, end_port + 1))
        return ports, 120, 0.35, True, "Personalizado"

    if custom_option == "2":
        ports_text = input("Digite as portas separadas por vírgula: ").strip()
        ports = []

        for item in ports_text.split(","):
            item = item.strip()
            if not item.isdigit():
                raise ValueError("Todas as portas devem ser numéricas.")
            port = int(item)
            if not (1 <= port <= 65535):
                raise ValueError("As portas devem estar entre 1 e 65535.")
            ports.append(port)

        if not ports:
            raise ValueError("Nenhuma porta válida foi informada.")

        return sorted(set(ports)), 120, 0.35, True, "Personalizado"

    raise ValueError("Opção inválida no modo personalizado.")


def try_banner_grab(ip: str, port: int, timeout: float = 0.8) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            if port in {80, 8080, 8000, 8888}:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: audit\r\n\r\n")
            elif port in {443, 8443}:
                return "TLS/HTTPS detectado"
            else:
                pass

            data = sock.recv(1024)
            if not data:
                return None

            text = data.decode("utf-8", errors="ignore").strip().replace("\r", " ").replace("\n", " ")
            return text[:80] if text else None
    except OSError:
        return None


def scan_single_port(ip: str, port: int, timeout: float = 0.35, do_banner: bool = True) -> Optional[dict]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            item = {
                "port": port,
                "service": service_name(port),
                "risk": classify_port(port),
                "banner": None,
                "ephemeral": is_ephemeral_port(port),
            }

            if do_banner:
                item["banner"] = try_banner_grab(ip, port, timeout=max(timeout, 0.8))

            return item
        return None
    except OSError:
        return None
    finally:
        sock.close()


def scan_ports(ip: str, ports: list[int], max_workers: int, timeout: float, do_banner: bool) -> list[dict]:
    open_ports: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Escaneando portas...", total=len(ports))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scan_single_port, ip, port, timeout, do_banner): port
                for port in ports
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                progress.advance(task)

    return sorted(open_ports, key=lambda x: x["port"])


def calculate_security_score(open_ports: list[dict], is_internal_target: bool) -> tuple[int, str]:
    score = 100

    for item in open_ports:
        port = item["port"]
        if item["ephemeral"]:
            score -= 1
            continue

        if port in HIGH_RISK_PORTS:
            score -= 8 if is_internal_target else 18
        elif port in MEDIUM_RISK_PORTS:
            score -= 4 if is_internal_target else 8
        else:
            score -= 2 if is_internal_target else 4

    score = max(score, 0)

    if score >= 85:
        level = "Alto"
    elif score >= 65:
        level = "Médio"
    else:
        level = "Baixo"

    return score, level


def create_summary_table(
    open_ports: list[dict],
    started_at: datetime,
    finished_at: datetime,
    ports_scanned: int,
    scan_mode_name: str,
    scan_speed: float,
    security_score: int,
    security_level: str,
    is_internal_target: bool,
) -> Table:
    high = sum(1 for p in open_ports if p["risk"] == "Alto risco")
    medium = sum(1 for p in open_ports if p["risk"] == "Médio risco")
    low = sum(1 for p in open_ports if p["risk"] == "Baixo risco")

    table = Table(title="Resumo Executivo", border_style="blue")
    table.add_column("Métrica", style="bold white")
    table.add_column("Valor", style="cyan")

    table.add_row("Modo", scan_mode_name)
    table.add_row("Escopo", "Interno / Privado" if is_internal_target else "Público / Externo")
    table.add_row("Início", str(started_at))
    table.add_row("Fim", str(finished_at))
    table.add_row("Duração", str(finished_at - started_at))
    table.add_row("Portas escaneadas", str(ports_scanned))
    table.add_row("Portas abertas", str(len(open_ports)))
    table.add_row("Velocidade média", f"{scan_speed:.2f} portas/seg")
    table.add_row("Score de segurança", f"{security_score}/100")
    table.add_row("Nível de segurança", security_level)
    table.add_row("Alto risco", str(high))
    table.add_row("Médio risco", str(medium))
    table.add_row("Baixo risco", str(low))

    return table


def create_results_table(open_ports: list[dict]) -> Table:
    table = Table(title="Portas Abertas Identificadas", border_style="cyan")
    table.add_column("Porta", justify="right", style="bold white")
    table.add_column("Serviço", style="green")
    table.add_column("Risco", style="magenta")
    table.add_column("Banner", style="yellow")

    for item in open_ports:
        risk_style = {
            "Alto risco": "[red]Alto risco[/red]",
            "Médio risco": "[yellow]Médio risco[/yellow]",
            "Baixo risco": "[green]Baixo risco[/green]",
        }.get(item["risk"], item["risk"])

        banner = item["banner"] if item["banner"] else "-"
        table.add_row(str(item["port"]), item["service"], risk_style, banner)

    return table


def build_analysis(open_ports: list[dict], is_internal_target: bool) -> list[str]:
    insights = []
    ports = {item["port"] for item in open_ports}
    high_ports = {item["port"] for item in open_ports if item["risk"] == "Alto risco"}

    if 445 in ports:
        if is_internal_target:
            insights.append("Porta 445 (SMB) detectada internamente: serviço sensível, porém comum em ambientes Windows.")
            insights.append("Sem evidência automática de exposição externa neste escopo interno.")
        else:
            insights.append("Porta 445 (SMB) detectada em alvo público: requer atenção imediata.")
    if 3389 in ports:
        insights.append("Porta 3389 (RDP) identificada: recomenda-se proteção rigorosa de acesso.")
    if 21 in ports or 23 in ports:
        insights.append("Serviços legados como FTP/Telnet elevam a superfície de ataque.")
    if 80 in ports and 443 not in ports:
        insights.append("HTTP exposto sem HTTPS: considerar proteção de tráfego.")
    if 80 in ports and 443 in ports:
        insights.append("HTTP e HTTPS identificados: revisar se a exposição simultânea é necessária.")

    ephemeral_count = sum(1 for item in open_ports if item["ephemeral"])
    if ephemeral_count > 0:
        insights.append(f"Foram identificadas {ephemeral_count} portas efêmeras, geralmente relacionadas a conexões temporárias do sistema.")

    if not insights and open_ports:
        if is_internal_target:
            insights.append("Foram identificados serviços internos; recomenda-se validar necessidade operacional e segmentação.")
        else:
            insights.append("Foram identificados serviços expostos; recomenda-se validar necessidade e proteção.")
    if not open_ports:
        insights.append("Nenhuma porta aberta foi identificada no escopo analisado.")

    if is_internal_target and high_ports:
        insights.append("A classificação de risco foi ajustada considerando que o alvo está em contexto interno/privado.")

    return insights


def build_recommendations(open_ports: list[dict], is_internal_target: bool) -> list[str]:
    recommendations = []

    if open_ports:
        recommendations.append("Validar se cada serviço exposto é realmente necessário.")
        recommendations.append("Manter versões e patches atualizados.")
        recommendations.append("Monitorar serviços expostos com logs e alertas.")

    ports = {item["port"] for item in open_ports}

    if is_internal_target:
        recommendations.append("Garantir que o firewall bloqueie exposição indevida para redes externas.")
    else:
        recommendations.append("Restringir acessos externos com firewall, VPN ou listas de controle.")

    if 445 in ports:
        recommendations.append("Restringir SMB a redes internas sempre que possível.")
    if 3389 in ports:
        recommendations.append("Proteger RDP com VPN, MFA e listas de acesso.")
    if 80 in ports and 443 not in ports:
        recommendations.append("Avaliar migração para HTTPS e proteção de tráfego.")

    return recommendations


def create_analysis_panel(open_ports: list[dict], is_internal_target: bool) -> Panel:
    insights = build_analysis(open_ports, is_internal_target)
    content = "\n".join(f"• {line}" for line in insights)
    return Panel(content, title="Análise Automática", border_style="magenta")


def create_recommendations_panel(open_ports: list[dict], is_internal_target: bool) -> Panel:
    recommendations = build_recommendations(open_ports, is_internal_target)
    content = "\n".join(f"• {line}" for line in recommendations)
    return Panel(content, title="Recomendações", border_style="yellow")


def ensure_reports_dir() -> Path:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    return reports_dir


def save_reports(
    target: str,
    ip: str,
    ports_scanned: list[int],
    open_ports: list[dict],
    started_at: datetime,
    finished_at: datetime,
    scan_mode_name: str,
    scan_speed: float,
    security_score: int,
    security_level: str,
    is_internal_target: bool,
) -> tuple[Path, Path]:
    reports_dir = ensure_reports_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_target = target.replace(".", "_").replace(":", "_")
    txt_path = reports_dir / f"cyberscan_{safe_target}_{timestamp}.txt"
    json_path = reports_dir / f"cyberscan_{safe_target}_{timestamp}.json"

    high = sum(1 for p in open_ports if p["risk"] == "Alto risco")
    medium = sum(1 for p in open_ports if p["risk"] == "Médio risco")
    low = sum(1 for p in open_ports if p["risk"] == "Baixo risco")

    txt_lines = [
        "CyberScan Smart - Relatório Executivo",
        "=" * 60,
        f"Alvo informado: {target}",
        f"IP resolvido: {ip}",
        f"Modo: {scan_mode_name}",
        f"Escopo: {'Interno / Privado' if is_internal_target else 'Público / Externo'}",
        f"Quantidade de portas escaneadas: {len(ports_scanned)}",
        f"Início: {started_at}",
        f"Fim: {finished_at}",
        f"Duração: {finished_at - started_at}",
        f"Velocidade média: {scan_speed:.2f} portas/seg",
        f"Score de segurança: {security_score}/100",
        f"Nível de segurança: {security_level}",
        "",
        "Resumo de risco:",
        f"- Alto risco: {high}",
        f"- Médio risco: {medium}",
        f"- Baixo risco: {low}",
        "",
        "Portas abertas:",
    ]

    if open_ports:
        for item in open_ports:
            banner = f" | Banner: {item['banner']}" if item.get("banner") else ""
            txt_lines.append(
                f"- Porta {item['port']} | Serviço: {item['service']} | Risco: {item['risk']}{banner}"
            )
    else:
        txt_lines.append("Nenhuma porta aberta foi identificada.")

    txt_lines += [
        "",
        "Análise automática:",
        *[f"- {line}" for line in build_analysis(open_ports, is_internal_target)],
        "",
        "Recomendações:",
        *[f"- {line}" for line in build_recommendations(open_ports, is_internal_target)],
        "",
        "Conclusão:",
        "Este relatório pode ser utilizado como base inicial para análise de superfície de ataque.",
        "Recomenda-se validação manual e aplicação de controles de segurança.",
    ]

    txt_path.write_text("\n".join(txt_lines), encoding="utf-8")

    json_data = {
        "scanner": "CyberScan Smart",
        "target": target,
        "resolved_ip": ip,
        "mode": scan_mode_name,
        "scope": "internal/private" if is_internal_target else "public/external",
        "started_at": str(started_at),
        "finished_at": str(finished_at),
        "duration": str(finished_at - started_at),
        "ports_scanned_count": len(ports_scanned),
        "scan_speed_ports_per_sec": round(scan_speed, 2),
        "security_score": security_score,
        "security_level": security_level,
        "risk_summary": {
            "high": high,
            "medium": medium,
            "low": low,
        },
        "open_ports": open_ports,
        "analysis": build_analysis(open_ports, is_internal_target),
        "recommendations": build_recommendations(open_ports, is_internal_target),
    }

    json_path.write_text(json.dumps(json_data, indent=2, ensure_ascii=False), encoding="utf-8")
    return txt_path, json_path


def main() -> None:
    print_banner()

    try:
        authorized_use_check()

        console.print(Rule("[bold cyan]Inicialização[/bold cyan]"))
        target = input("Digite o IP ou domínio: ").strip()
        if not target:
            raise ValueError("Você precisa informar um alvo.")

        console.print("[green]Resolvendo DNS...[/green]")
        ip = resolve_target(target)
        is_internal_target = is_private_or_internal_ip(ip)

        ports, max_workers, timeout, do_banner, scan_mode_name = choose_scan_mode()

        console.print(
            Panel.fit(
                f"[bold]Alvo:[/bold] {target}\n"
                f"[bold]IP resolvido:[/bold] {ip}\n"
                f"[bold]Escopo:[/bold] {'Interno / Privado' if is_internal_target else 'Público / Externo'}\n"
                f"[bold]Modo:[/bold] {scan_mode_name}\n"
                f"[bold]Portas para escanear:[/bold] {len(ports)}",
                border_style="green",
            )
        )

        console.print("[green]Aplicando heurísticas de análise...[/green]")

        started_at = datetime.now()
        perf_start = time.perf_counter()

        open_ports = scan_ports(ip, ports, max_workers=max_workers, timeout=timeout, do_banner=do_banner)

        perf_end = time.perf_counter()
        finished_at = datetime.now()

        elapsed_seconds = max(perf_end - perf_start, 0.0001)
        scan_speed = len(ports) / elapsed_seconds
        security_score, security_level = calculate_security_score(open_ports, is_internal_target)

        console.print()
        console.print(
            create_summary_table(
                open_ports,
                started_at,
                finished_at,
                len(ports),
                scan_mode_name,
                scan_speed,
                security_score,
                security_level,
                is_internal_target,
            )
        )
        console.print()

        if open_ports:
            console.print(create_results_table(open_ports))
        else:
            console.print(Panel.fit("Nenhuma porta aberta foi encontrada.", border_style="yellow"))

        console.print()
        console.print(create_analysis_panel(open_ports, is_internal_target))
        console.print(create_recommendations_panel(open_ports, is_internal_target))

        txt_path, json_path = save_reports(
            target=target,
            ip=ip,
            ports_scanned=ports,
            open_ports=open_ports,
            started_at=started_at,
            finished_at=finished_at,
            scan_mode_name=scan_mode_name,
            scan_speed=scan_speed,
            security_score=security_score,
            security_level=security_level,
            is_internal_target=is_internal_target,
        )

        console.print()
        console.print(
            Panel.fit(
                f"[green]Relatórios gerados com sucesso![/green]\n"
                f"TXT: {txt_path.resolve()}\n"
                f"JSON: {json_path.resolve()}",
                border_style="green",
            )
        )
        console.print(
            Panel.fit(
                "[bold green]Scan concluído com sucesso[/bold green]\n\n"
                "Este relatório pode ser utilizado como base inicial para análise de superfície de ataque.\n"
                "Recomenda-se validação manual e aplicação de controles de segurança.\n\n"
                "[white]Desenvolvido por Vanessa Teles Norte[/white]",
                border_style="cyan",
            )
        )

    except ValueError as error:
        console.print(f"[red]{error}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Execução interrompida pelo usuário.[/yellow]")


if __name__ == "__main__":
    main()
    