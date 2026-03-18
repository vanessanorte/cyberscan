import socket
from datetime import datetime
from pathlib import Path

# Portas conhecidas
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
}

# Classificação de risco
HIGH_RISK_PORTS = {21, 23, 445, 3389}
MEDIUM_RISK_PORTS = {22, 25, 110, 139, 143, 3306}


def print_banner():
    print("=" * 60)
    print("🔐 CyberScan - Scanner Inteligente de Portas")
    print("=" * 60)
    print("Uso autorizado apenas.\n")


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except:
        print("❌ Erro ao resolver o host.")
        exit()


def classify_port(port):
    if port in HIGH_RISK_PORTS:
        return "Alto risco"
    elif port in MEDIUM_RISK_PORTS:
        return "Médio risco"
    else:
        return "Baixo risco"


def get_service(port):
    return COMMON_PORTS.get(port, "Desconhecido")


def scan_ports(ip, start_port, end_port):
    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((ip, port))

        if result == 0:
            service = get_service(port)
            risk = classify_port(port)

            print(f"🔓 Porta {port} | Serviço: {service} | Risco: {risk}")

            open_ports.append({
                "port": port,
                "service": service,
                "risk": risk
            })

        sock.close()

    return open_ports


def generate_report(target, ip, open_ports, start, end, inicio, fim):
    path = Path("report.txt")

    with open(path, "w", encoding="utf-8") as file:
        file.write("CyberScan - Relatório\n")
        file.write("=" * 40 + "\n")
        file.write(f"Alvo: {target}\n")
        file.write(f"IP: {ip}\n")
        file.write(f"Portas: {start} - {end}\n")
        file.write(f"Início: {inicio}\n")
        file.write(f"Fim: {fim}\n\n")

        if open_ports:
            file.write("Portas abertas:\n")
            for p in open_ports:
                file.write(f"- Porta {p['port']} | {p['service']} | {p['risk']}\n")
        else:
            file.write("Nenhuma porta aberta encontrada.\n")

    return path


def main():
    print_banner()

    target = input("Digite o IP ou domínio: ")
    ip = resolve_target(target)

    print(f"\n🎯 Alvo: {target}")
    print(f"🌐 IP: {ip}")

    # 🔥 Intervalo padrão + opção personalizada
    print("\n📌 Intervalo padrão recomendado: 1 a 1024")
    usar_padrao = input("Deseja usar o padrão? (s/n): ").lower()

    if usar_padrao == "s":
        start_port = 1
        end_port = 1024
    else:
        start_port = int(input("Porta inicial: "))
        end_port = int(input("Porta final: "))

    print(f"\n🔍 Escaneando de {start_port} até {end_port}...\n")

    inicio = datetime.now()

    open_ports = scan_ports(ip, start_port, end_port)

    fim = datetime.now()

    print("\n" + "=" * 60)
    print("✅ Escaneamento finalizado")
    print(f"🕒 Início: {inicio}")
    print(f"🕒 Fim: {fim}")
    print(f"📊 Total de portas abertas: {len(open_ports)}")

    # 🔥 DIFERENCIAL — análise de risco
    high = sum(1 for p in open_ports if p["risk"] == "Alto risco")
    medium = sum(1 for p in open_ports if p["risk"] == "Médio risco")
    low = sum(1 for p in open_ports if p["risk"] == "Baixo risco")

    print("\n📊 Classificação de risco:")
    print(f"🔴 Alto risco: {high}")
    print(f"🟠 Médio risco: {medium}")
    print(f"🟢 Baixo risco: {low}")

    if open_ports:
        print("\nResumo:")
        for p in open_ports:
            print(f"- Porta {p['port']} | {p['service']} | {p['risk']}")
    else:
        print("Nenhuma porta aberta encontrada.")

    report = generate_report(target, ip, open_ports, start_port, end_port, inicio, fim)

    print("\n📄 Relatório gerado com sucesso!")
    print(f"📂 Local: {report.resolve()}")

    print("\n🔐 Análise concluída.")
    print("⚠️ Recomenda-se revisar serviços expostos e aplicar boas práticas de segurança.")

    print("\n👩‍💻 Desenvolvido por Vanessa Teles Norte")
    print("=" * 60)


if __name__ == "__main__":
    main()