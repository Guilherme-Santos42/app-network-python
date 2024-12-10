import socket
import subprocess
from scapy.all import ARP, Ether, srp
import ipaddress

def ping(ip):
    """Ping um IP para verificar se está ativo."""
    try:
        subprocess.check_output(['ping', '-n', '1', '-w', '100', ip], stderr=subprocess.DEVNULL, text=True)
        return True
    except subprocess.CalledProcessError:
        return False

def get_mac(ip):
    """Obtém o endereço MAC de um IP usando ARP."""
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    except Exception:
        return None

def port_scan(ip, ports=[22, 80, 443, 445, 3389]):
    """Varre portas específicas para verificar se estão abertas."""
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

def network_scan(network):
    """Escaneia uma rede para encontrar dispositivos e portas abertas."""
    try:
        print(f"\nIniciando varredura na rede {network}...\n")
        devices = []
        for ip in ipaddress.IPv4Network(network, strict=False):
            ip = str(ip)
            if ping(ip):
                mac = get_mac(ip)
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Desconhecido"
                ports = port_scan(ip)
                devices.append({"ip": ip, "hostname": hostname, "mac": mac, "ports": ports})
                print(f"Dispositivo encontrado: IP: {ip}, Hostname: {hostname}, MAC: {mac}, Portas abertas: {ports}")
        return devices
    except Exception as e:
        print(f"Erro ao escanear a rede: {e}")

if __name__ == "__main__":
    # Solicita o intervalo de IPs do usuário
    rede = input("Digite o intervalo da rede (ex: 192.168.1.0/24): ")
    dispositivos = network_scan(rede)
    
    # Exibe o resumo final
    print("\nResumo da Varredura:")
    for dispositivo in dispositivos:
        print(dispositivo)
