import ssl
import socket
from datetime import datetime
from cryptography import x509
import threading
import sys

def obtain_expiration(fqdn,port):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((fqdn, port),timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                cert = ssock.getpeercert(True)
                pem_data =  ssl.DER_cert_to_PEM_cert(cert)
                cert_data = x509.load_pem_x509_certificate(str.encode(pem_data))

                expiration_date = cert_data.not_valid_after
                expiration_date_datetime = datetime.strptime(str(expiration_date),'%Y-%m-%d %H:%M:%S')
                days_remaining = expiration_date_datetime - datetime.now()
                expXSerXPort = fqdn+','+port+','+str(expiration_date_datetime.strftime('%m-%d-%Y'))+','+str(days_remaining.days)+' Days Remaining'

                return expXSerXPort

    except socket.timeout:
        return fqdn +','+port+',' + "Error: Timeout Reached"
    except socket.gaierror:
        return fqdn +','+port+',' + "Error: Dirección IP inválida o no se pudo resolver."
    except ssl.SSLError:
        return fqdn +','+port+',' + "Error: Ocurrió un error SSL al intentar conectarse al servidor."
    except Exception as e:
        print("Error:", str(e))
        return fqdn +','+port+',' + str(e)

def process_host(host, port, output_file):
    result = obtain_expiration(host, port)
    output_file.write(result + '\n')
    print(result)

def main():
    today = datetime.strptime(str(datetime.now()),'%Y-%m-%d %H:%M:%S.%f')
    today = today.strftime('%m-%d-%Y')
    output_file = str(today) +"_Certscan.csv"
    filename = sys.argv[1]

    hosts = []
    with open(filename, "r") as file:
        for line in file:
            host, port = line.strip().split(",")
            hosts.append((host, int(port)))
    with open(output_file, "w") as file:
        threads = []
        for host, port in hosts:
            thread = threading.Thread(target=process_host, args=(host, port))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

if __name__ == "__main__":
    main()