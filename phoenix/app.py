from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return {
        "app": "Phoenix",
        "description": "A deliberately vulnerable Flask app for Kubernetes hardening demos." 
    }

@app.route("/execute", methods=["POST"])
def execute():
    cmd = request.args.get("cmd")
    if not cmd:
        return jsonify({"error": "Missing cmd query parameter"}), 400

    # Deliberately vulnerable endpoint for demonstration only.
    output = subprocess.getoutput(cmd)
    return jsonify({"cmd": cmd, "output": output})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
