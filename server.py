import json
import hmac
import subprocess

from flask import Flask, jsonify, make_response, request, abort

app = Flask(__name__)
config = json.load(open('config.json'))


@app.route('/update_kestin', methods=['POST'])
def update_kestin():
    digester = hmac.new(config['kestin']['github-secret'])
    headers = dict(request.headers)
    print(dict(headers))
    if 'X-HubSignature' in headers.keys():
        hub_sig = headers['X-HubSignature']
        print(hub_sig)
        if request.json:
            data = request.json
            digester.update(json.dumps(data))
            hex_digest = digester.hexdigest()
            print(hex_digest)
            if hex_digest == hub_sig:
                try:
                    subprocess.Popen(config['kestin']['command'].split(" "), cwd=config['kestin']['folder-path'])
                    print("Success")
                    return make_response(jsonify({'success': True}), 200, {'ContentType': 'application/json'})
                except Exception as ex:
                    print("Failed to git pull")
                    print(ex)
                    pass

    return abort(401)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5050)
