from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route('/')
def open_api_definition():
    return jsonify(swagger='2.0',
                   definitions={
                       'Header': {
                           'type': 'object',
                           'properties': {
                               'Accept': {
                                   'type': 'string'
                               },
                               'Accept-Encoding': {
                                   'type': 'string'
                               },
                               'Connection': {
                                   'type': 'string'
                               },
                               'Content-Length': {
                                   'type': 'string'
                               },
                               'Content-Type': {
                                   'type': 'string'
                               },
                               'Header-String': {
                                   'type': 'string'
                               },
                               'Host': {
                                   'type': 'string'
                               },
                               'User-Agent': {
                                   'type': 'string'
                               }
                           },
                           'title': 'Test'
                       }
                   },
                   paths={
                       '/header': {
                           'get': {
                               'operationId': 'get_header',
                               'parameters': [
                                   {
                                       'description': 'header parameter',
                                       'in': 'header',
                                       'name': 'header_string',
                                       'required': True,
                                       'type': 'string'
                                   }
                               ],
                               'responses': {
                                   200: {
                                       'description': 'successful operation',
                                       'schema': {
                                           '$ref': '#/definitions/Header'
                                       }
                                   }
                               }
                           }
                       }
                   })


@app.route('/header', methods=['GET'])
def get_header():
    return jsonify(dict(request.headers))


def start_server(port):
    app.run(port=port)


if __name__ == '__main__':
    start_server(8951)
