from flask_restful import Resource

class status(Resource):
	def get(self):
		return {'status':'OK'}, 200