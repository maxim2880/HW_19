from flask import request
from flask_restx import Resource, Namespace

from dao.model.director import DirectorSchema
from implemented import director_service
from service.decorators import auth_requered, admin_requered

director_ns = Namespace('directors')


@director_ns.route('/')
class DirectorsView(Resource):
    @auth_requered
    def get(self):
        rs = director_service.get_all()
        res = DirectorSchema(many=True).dump(rs)
        return res, 200
    @admin_requered
    def post(self):
        req_json = request.json
        new_director = director_service.create(req_json)
        return "", 201, {"location": f"/directors/{new_director.id}"}



@director_ns.route('/<int:rid>')
class DirectorView(Resource):
    @auth_requered
    def get(self, rid):
        r = director_service.get_one(rid)
        sm_d = DirectorSchema().dump(r)
        return sm_d, 200

    @admin_requered
    def put(self, did):
        req_json = request.json
        if "id" not in req_json:
            req_json["id"] = did
        director_service.update(req_json)
        return "", 204

    @admin_requered
    def delete(self, did):
        director_service.delete(did)
        return "", 204
