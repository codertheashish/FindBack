from flask import Blueprint

claims_bp = Blueprint('claims', __name__, url_prefix='/claims')

from . import routes
