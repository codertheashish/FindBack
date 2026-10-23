from flask import Blueprint

teacher_bp = Blueprint('teacher', __name__, url_prefix='/teacher')

from . import routes
