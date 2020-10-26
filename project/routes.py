from project import project

@project.route("/")
@project.route("/index")
def index():
    return "Hello, World!"
